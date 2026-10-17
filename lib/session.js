'use strict';

/*
 * EDP receiver: the SPC panel dials in to our TCP server.
 *
 *   panel -> HELLO (1.2)        we -> HELLO_ACK (1.3, echo)
 *   panel -> POLL every ~10 s   we -> POLL_ACK (1.1, echo)
 *   panel -> SIA event (2.0)    we -> EVENT_ACK (2.1, echo)
 *   we    -> XML query (10.0)   panel -> reply (10.1)
 *   we    -> area command (4.0) panel -> reply (4.2)
 *
 * Commands are serialized and wait for 100 ms of quiet so they cannot collide
 * with sequence numbers of an event burst from the panel.
 */

const net = require('node:net');
const { EventEmitter } = require('node:events');
const edp = require('./edp');

const COMMAND_QUIET_TIME = 100;
const COMMAND_TIMEOUT = 5000;
const MAX_XML_FRAGMENTS = 64;
const DEFAULT_IDLE_TIMEOUT = 120000;

class SpcError extends Error {}
class SpcTimeout extends SpcError {}
class SpcConnectionLost extends SpcError {}
class SpcProtocolError extends SpcError {}
class PanelRejected extends SpcError {
    constructor(code, command) {
        super(`${edp.replyMessage(code)} (code=0x${code.toString(16)}) for ${command}`);
        this.code = code;
    }
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/**
 * One panel connection.
 *
 * Events: 'ready' (first POLL after HELLO), 'event' (parsed SIA event),
 * 'close'.
 */
class Session extends EventEmitter {
    constructor(socket, { receiverId, key, log, idleTimeout }) {
        super();
        this.socket = socket;
        this.receiverId = receiverId;
        this.key = key || null;
        this.log = log;
        this.peer = `${socket.remoteAddress}:${socket.remotePort}`;
        this.panelId = null;
        this.nextSeq = 0;
        this.lastReceived = 0;
        this.pollCount = 0;
        this.closed = false;
        this.pending = new Map();
        this.queue = Promise.resolve();
        this.decoder = new edp.FrameDecoder(this.key, log);

        socket.setNoDelay(true);
        socket.setTimeout(idleTimeout || DEFAULT_IDLE_TIMEOUT);
        socket.on('data', data => this._onData(data));
        socket.on('timeout', () => {
            this.log.warn(
                this.panelId === null && this.key
                    ? `EDP idle timeout on ${this.peer} without decodable frames - wrong encryption key?`
                    : `EDP idle timeout on ${this.peer}, disconnecting`,
            );
            this.close();
        });
        socket.on('error', err => this.log.warn(`EDP socket error on ${this.peer}: ${err.message}`));
        socket.on('close', () => this._teardown());
    }

    get ready() {
        return this.pollCount > 0;
    }

    close() {
        this.socket.destroy();
        this._teardown();
    }

    _teardown() {
        if (this.closed) {
            return;
        }
        this.closed = true;
        for (const p of this.pending.values()) {
            clearTimeout(p.timer);
            p.reject(new SpcConnectionLost('panel disconnected'));
        }
        this.pending.clear();
        this.emit('close');
    }

    _onData(data) {
        let frames;
        try {
            frames = this.decoder.feed(data);
        } catch (err) {
            if (err instanceof edp.EncryptionRequired) {
                this.log.error(`${this.peer} sends encrypted EDP frames but no key is configured`);
            } else {
                this.log.error(`${this.peer}: ${err.message}; disconnecting`);
            }
            this.close();
            return;
        }
        for (const frame of frames) {
            try {
                this._dispatch(frame);
            } catch (err) {
                this.log.warn(`error handling EDP frame ${frame.major}.${frame.minor}: ${err.message}`);
            }
        }
    }

    _send(frame) {
        if (this.closed) {
            return;
        }
        this.socket.write(
            edp.encodeFrame(
                {
                    ...frame,
                    srcId: this.receiverId,
                    dstId: this.panelId,
                    flags: edp.FLAG_FROM_RECEIVER,
                },
                this.key,
            ),
        );
    }

    _echo(req, minor) {
        this._send({ major: req.major, minor, sequence: req.sequence, payload: req.payload });
    }

    _dispatch(frame) {
        if (this.panelId === null) {
            this.panelId = frame.srcId;
            this.log.info(`EDP panel ${frame.srcId} connected from ${this.peer}`);
        }
        this.lastReceived = Date.now();
        if (frame.sequence > this.nextSeq) {
            this.nextSeq = frame.sequence;
        }

        const isXmlReply = frame.major === edp.Major.XML_CMD && frame.minor === edp.Minor.REPLY;
        const isBinReply = frame.major === edp.Major.BINARY_CMD && frame.minor === edp.Minor.BINARY_REPLY;
        if (isXmlReply || isBinReply) {
            const p = this.pending.get(frame.sequence);
            if (p && p.kind === (isXmlReply ? 'xml' : 'bin')) {
                this.pending.delete(frame.sequence);
                clearTimeout(p.timer);
                p.resolve(frame.payload);
            }
            return;
        }

        if (frame.major === edp.Major.SESSION) {
            if (frame.minor === edp.Minor.POLL) {
                this._echo(frame, edp.Minor.POLL_ACK);
                this.pollCount++;
                if (this.pollCount === 1) {
                    this.emit('ready');
                }
            } else if (frame.minor === edp.Minor.HELLO) {
                this._echo(frame, edp.Minor.HELLO_ACK);
            }
            return;
        }

        if (frame.major === edp.Major.EVENT && frame.minor === edp.Minor.EVENT_PUSH) {
            this._echo(frame, edp.Minor.EVENT_ACK);
            let event;
            try {
                event = edp.parseSiaEvent(frame.payload);
            } catch {
                this.log.warn(`unparseable SIA payload: ${edp.decodeText(frame.payload)}`);
                return;
            }
            this.emit('event', event);
            return;
        }

        this.log.debug(`unhandled EDP frame ${frame.major}.${frame.minor}`);
    }

    /** Run fn after all previously queued commands; returns its result. */
    _serialize(fn) {
        const run = this.queue.then(fn, fn);
        this.queue = run.catch(() => {});
        return run;
    }

    async _waitToSend(timeout) {
        const deadline = Date.now() + timeout;
        for (;;) {
            if (this.closed) {
                throw new SpcConnectionLost('panel disconnected');
            }
            const remaining = this.lastReceived + COMMAND_QUIET_TIME - Date.now();
            if (remaining <= 0) {
                return;
            }
            if (Date.now() + remaining > deadline) {
                throw new SpcTimeout('panel did not become idle before the command timeout');
            }
            await sleep(remaining);
        }
    }

    async _request(kind, major, payload, timeout, label) {
        await this._waitToSend(timeout);
        this.nextSeq = (this.nextSeq + 1) >>> 0;
        const sequence = this.nextSeq;
        const reply = new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(sequence);
                reject(new SpcTimeout(`no reply within ${timeout} ms for ${label}`));
            }, timeout);
            this.pending.set(sequence, { kind, resolve, reject, timer });
        });
        this._send({ major, minor: edp.Minor.REQUEST, sequence, payload });
        return reply;
    }

    /**
     * Send an XML query (e.g. "info", "area_status", "zone_status") and return
     * the parsed reply. Fragmented replies are pulled with continuation requests.
     */
    xmlCommand(commandId, { timeout = COMMAND_TIMEOUT, attrs } = {}) {
        return this._serialize(async () => {
            const assembler = new edp.ReplyAssembler();
            for (let i = 0; i < MAX_XML_FRAGMENTS; i++) {
                const payload = edp.buildXmlRequest(commandId, i > 0, attrs);
                const reply = await this._request('xml', edp.Major.XML_CMD, payload, timeout, commandId);
                let assembled;
                try {
                    assembled = assembler.feed(reply);
                    if (assembled) {
                        return edp.parseXmlReply(assembled);
                    }
                } catch (err) {
                    throw new SpcProtocolError(`invalid XML reply for ${commandId}: ${err.message}`);
                }
            }
            throw new SpcProtocolError(`XML reply for ${commandId} not closed after ${MAX_XML_FRAGMENTS} fragments`);
        });
    }

    /** Arm or disarm an area; rejects with PanelRejected unless the panel replies OK. */
    areaCommand(op, areaId, { timeout = COMMAND_TIMEOUT } = {}) {
        if (!Number.isInteger(areaId) || areaId < 1 || areaId > 255) {
            return Promise.reject(new RangeError('Area ID must be between 1 and 255'));
        }
        const label = `area command 0x${op.toString(16)} area=${areaId}`;
        return this._serialize(async () => {
            const reply = await this._request(
                'bin',
                edp.Major.BINARY_CMD,
                Buffer.from([op, areaId, 0]),
                timeout,
                label,
            );
            if (!reply.length) {
                throw new SpcProtocolError(`empty reply for ${label}`);
            }
            if (reply[0] !== edp.ReplyCode.OK) {
                throw new PanelRejected(reply[0], label);
            }
        });
    }
}

/**
 * TCP listener for EDP connections. Emits 'session' for every new panel
 * connection.
 */
class EdpServer extends EventEmitter {
    constructor({ receiverId, key, bind, port, log, idleTimeout }) {
        super();
        this.options = { receiverId, key: edp.normaliseKey(key), log, idleTimeout };
        this.bind = bind || '0.0.0.0';
        this.port = port;
        this.log = log;
        this.server = null;
        this.sessions = new Set();
    }

    listen() {
        return new Promise((resolve, reject) => {
            this.server = net.createServer(socket => {
                const session = new Session(socket, this.options);
                this.sessions.add(session);
                session.on('close', () => this.sessions.delete(session));
                this.emit('session', session);
            });
            this.server.once('error', reject);
            this.server.listen(this.port, this.bind, () => {
                this.server.removeListener('error', reject);
                this.server.on('error', err => this.log.error(`EDP server error: ${err.message}`));
                resolve(this.server.address());
            });
        });
    }

    close() {
        for (const s of this.sessions) {
            s.close();
        }
        this.sessions.clear();
        return new Promise(resolve => (this.server ? this.server.close(() => resolve()) : resolve()));
    }
}

module.exports = {
    Session,
    EdpServer,
    SpcError,
    SpcTimeout,
    SpcConnectionLost,
    SpcProtocolError,
    PanelRejected,
};
