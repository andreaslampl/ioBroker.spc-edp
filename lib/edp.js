'use strict';

/*
 * Vanderbilt SPC EDP v2: framing, checksum, AES encryption, SIA events and
 * XML replies.
 *
 * Protocol details are ported from spcedp by Ian Duffy (MIT license,
 * https://github.com/imduffy15/spcedp, see PROTOCOL.md there).
 *
 * Wire layout (little-endian, offsets include the 2-byte length prefix):
 *   0  u16  remaining length     9  u32  source ID      19  u16  checksum
 *   2  u8   protocol 0x45       13  u32  destination   21  u16  payload length
 *   3  u8   version 0x02        17  u8   major         23  ...  payload
 *   4  u8   flags               18  u8   minor
 *   5  u32  sequence
 */

const crypto = require('node:crypto');

const PROTOCOL_BYTE = 0x45;
const PROTOCOL_VERSION = 0x02;
const HEADER_LEN = 23;
const MAX_FRAME_LEN = 0xffff;
// Real frames are small (XML replies fragment at ~1.4 KB); a header claiming
// more than this is treated as garbage and resynced instead of waited on.
const MAX_PLAUSIBLE_FRAME = 16384;
// Give up on a stream after dropping this many bytes (wrong key / corruption).
const RESYNC_LIMIT = 8192;

const FLAG_ENCRYPTED = 0x01;
const FLAG_FROM_RECEIVER = 0x08;

const ENCRYPT_OFFSET_IN_WIRE = 17;
const AES_BLOCK_SIZE = 16;

// Checksum slot inside the struct (wire bytes minus the length prefix).
const CSUM_OFFSET = 0x11;

const Major = Object.freeze({
    SESSION: 1,
    EVENT: 2,
    BINARY_CMD: 4,
    XML_CMD: 10,
});

const Minor = Object.freeze({
    POLL: 0,
    POLL_ACK: 1,
    HELLO: 2,
    HELLO_ACK: 3,
    EVENT_PUSH: 0,
    EVENT_ACK: 1,
    REQUEST: 0,
    REPLY: 1,
    BINARY_REPLY: 2,
});

// Area commands (major 4, payload: opcode, area ID, 0).
const AreaOp = Object.freeze({
    SET: 0x01,
    UNSET: 0x02,
    SET_A: 0x0f,
    SET_B: 0x10,
});

const ReplyCode = Object.freeze({
    OK: 0xf0,
});

const REPLY_MESSAGES = {
    0xf0: 'ok',
    0xf2: 'Invalid parameters',
    0xf3: 'Panel is waiting for data',
    0xf4: 'Panel is in full engineer mode',
    0xf5: 'Command is not possible now',
    0xfb: 'Command is not permitted',
    0xfc: 'Command is not implemented (engineer mode active?)',
    0xfd: 'Command rejected (open zone?)',
};

function replyMessage(code) {
    return REPLY_MESSAGES[code] || `unknown reply code 0x${code.toString(16)}`;
}

class FrameDecodeError extends Error {}

/** The frame is encrypted but no key is configured; resyncing will not help. */
class EncryptionRequired extends FrameDecodeError {}

/**
 * EDP v2 checksum over the struct bytes (wire bytes without the length
 * prefix), skipping the checksum slot. A 16-bit shift register where each
 * byte is added (without carry) into the low half, XOR 0xA097 on overflow.
 */
function edpChecksum(structBytes, dlen) {
    const end = dlen + 0x15;
    if (structBytes.length < end) {
        throw new RangeError(`struct too short: have ${structBytes.length}, need ${end}`);
    }
    let low = 0xff;
    let high = 0xff;
    for (let i = 0; i < end; i++) {
        if (i === CSUM_OFFSET || i === CSUM_OFFSET + 1) {
            continue;
        }
        const carry = high & 0x80;
        const state = (((high << 8) | low) << 1) & 0xffff;
        low = ((state & 0xff) + structBytes[i]) & 0xff;
        high = (state >> 8) & 0xff;
        if (carry) {
            low ^= 0x97;
            high ^= 0xa0;
        }
    }
    return (high << 8) | low;
}

/** Accept 16 raw bytes or 32 hex digits; return a Buffer or null for "no key". */
function normaliseKey(key) {
    if (key === null || key === undefined || key === '') {
        return null;
    }
    let buf;
    if (Buffer.isBuffer(key)) {
        buf = key;
    } else {
        const hex = String(key).replace(/\s+/g, '');
        if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
            throw new RangeError('EDP key must be 32 hex digits (16 bytes)');
        }
        buf = Buffer.from(hex, 'hex');
    }
    if (buf.length !== 16) {
        throw new RangeError(`EDP key must be 16 bytes, got ${buf.length}`);
    }
    return buf;
}

function aes(key, data, encrypt) {
    const cipher = encrypt
        ? crypto.createCipheriv('aes-128-ecb', key, null)
        : crypto.createDecipheriv('aes-128-ecb', key, null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

/**
 * Serialize a frame to wire bytes.
 *
 * @param {{srcId:number,dstId:number,sequence:number,major:number,minor:number,payload?:Buffer,flags?:number}} frame
 * @param {Buffer|null} [key] AES-128 key; encrypts struct offsets 15+ when set
 * @returns {Buffer}
 */
function encodeFrame(frame, key) {
    const payload = frame.payload || Buffer.alloc(0);
    if (payload.length > MAX_FRAME_LEN) {
        throw new RangeError(`EDP payload too large: ${payload.length} bytes`);
    }
    let flags = frame.flags || 0;
    if (key) {
        flags |= FLAG_ENCRYPTED;
    }
    let struct = Buffer.alloc(21 + payload.length);
    struct[0] = PROTOCOL_BYTE;
    struct[1] = PROTOCOL_VERSION;
    struct[2] = flags & 0xff;
    struct.writeUInt32LE(frame.sequence >>> 0, 3);
    struct.writeUInt32LE(frame.srcId >>> 0, 7);
    struct.writeUInt32LE(frame.dstId >>> 0, 11);
    struct[15] = frame.major & 0xff;
    struct[16] = frame.minor & 0xff;
    struct.writeUInt16LE(payload.length, 19);
    payload.copy(struct, 21);
    struct.writeUInt16LE(edpChecksum(struct, payload.length), CSUM_OFFSET);
    if (key) {
        const tail = struct.subarray(15);
        const padded = Buffer.alloc(Math.ceil(tail.length / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
        tail.copy(padded);
        struct = Buffer.concat([struct.subarray(0, 15), aes(key, padded, true)]);
    }
    if (struct.length > MAX_FRAME_LEN) {
        throw new RangeError(`EDP frame too large: ${struct.length} bytes`);
    }
    const prefix = Buffer.alloc(2);
    prefix.writeUInt16LE(struct.length, 0);
    return Buffer.concat([prefix, struct]);
}

/**
 * Decode one complete wire frame.
 *
 * @param {Buffer} buf
 * @param {Buffer|null} [key]
 */
function decodeFrame(buf, key) {
    if (buf.length < HEADER_LEN) {
        throw new FrameDecodeError(`buffer too short for EDP header: ${buf.length}B`);
    }
    const total = buf.readUInt16LE(0) + 2;
    if (buf.length < total) {
        throw new FrameDecodeError(`buffer truncated: have ${buf.length}B, frame says ${total}B`);
    }
    if (buf[2] !== PROTOCOL_BYTE || buf[3] !== PROTOCOL_VERSION) {
        throw new FrameDecodeError(`bad EDP magic: ${buf[2]} ${buf[3]}`);
    }
    let frameBuf = Buffer.from(buf.subarray(0, total));
    const encrypted = (frameBuf[4] & FLAG_ENCRYPTED) !== 0;
    if (encrypted) {
        if (!key) {
            throw new EncryptionRequired('frame is encrypted but no key was configured');
        }
        const tail = frameBuf.subarray(ENCRYPT_OFFSET_IN_WIRE);
        if (tail.length % AES_BLOCK_SIZE !== 0) {
            throw new FrameDecodeError(`encrypted tail length ${tail.length} is not a multiple of 16`);
        }
        frameBuf = Buffer.concat([frameBuf.subarray(0, ENCRYPT_OFFSET_IN_WIRE), aes(key, tail, false)]);
    }
    const sequence = frameBuf.readUInt32LE(5);
    const srcId = frameBuf.readUInt32LE(9);
    const dstId = frameBuf.readUInt32LE(13);
    const major = frameBuf[17];
    const minor = frameBuf[18];
    const checksum = frameBuf.readUInt16LE(19);
    const dlen = frameBuf.readUInt16LE(21);
    if (HEADER_LEN + dlen > total) {
        throw new FrameDecodeError(`payload length ${dlen} overflows frame (${total}B total)`);
    }
    // The checksum is computed with the encrypted flag as sent, so a wrong key
    // or a corrupt stream is caught here.
    if (edpChecksum(frameBuf.subarray(2, total), dlen) !== checksum) {
        throw new FrameDecodeError(encrypted ? 'checksum mismatch after decrypt (wrong key?)' : 'checksum mismatch');
    }
    return {
        srcId,
        dstId,
        sequence,
        major,
        minor,
        checksum,
        flags: frameBuf[4] & ~FLAG_ENCRYPTED,
        payload: Buffer.from(frameBuf.subarray(HEADER_LEN, HEADER_LEN + dlen)),
    };
}

/**
 * Splits a TCP byte stream into frames. Frames can be split across reads and
 * several can arrive at once; garbage is skipped byte by byte.
 */
class FrameDecoder {
    constructor(key, log) {
        this.key = key || null;
        this.log = log;
        this.buf = Buffer.alloc(0);
        this.dropped = 0;
        this.waitTotal = null;
        this.waitStartLen = 0;
    }

    /** @returns {object[]} decoded frames */
    feed(data) {
        this.buf = this.buf.length ? Buffer.concat([this.buf, data]) : Buffer.from(data);
        const out = [];
        for (;;) {
            if (this.buf.length < HEADER_LEN) {
                return out;
            }
            const rem = this.buf.readUInt16LE(0);
            const total = rem + 2;
            const looksValid =
                total >= HEADER_LEN &&
                total <= MAX_PLAUSIBLE_FRAME &&
                this.buf[2] === PROTOCOL_BYTE &&
                this.buf[3] === PROTOCOL_VERSION;
            if (!looksValid) {
                this._resetWait();
                this._resync();
                continue;
            }
            if (this.buf.length < total) {
                // Bound the wait so a phantom header cannot wedge the stream.
                if (this.waitTotal !== total) {
                    this.waitTotal = total;
                    this.waitStartLen = this.buf.length;
                }
                if (this.buf.length - this.waitStartLen > RESYNC_LIMIT) {
                    this._resetWait();
                    this._resync();
                    continue;
                }
                return out;
            }
            this._resetWait();
            let frame;
            try {
                frame = decodeFrame(this.buf.subarray(0, total), this.key);
            } catch (err) {
                if (err instanceof EncryptionRequired) {
                    throw err;
                }
                if (this.log) {
                    this.log.warn(`dropping undecodable EDP frame, resyncing: ${err.message}`);
                }
                this._resync();
                continue;
            }
            this.buf = this.buf.subarray(total);
            this.dropped = 0;
            out.push(frame);
        }
    }

    _resetWait() {
        this.waitTotal = null;
        this.waitStartLen = 0;
    }

    _resync() {
        this.buf = this.buf.subarray(1);
        this.dropped++;
        if (this.dropped > RESYNC_LIMIT) {
            throw new FrameDecodeError(
                `gave up resyncing after dropping ${this.dropped} bytes (corrupt stream or wrong encryption key?)`,
            );
        }
    }
}

const utf8 = new TextDecoder('utf-8', { fatal: true });

/** Decode panel text as UTF-8, falling back to Latin-1 (which maps 0xA6 to "¦"). */
function decodeText(buf) {
    try {
        return utf8.decode(buf);
    } catch {
        return buf.toString('latin1');
    }
}

const ENVELOPE = /^E2\[#(\d+)\|(\d{14})\|([\s\S]*)\]$/;

/**
 * Parse an SIA event payload:
 *   E2[#<panel>|<HHMMSSDDMMYYYY>|<code>|<address>|<description>|<extra>|<vid>]
 * The description may contain "|", so the trailing two fields are taken from
 * the right.
 *
 * @param {Buffer|string} payload
 */
function parseSiaEvent(payload) {
    const text = (Buffer.isBuffer(payload) ? decodeText(payload) : payload).trim();
    const m = ENVELOPE.exec(text);
    if (!m) {
        throw new SyntaxError(`not an SIA event payload: ${JSON.stringify(text)}`);
    }
    const rest = m[3];
    const first = rest.indexOf('|');
    const second = first < 0 ? -1 : rest.indexOf('|', first + 1);
    if (second < 0) {
        throw new SyntaxError(`not an SIA event payload: ${JSON.stringify(text)}`);
    }
    const code = rest.slice(0, first);
    const address = rest.slice(first + 1, second);
    const tail = rest.slice(second + 1);
    const last = tail.lastIndexOf('|');
    const prev = last < 0 ? -1 : tail.lastIndexOf('|', last - 1);
    if (prev < 0) {
        throw new SyntaxError(`not an SIA event payload: ${JSON.stringify(text)}`);
    }
    const ts = m[2];
    return {
        panelId: Number(m[1]),
        timestampRaw: ts,
        timestamp: formatTimestamp(ts),
        code,
        address,
        description: tail.slice(0, prev),
        extra: tail.slice(prev + 1, last),
        verificationId: tail.slice(last + 1),
    };
}

/** HHMMSSDDMMYYYY (panel-local) to "YYYY-MM-DD HH:MM:SS", or null if invalid. */
function formatTimestamp(raw) {
    const two = i => Number(raw.slice(i, i + 2));
    const [hh, mi, ss, dd, mo] = [two(0), two(2), two(4), two(6), two(8)];
    const yyyy = raw.slice(10, 14);
    if (mo < 1 || mo > 12 || dd < 1 || dd > 31 || hh > 23 || mi > 59 || ss > 59) {
        return null;
    }
    const p = n => String(n).padStart(2, '0');
    return `${yyyy}-${p(mo)}-${p(dd)} ${p(hh)}:${p(mi)}:${p(ss)}`;
}

const FRAG_FIRST = 0x01;
const FRAG_CONT = 0x02;
const MAX_REPLY_BYTES = 1 << 20;

function escapeAttr(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/** Payload for an XML command request (major 10). */
function buildXmlRequest(commandId, continuation, attrs) {
    let extra = '';
    for (const [k, v] of Object.entries(attrs || {})) {
        if (v !== null && v !== undefined) {
            extra += ` ${k.toUpperCase()}="${escapeAttr(v)}"`;
        }
    }
    const xml = `<COMMAND ID="${escapeAttr(commandId)}"${extra} />`;
    return Buffer.concat([Buffer.from([continuation ? FRAG_CONT : FRAG_FIRST]), Buffer.from(xml, 'ascii')]);
}

/** Concatenates fragmented XML reply payloads (each has a 1-byte marker). */
class ReplyAssembler {
    constructor() {
        this.parts = [];
        this.size = 0;
    }

    /** @returns {Buffer|null} the complete reply, or null if more fragments are needed */
    feed(payload) {
        if (!payload || !payload.length) {
            return null;
        }
        const part = payload.subarray(1);
        this.parts.push(part);
        this.size += part.length;
        if (this.size > MAX_REPLY_BYTES) {
            throw new RangeError(`XML reply exceeded ${MAX_REPLY_BYTES} bytes`);
        }
        const all = Buffer.concat(this.parts);
        if (all.includes('</COMMAND_REPLY>')) {
            this.parts = [];
            this.size = 0;
            return all;
        }
        return null;
    }
}

function decodeEntities(s) {
    return s.replace(/&(#x[0-9a-fA-F]+|#\d+|lt|gt|amp|quot|apos);/g, (_, e) => {
        switch (e) {
            case 'lt':
                return '<';
            case 'gt':
                return '>';
            case 'amp':
                return '&';
            case 'quot':
                return '"';
            case 'apos':
                return "'";
            default:
                return String.fromCodePoint(e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
        }
    });
}

const TAG = /<(\/?)([A-Za-z_][\w.:-]*)((?:\s+[\w.:-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>/g;
const ATTR = /([\w.:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;

/**
 * Parse a COMMAND_REPLY into { SECTION: [ {ATTR: value, ...}, ... ] }.
 * The panel's XML is shallow: sections containing attribute-only rows. A leaf
 * section such as <INFO .../> becomes a single-row list.
 *
 * @param {Buffer|string} xml
 */
function parseXmlReply(xml) {
    const text = Buffer.isBuffer(xml) ? decodeText(xml) : xml;
    if (/<!DOCTYPE|<!ENTITY/i.test(text)) {
        throw new SyntaxError('XML reply contains a DTD; rejected');
    }
    const out = {};
    const stack = [];
    let section = null;
    let sawRoot = false;
    TAG.lastIndex = 0;
    let m;
    while ((m = TAG.exec(text)) !== null) {
        const [, closing, name, attrText, selfClosing] = m;
        if (closing) {
            if (stack.pop() !== name) {
                throw new SyntaxError(`malformed XML reply: unexpected </${name}>`);
            }
            if (stack.length === 1 && section && section.name === name) {
                section = null;
            }
            continue;
        }
        const attrs = {};
        ATTR.lastIndex = 0;
        let a;
        while ((a = ATTR.exec(attrText)) !== null) {
            attrs[a[1]] = decodeEntities(a[2] !== undefined ? a[2] : a[3]);
        }
        const depth = stack.length;
        if (depth === 0) {
            if (name !== 'COMMAND_REPLY') {
                throw new SyntaxError(`expected COMMAND_REPLY, got <${name}>`);
            }
            sawRoot = true;
        } else if (depth === 1) {
            out[name] = [];
            if (selfClosing) {
                out[name].push(attrs);
            } else {
                section = { name, attrs };
            }
        } else if (depth === 2 && section) {
            out[section.name].push(attrs);
        }
        if (!selfClosing) {
            stack.push(name);
        }
    }
    if (!sawRoot || stack.length) {
        throw new SyntaxError('malformed XML reply: COMMAND_REPLY not closed');
    }
    // A section without children carries its attributes itself.
    for (const [name, rows] of Object.entries(out)) {
        if (!rows.length) {
            const tag = new RegExp(`<${name}((?:\\s+[\\w.:-]+\\s*=\\s*(?:"[^"]*"|'[^']*'))*)\\s*>`).exec(text);
            const attrs = {};
            if (tag) {
                ATTR.lastIndex = 0;
                let a;
                while ((a = ATTR.exec(tag[1])) !== null) {
                    attrs[a[1]] = decodeEntities(a[2] !== undefined ? a[2] : a[3]);
                }
            }
            if (Object.keys(attrs).length) {
                rows.push(attrs);
            }
        }
    }
    return out;
}

module.exports = {
    PROTOCOL_BYTE,
    PROTOCOL_VERSION,
    HEADER_LEN,
    FLAG_ENCRYPTED,
    FLAG_FROM_RECEIVER,
    Major,
    Minor,
    AreaOp,
    ReplyCode,
    replyMessage,
    FrameDecodeError,
    EncryptionRequired,
    edpChecksum,
    normaliseKey,
    encodeFrame,
    decodeFrame,
    FrameDecoder,
    decodeText,
    parseSiaEvent,
    formatTimestamp,
    buildXmlRequest,
    ReplyAssembler,
    parseXmlReply,
};
