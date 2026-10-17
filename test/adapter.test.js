'use strict';

// End-to-end: the adapter (with a stubbed adapter-core) talks to a simulated
// SPC panel over TCP.

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const Module = require('node:module');
const { EventEmitter } = require('node:events');
const edp = require('../lib/edp');

class FakeAdapter extends EventEmitter {
    constructor(options) {
        super();
        this.namespace = `${options.name}.0`;
        this.config = options.config;
        this.states = {};
        this.objects = {};
        this.log = { debug() {}, info() {}, warn: m => this.warnings.push(m), error: m => this.errors.push(m) };
        this.warnings = [];
        this.errors = [];
    }
    async setState(id, val, ack) {
        id = id.startsWith(this.namespace) ? id.slice(this.namespace.length + 1) : id;
        this.states[id] = { val, ack };
    }
    async extendObject(id, obj) {
        this.objects[id] = obj;
    }
    subscribeStates() {}
    setInterval(fn, ms) {
        return setInterval(fn, ms);
    }
    clearInterval(t) {
        clearInterval(t);
    }
}

const origLoad = Module._load;
Module._load = function (request, ...rest) {
    if (request === '@iobroker/adapter-core') {
        return { Adapter: FakeAdapter };
    }
    return origLoad.call(this, request, ...rest);
};

const KEY = edp.normaliseKey('00112233445566778899aabbccddeeff');

/** Minimal simulated SPC panel (EDP client). */
function startPanel(port, key) {
    const sock = net.connect(port, '127.0.0.1');
    const decoder = new edp.FrameDecoder(key);
    let seq = 100;
    const area = { mode: '0' };
    const frames = [];
    const send = (major, minor, payload, sequence) =>
        sock.write(edp.encodeFrame({ srcId: 1000, dstId: 1001, sequence: sequence ?? ++seq, major, minor, payload: Buffer.from(payload, 'latin1') }, key));
    const reply = (req, xml) => send(10, 1, xml, req.sequence);

    sock.on('data', data => {
        for (const f of decoder.feed(data)) {
            frames.push(f);
            if (f.major === 10 && f.minor === 0) {
                const body = f.payload.toString('latin1');
                const cont = f.payload[0] === 2;
                if (body.includes('"info"')) {
                    reply(f, '\x01<COMMAND_REPLY><INFO TYPE="SPC4000" VARIANT="4300" VERSION="3.15.0" SN="123456" /></COMMAND_REPLY>');
                } else if (body.includes('"area_status"')) {
                    reply(f, `\x01<COMMAND_REPLY><AREA_STATUS><AREA ID="1" NAME="Haus" MODE="${area.mode}" /></AREA_STATUS></COMMAND_REPLY>`);
                } else if (body.includes('"zone_status"')) {
                    reply(
                        f,
                        cont
                            ? '\x02TYPE="0" AREA="1" INPUT="0" /></ZONE_STATUS></COMMAND_REPLY>'
                            : '\x01<COMMAND_REPLY><ZONE_STATUS><ZONE ID="1" ZONE_NAME="Haustür" TYPE="1" AREA="1" INPUT="1" /><ZONE ID="2" ZONE_NAME="Wohnzimmer" ',
                    );
                }
            } else if (f.major === 4 && f.minor === 0) {
                const [op] = f.payload;
                if (op === 0x01 && area.mode === '0') {
                    area.mode = '3';
                    send(4, 2, '\xf0', f.sequence);
                } else if (op === 0x02) {
                    area.mode = '0';
                    send(4, 2, '\xf0', f.sequence);
                } else {
                    send(4, 2, '\xfd', f.sequence);
                }
            }
        }
    });
    return {
        frames,
        area,
        hello: () => send(1, 2, 'abcdefgh'),
        poll: () => send(1, 0, '12345678'),
        event: text => send(2, 0, text),
        close: () => sock.destroy(),
    };
}

const until = async (cond, ms = 3000) => {
    const end = Date.now() + ms;
    while (!cond()) {
        if (Date.now() > end) {
            throw new Error('timeout waiting for condition');
        }
        await new Promise(r => setTimeout(r, 20));
    }
};

for (const encrypted of [false, true]) {
    test(`adapter end-to-end (${encrypted ? 'encrypted' : 'plain'})`, async () => {
        const port = 40000 + Math.floor(Math.random() * 10000);
        const create = require('../main.js');
        const adapter = create({
            config: {
                bind: '127.0.0.1',
                port,
                receiverId: 1001,
                panelId: 0,
                useEncryption: encrypted,
                key: encrypted ? '00112233445566778899aabbccddeeff' : '',
                refreshInterval: 60,
                allowControl: true,
            },
        });
        adapter.emit('ready');
        await until(() => adapter.server && adapter.server.server && adapter.server.server.listening);

        const panel = startPanel(port, encrypted ? KEY : null);
        panel.hello();
        panel.poll();
        await until(() => adapter.states['info.connection']?.val === true);

        // Handshake ACKs echo sequence and payload, flagged from receiver.
        assert.equal(panel.frames[0].major, 1);
        assert.equal(panel.frames[0].minor, 3);
        assert.equal(panel.frames[0].flags, edp.FLAG_FROM_RECEIVER);
        assert.equal(panel.frames[0].srcId, 1001);
        assert.equal(panel.frames[0].dstId, 1000);

        const s = adapter.states;
        assert.equal(s['info.panelType'].val, 'SPC4000 4300');
        assert.equal(s['info.firmware'].val, '3.15.0');
        assert.equal(s['areas.1.mode'].val, 0);
        assert.equal(s['areas.1.armed'].val, false);
        assert.equal(adapter.objects['areas.1'].common.name, 'Haus');
        assert.equal(adapter.objects['zones.1'].common.name, 'Haustür');
        assert.equal(s['zones.1.open'].val, true);
        assert.equal(s['zones.2.open'].val, false);
        assert.equal(s['zones.2.type'].val, 0);

        // Zone event updates immediately.
        panel.event('E2[#1000|12000017102026|ZO|2|Wohnzimmer||0]');
        await until(() => s['zones.2.open'].val === true);
        assert.equal(s['events.lastCode'].val, 'ZO');
        assert.equal(s['events.lastTimestamp'].val, '2026-10-17 12:00:00');

        // Arm via setMode, then alarm, then disarm clears triggered.
        await adapter.onStateChange(`${adapter.namespace}.areas.1.setMode`, { val: 3, ack: false });
        assert.equal(s['areas.1.mode'].val, 3);
        assert.deepEqual(s['areas.1.setMode'], { val: 3, ack: true });

        panel.event('E2[#1000|12010017102026|BA|2|Einbruch||0]');
        await until(() => s['areas.1.triggered'].val === true);

        // Rejected command is reported, state stays.
        await adapter.onStateChange(`${adapter.namespace}.areas.1.setMode`, { val: 1, ack: false });
        assert.match(s['info.lastCommandResult'].val, /rejected/);
        assert.equal(s['areas.1.mode'].val, 3);

        await adapter.onStateChange(`${adapter.namespace}.areas.1.setMode`, { val: 0, ack: false });
        assert.equal(s['areas.1.mode'].val, 0);
        assert.equal(s['areas.1.triggered'].val, false);

        // Arm by keypad: the CL event triggers an area refresh.
        panel.area.mode = '3';
        panel.event('E2[#1000|12020017102026|CL|5|User 5||0]');
        await until(() => s['areas.1.mode'].val === 3);

        panel.close();
        await until(() => s['info.connection'].val === false);
        assert.deepEqual(adapter.errors, []);

        await new Promise(resolve => adapter.emit('unload', resolve));
    });
}
