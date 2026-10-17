'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const edp = require('../lib/edp');

const hex = s => Buffer.from(s.replace(/\s+/g, ''), 'hex');

// Frames captured from an SPC4300 (firmware 3.15.0), taken from spcedp's tests.
const HELLO = hex(
    '1d 00 45 02 00 10 15 58 0f e8 03 00 00 e9 03 00 00 01 02 38 9d 08 00 24 cf 64 45 66 0c a4 3d',
);
const HELLO_ACK = hex(
    '1d 00 45 02 08 10 15 58 0f e9 03 00 00 e8 03 00 00 01 03 8c cb 08 00 24 cf 64 45 66 0c a4 3d',
);
const SIA_EVENT = hex(
    '45 00 45 02 00 12 15 58 0f e8 03 00 00 e9 03 00 00 02 00 74 7a 30 00' +
        '45 32 5b 23 31 30 30 30 7c 30 39 31 35 33 34 30 33 30 36 32 30 32 36' +
        '7c 4e 52 7c 30 7c 49 50 20 4c 69 6e 6b 20 52 65 73 74 6f 72 65 7c 7c 30 5d',
);

test('checksum matches captured frames', () => {
    for (const wire of [HELLO, HELLO_ACK, SIA_EVENT]) {
        const struct = wire.subarray(2);
        assert.equal(edp.edpChecksum(struct, struct.readUInt16LE(0x13)), struct.readUInt16LE(0x11));
    }
});

test('decode + encode reproduces captured frames byte for byte', () => {
    for (const wire of [HELLO, HELLO_ACK, SIA_EVENT]) {
        const f = edp.decodeFrame(wire);
        assert.deepEqual(edp.encodeFrame(f), wire);
    }
    const hello = edp.decodeFrame(HELLO);
    assert.equal(hello.sequence, 0x0f581510);
    assert.equal(hello.srcId, 1000);
    assert.equal(hello.dstId, 1001);
    assert.equal(hello.major, 1);
    assert.equal(hello.minor, 2);
});

test('encryption matches the pinned reference bytes and round-trips', () => {
    const key = edp.normaliseKey('00112233445566778899AABBCCDDEEFF');
    const frame = { srcId: 1000, dstId: 1001, sequence: 0xa1e92aab, major: 1, minor: 0, payload: Buffer.from('abcdefgh') };
    const wire = edp.encodeFrame(frame, key);
    assert.deepEqual(wire, hex('1f00450201ab2ae9a1e8030000e9030000289b213cf9f1d72805d90900cf744013'));
    const back = edp.decodeFrame(wire, key);
    assert.deepEqual(back.payload, frame.payload);
    assert.equal(back.sequence, frame.sequence);
    assert.throws(() => edp.decodeFrame(wire, Buffer.alloc(16)), edp.FrameDecodeError);
    assert.throws(() => edp.decodeFrame(wire), edp.EncryptionRequired);
});

test('decoder handles split frames, several frames per chunk and leading garbage', () => {
    const d = new edp.FrameDecoder(null);
    const stream = Buffer.concat([hex('00 ff 13'), HELLO, SIA_EVENT, HELLO_ACK]);
    const out = [];
    for (let i = 0; i < stream.length; i += 7) {
        out.push(...d.feed(stream.subarray(i, i + 7)));
    }
    assert.deepEqual(out.map(f => `${f.major}.${f.minor}`), ['1.2', '2.0', '1.3']);
});

test('SIA events parse, including pipes in the description', () => {
    const ev = edp.parseSiaEvent(edp.decodeFrame(SIA_EVENT).payload);
    assert.equal(ev.panelId, 1000);
    assert.equal(ev.code, 'NR');
    assert.equal(ev.address, '0');
    assert.equal(ev.description, 'IP Link Restore');
    assert.equal(ev.timestamp, '2026-06-03 09:15:34');

    const piped = edp.parseSiaEvent('E2[#1000|10153001012026|ZO|5|Tür|Flur|x|7]');
    assert.equal(piped.description, 'Tür|Flur');
    assert.equal(piped.extra, 'x');
    assert.equal(piped.verificationId, '7');

    const latin1 = Buffer.concat([Buffer.from('E2[#1|99999901012026|BA|3|Haust'), Buffer.from([0xfc, 0xa6]), Buffer.from('r||]')]);
    const ev2 = edp.parseSiaEvent(latin1);
    assert.equal(ev2.description, 'Haustü¦r');
    assert.equal(ev2.timestamp, null);
    assert.equal(ev2.timestampRaw, '99999901012026');
});

test('XML replies are reassembled and parsed', () => {
    const asm = new edp.ReplyAssembler();
    assert.equal(
        asm.feed(Buffer.from('\x01<COMMAND_REPLY><ZONE_STATUS><ZONE ID="1" ZONE_NAME="Hall &amp; Flur" TYPE="1" AREA="1" INPUT="1" />' +
            '<ZONE ID="2" ZONE_NAME="Kitchen" ', 'latin1')),
        null,
    );
    const xml = asm.feed(Buffer.from('\x02TYPE="1" AREA="1" INPUT="0" /></ZONE_STATUS></COMMAND_REPLY>', 'latin1'));
    assert.deepEqual(edp.parseXmlReply(xml), {
        ZONE_STATUS: [
            { ID: '1', ZONE_NAME: 'Hall & Flur', TYPE: '1', AREA: '1', INPUT: '1' },
            { ID: '2', ZONE_NAME: 'Kitchen', TYPE: '1', AREA: '1', INPUT: '0' },
        ],
    });
    assert.deepEqual(edp.parseXmlReply('<COMMAND_REPLY><INFO TYPE="SPC4000" VERSION="3.15.0" /></COMMAND_REPLY>'), {
        INFO: [{ TYPE: 'SPC4000', VERSION: '3.15.0' }],
    });
    assert.deepEqual(edp.parseXmlReply('<COMMAND_REPLY><DOOR_STATUS></DOOR_STATUS></COMMAND_REPLY>'), { DOOR_STATUS: [] });
    assert.throws(() => edp.parseXmlReply('<!DOCTYPE x><COMMAND_REPLY/>'));
    assert.throws(() => edp.parseXmlReply('<OTHER/>'));
});

test('XML request payload', () => {
    assert.deepEqual(edp.buildXmlRequest('zone_status', false), Buffer.from('\x01<COMMAND ID="zone_status" />', 'latin1'));
    assert.equal(edp.buildXmlRequest('zone_status', true)[0], 0x02);
});
