# ioBroker.spc-edp

ioBroker adapter for Vanderbilt SPC intrusion panels via the native EDP v2
protocol. The panel connects to us: we run a TCP server (default port 50000)
that acts as EDP receiver.

## Layout

- `main.js` – adapter: areas/zones objects, SIA event handling, arm/disarm.
- `lib/edp.js` – framing, checksum, AES-128-ECB encryption, SIA event and XML parsing.
- `lib/session.js` – `EdpServer` / `Session`: ACKs (HELLO/POLL/EVENT), serialized
  commands with 100 ms quiet time, XML fragment reassembly.
- `test/` – `node --test`; `edp.test.js` uses frames captured from an SPC4300,
  `adapter.test.js` runs the adapter against a simulated panel (plain + encrypted).

## Protocol notes

- Ported from spcedp by Ian Duffy (MIT), see its PROTOCOL.md.
- Area commands: major 4, payload [opcode, area, 0]; 0x01 full, 0x02 unset,
  0x0F part A, 0x10 part B; reply 0xF0 = ok.
- Arm/disarm SIA events don't reliably carry area/mode -> re-read AREA_STATUS.

## Field experience (owner's panel)

- Works on the owner's SPC. In that firmware EDP lives under
  Kommunikation -> Div. Protokolle -> EDP; receiver must use TCP/IP, protocol version 2.
- FlexC was considered and dropped: proprietary, and EDP already covers everything.

## Conventions

- UI texts and README in German, code and comments in English.
- Bump `version` in both `package.json` and `io-package.json` and add a `news` entry.
- Install on the ioBroker host: `iobroker url https://github.com/andreaslampl/ioBroker.spc-edp`.
- Arming/disarming is opt-in (`allowControl`), keep it that way.
- Run `npm test` before committing.
