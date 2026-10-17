'use strict';

const utils = require('@iobroker/adapter-core');
const edp = require('./lib/edp');
const { EdpServer } = require('./lib/session');

const AREA_MODES = { 0: 'Unset', 1: 'Part set A', 2: 'Part set B', 3: 'Full set' };
const MODE_TO_OP = { 0: edp.AreaOp.UNSET, 1: edp.AreaOp.SET_A, 2: edp.AreaOp.SET_B, 3: edp.AreaOp.SET };

const ZONE_INPUTS = {
    0: 'Closed',
    1: 'Open',
    2: 'Short',
    3: 'Disconnected',
    4: 'PIR masked',
    5: 'DC substitution',
    6: 'Sensor missing',
    7: 'Offline',
};

const ZONE_TYPES = {
    0: 'Alarm',
    1: 'Entry/Exit',
    2: 'Exit terminator',
    3: 'Fire',
    4: 'Fire exit',
    5: 'Line',
    6: 'Panic',
    7: 'Hold up',
    8: 'Tamper',
    9: 'Technical',
    10: 'Medical',
    11: 'Key arm',
    12: 'Unused',
    13: 'Shunt',
    14: 'X-Shunt',
    15: 'Fault',
    16: 'Lock supervision',
    17: 'Seismic',
    18: 'All okay',
    19: 'Hold up fault',
    20: 'Warning fault',
    21: 'Setting authorisation',
    22: 'Lock element',
    23: 'Glassbreak',
    24: 'Water',
    25: 'Heat',
    26: 'Fridge/Freezer',
    27: 'Gas',
    28: 'Sprinkler',
    29: 'CO',
    30: 'Entry/Exit 2',
};

// Alarm codes that name a zone and mark its area triggered.
const ALARM_CODES = new Set(['BA', 'FA', 'PA', 'HA', 'TA']);
// Arm/disarm codes do not reliably carry the mode or even the area, so the
// area status is read from the panel instead.
const AREA_STATUS_CODES = new Set(['BV', 'CG', 'CL', 'NL', 'OG', 'OP']);

class SpcEdp extends utils.Adapter {
    constructor(options) {
        super({ ...options, name: 'spc-edp' });
        this.server = null;
        this.session = null;
        this.work = Promise.resolve();
        this.refreshTimer = null;
        this.areas = new Map();
        this.zones = new Map();
        this.objectNames = new Map();

        this.on('ready', this.onReady.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
        this.on('unload', this.onUnload.bind(this));
    }

    async onReady() {
        await this.setState('info.connection', false, true);

        const cfg = this.config;
        const receiverId = Number(cfg.receiverId);
        const port = Number(cfg.port);
        if (!Number.isInteger(receiverId) || receiverId < 1 || !Number.isInteger(port) || port < 1 || port > 65535) {
            this.log.error('Invalid configuration: receiver ID and port are required');
            return;
        }

        this.server = new EdpServer({
            receiverId,
            key: cfg.useEncryption ? cfg.key : null,
            bind: cfg.bind || '0.0.0.0',
            port,
            log: this.log,
        });
        this.server.on('session', session => this.onSession(session));
        try {
            await this.server.listen();
        } catch (err) {
            this.log.error(`Cannot listen on ${cfg.bind || '0.0.0.0'}:${port}: ${err.message}`);
            return;
        }
        this.log.info(
            `Waiting for SPC panel on ${cfg.bind || '0.0.0.0'}:${port} (receiver ID ${receiverId}` +
                `${cfg.useEncryption ? ', encrypted' : ''})`,
        );

        if (cfg.allowControl) {
            this.subscribeStates('areas.*.setMode');
        }
    }

    onSession(session) {
        const expectedPanel = Number(this.config.panelId) || 0;
        session.once('ready', () => {
            if (expectedPanel && session.panelId !== expectedPanel) {
                this.log.warn(`Rejecting EDP panel ${session.panelId}, expected ${expectedPanel}`);
                session.close();
                return;
            }
            if (this.session && this.session !== session) {
                this.log.info('New panel connection replaces the previous one');
                this.session.close();
            }
            this.session = session;
            this.work = Promise.resolve();
            this.enqueue(async () => {
                await this.refreshAll();
                await this.setState('info.connection', true, true);
                await this.setState('info.panelId', session.panelId, true);
            });
            this.startRefreshTimer();
        });
        session.on('event', event => {
            if (this.session === session) {
                this.enqueue(() => this.handleEvent(event));
            }
        });
        session.on('close', () => {
            if (this.session !== session) {
                return;
            }
            this.log.info('SPC panel disconnected');
            this.session = null;
            this.stopRefreshTimer();
            this.setState('info.connection', false, true);
        });
    }

    /** Serialize panel work (refreshes, events, commands) in arrival order. */
    enqueue(fn) {
        const run = this.work.then(fn);
        this.work = run.catch(err => {
            if (this.session) {
                this.log.warn(err.message);
            }
        });
        return run;
    }

    startRefreshTimer() {
        this.stopRefreshTimer();
        const seconds = Math.max(10, Number(this.config.refreshInterval) || 60);
        this.refreshTimer = this.setInterval(() => {
            this.enqueue(async () => {
                await this.refreshAreas();
                await this.refreshZones();
            });
        }, seconds * 1000);
    }

    stopRefreshTimer() {
        if (this.refreshTimer) {
            this.clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
    }

    async refreshAll() {
        const info = (await this.session.xmlCommand('info')).INFO;
        const row = (info && info[0]) || {};
        await this.setState('info.panelType', `${row.TYPE || ''} ${row.VARIANT || ''}`.trim(), true);
        await this.setState('info.firmware', row.VERSION || '', true);
        await this.setState('info.serial', row.SN || '', true);
        await this.refreshAreas();
        await this.refreshZones();
    }

    async refreshAreas() {
        if (!this.session) {
            return;
        }
        const reply = await this.session.xmlCommand('area_status');
        for (const row of reply.AREA_STATUS || []) {
            const id = parseId(row.ID);
            if (id === null) {
                continue;
            }
            const mode = row.MODE in AREA_MODES ? Number(row.MODE) : null;
            const prev = this.areas.get(id);
            // "triggered" comes from events; keep it until the panel reports unset.
            const triggered = mode !== 0 && prev ? prev.triggered : false;
            this.areas.set(id, { mode, triggered });
            await this.ensureAreaObjects(id, row.NAME || `Area ${id}`);
            await this.updateArea(id);
        }
    }

    async updateArea(id) {
        const area = this.areas.get(id);
        await this.setState(`areas.${id}.mode`, area.mode, true);
        await this.setState(`areas.${id}.armed`, area.mode === null ? null : area.mode !== 0, true);
        await this.setState(`areas.${id}.triggered`, area.triggered, true);
        if (this.config.allowControl) {
            await this.setState(`areas.${id}.setMode`, area.mode, true);
        }
    }

    async refreshZones() {
        if (!this.session) {
            return;
        }
        const reply = await this.session.xmlCommand('zone_status');
        for (const row of reply.ZONE_STATUS || []) {
            const id = parseId(row.ID);
            if (id === null) {
                continue;
            }
            const zone = {
                input: row.INPUT in ZONE_INPUTS ? Number(row.INPUT) : null,
                area: parseId(row.AREA) || 0,
                type: row.TYPE in ZONE_TYPES ? Number(row.TYPE) : null,
            };
            this.zones.set(id, zone);
            await this.ensureZoneObjects(id, row.ZONE_NAME || `Zone ${id}`);
            await this.setState(`zones.${id}.type`, zone.type, true);
            await this.setState(`zones.${id}.area`, zone.area, true);
            await this.updateZone(id);
        }
    }

    async updateZone(id) {
        const zone = this.zones.get(id);
        const open = zone.input === 1 ? true : zone.input === 0 ? false : null;
        await this.setState(`zones.${id}.input`, zone.input, true);
        await this.setState(`zones.${id}.open`, open, true);
    }

    async handleEvent(ev) {
        const code = ev.code.toUpperCase();
        this.log.debug(`SIA event ${code} address=${ev.address} "${ev.description}"`);
        await this.setState('events.lastCode', code, true);
        await this.setState('events.lastAddress', ev.address, true);
        await this.setState('events.lastDescription', ev.description, true);
        await this.setState('events.lastTimestamp', ev.timestamp || ev.timestampRaw, true);
        await this.setState('events.last', JSON.stringify(ev), true);

        const target = /^\d+$/.test(ev.address.trim()) ? Number(ev.address.trim()) : null;

        if (AREA_STATUS_CODES.has(code)) {
            await this.refreshAreas();
            if (code === 'BV' && target !== null && this.areas.has(target)) {
                this.areas.get(target).triggered = true;
                await this.updateArea(target);
            }
            return;
        }

        if (code !== 'ZC' && code !== 'ZO' && !ALARM_CODES.has(code)) {
            return;
        }
        const zone = target !== null ? this.zones.get(target) : undefined;
        if (!zone) {
            return;
        }
        zone.input = code === 'ZC' ? 0 : 1;
        await this.updateZone(target);
        if (ALARM_CODES.has(code) && this.areas.has(zone.area)) {
            this.areas.get(zone.area).triggered = true;
            await this.updateArea(zone.area);
        }
    }

    async onStateChange(id, state) {
        if (!state || state.ack) {
            return;
        }
        const m = /\.areas\.(\d+)\.setMode$/.exec(id);
        if (!m || !this.config.allowControl) {
            return;
        }
        const areaId = Number(m[1]);
        const op = MODE_TO_OP[state.val];
        const current = this.areas.has(areaId) ? this.areas.get(areaId).mode : null;
        if (op === undefined) {
            this.log.warn(`Invalid mode ${state.val} for area ${areaId} (0=unset, 1=part A, 2=part B, 3=full)`);
            await this.setState(id, current, true);
            return;
        }
        if (!this.session) {
            this.log.warn(`Cannot set area ${areaId}: panel not connected`);
            await this.setState(id, current, true);
            return;
        }
        const session = this.session;
        this.log.info(`Setting area ${areaId} to ${AREA_MODES[state.val]}`);
        try {
            await session.areaCommand(op, areaId);
            await this.setState('info.lastCommandResult', `area ${areaId}: ${AREA_MODES[state.val]} ok`, true);
        } catch (err) {
            this.log.warn(`Area ${areaId} command failed: ${err.message}`);
            await this.setState('info.lastCommandResult', `area ${areaId}: ${err.message}`, true);
        }
        // The panel is the source of truth; this also acknowledges setMode.
        await this.enqueue(() => this.refreshAreas()).catch(() => {});
    }

    async ensureAreaObjects(id, name) {
        if (this.objectNames.get(`areas.${id}`) === name) {
            return;
        }
        await this.extendObject(`areas.${id}`, { type: 'channel', common: { name }, native: {} });
        await this.extendObject(`areas.${id}.mode`, {
            type: 'state',
            common: {
                name: { en: 'Arm mode', de: 'Scharfschaltzustand' },
                type: 'number',
                role: 'value',
                read: true,
                write: false,
                states: AREA_MODES,
            },
            native: {},
        });
        await this.extendObject(`areas.${id}.armed`, {
            type: 'state',
            common: {
                name: { en: 'Armed (any mode)', de: 'Scharf (beliebiger Modus)' },
                type: 'boolean',
                role: 'indicator',
                read: true,
                write: false,
            },
            native: {},
        });
        await this.extendObject(`areas.${id}.triggered`, {
            type: 'state',
            common: {
                name: { en: 'Alarm triggered', de: 'Alarm ausgelöst' },
                type: 'boolean',
                role: 'indicator.alarm',
                read: true,
                write: false,
            },
            native: {},
        });
        if (this.config.allowControl) {
            await this.extendObject(`areas.${id}.setMode`, {
                type: 'state',
                common: {
                    name: { en: 'Set arm mode', de: 'Scharfschalten / Unscharfschalten' },
                    type: 'number',
                    role: 'level.mode',
                    read: true,
                    write: true,
                    states: AREA_MODES,
                },
                native: {},
            });
        }
        this.objectNames.set(`areas.${id}`, name);
    }

    async ensureZoneObjects(id, name) {
        if (this.objectNames.get(`zones.${id}`) === name) {
            return;
        }
        await this.extendObject(`zones.${id}`, { type: 'channel', common: { name }, native: {} });
        const states = {
            open: {
                name: { en: 'Open', de: 'Offen' },
                type: 'boolean',
                role: 'sensor',
            },
            input: {
                name: { en: 'Input state', de: 'Eingangszustand' },
                type: 'number',
                role: 'value',
                states: ZONE_INPUTS,
            },
            type: {
                name: { en: 'Zone type', de: 'Zonentyp' },
                type: 'number',
                role: 'value',
                states: ZONE_TYPES,
            },
            area: {
                name: { en: 'Area', de: 'Bereich' },
                type: 'number',
                role: 'value',
            },
        };
        for (const [key, common] of Object.entries(states)) {
            await this.extendObject(`zones.${id}.${key}`, {
                type: 'state',
                common: { ...common, read: true, write: false },
                native: {},
            });
        }
        this.objectNames.set(`zones.${id}`, name);
    }

    async onUnload(callback) {
        try {
            this.stopRefreshTimer();
            if (this.server) {
                await this.server.close();
            }
            await this.setState('info.connection', false, true);
        } finally {
            callback();
        }
    }
}

function parseId(raw) {
    return typeof raw === 'string' && /^\d+$/.test(raw) ? Number(raw) : null;
}

if (require.main !== module) {
    module.exports = options => new SpcEdp(options);
} else {
    new SpcEdp();
}
