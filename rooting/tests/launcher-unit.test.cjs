'use strict';
const assert = require('assert').strict;
const fs = require('fs');
const os = require('os');
const path = require('path');
const {spawnSync} = require('child_process');
const context = require('./provider-harness.cjs')(path.resolve(__dirname, '..')).context;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vetro-launch-unit-'));
const bin = path.join(tmp, 'bin');
const argsFile = path.join(tmp, 'systemd-run.args');
const pidFile = path.join(tmp, 'agent.pid');
const fixture = path.join(tmp, 'agent.cjs');
const unitMarker = '/tmp/vetro-agent-unit';
const directMarker = '/tmp/vetro-agent-direct';
let pid;
function run(script, env) {
    fs.rmSync(argsFile, {force: true});
    fs.rmSync(pidFile, {force: true});
    const result = spawnSync('/bin/sh', ['-c', script], {timeout: 1000, encoding: 'utf8', env});
    const deadline = Date.now() + 700;
    while (!fs.existsSync(pidFile) && Date.now() < deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
    if (fs.existsSync(pidFile)) pid = Number(fs.readFileSync(pidFile, 'utf8'));
    return result;
}
function stopChild() {
    if (pid) { try { process.kill(pid, 'SIGTERM'); } catch (_) {} pid = undefined; }
}
try {
    fs.mkdirSync(bin);
    fs.writeFileSync(fixture, "require('fs').writeFileSync(process.env.VETRO_TEST_CHILD_PID, String(process.pid)); setInterval(() => {}, 1000);\n");
    fs.writeFileSync(path.join(bin, 'systemd-run'),
        '#!/bin/sh\nprintf "%s\\n" "$@" > ' + argsFile + '\nexit 0\n', {mode: 0o755});
    context.STAGE = tmp;
    context.pkg = 'fixture';
    fs.mkdirSync(path.join(tmp, context.pkg));
    const script = context.buildLaunchScript(12345).replace('/usr/bin/dotnet', process.execPath + ' ' + fixture);
    const env = {...process.env, PATH: bin + ':' + process.env.PATH, VETRO_TEST_CHILD_PID: pidFile};
    fs.rmSync(unitMarker, {force: true});
    fs.rmSync(directMarker, {force: true});

    // Default: no unit marker, no systemd-run, the direct agent starts.
    let result = run(script, env);
    assert.equal(result.status, 0, result.stderr);
    assert.ok(!fs.existsSync(argsFile), 'the unit must be opt-in');
    assert.ok(pid, 'the direct agent must start by default');
    stopChild();

    // A unit marker selects the unit; a successful start must not also start the direct agent.
    fs.writeFileSync(unitMarker, '1\n');
    result = run(script, env);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    const args = fs.readFileSync(argsFile, 'utf8');
    assert.ok(args.includes('--unit=vetro-root'));
    assert.ok(args.includes('--collect'));
    assert.ok(args.includes('SmackProcessLabel=User'));
    assert.ok(args.includes('/bin/sh'));
    assert.ok(!pid, 'the direct agent must not start when the unit did');

    // The kill switch written after a refused unit start wins over the unit marker.
    fs.writeFileSync(directMarker, '1\n');
    result = run(script, env);
    assert.equal(result.status, 0, result.stderr);
    assert.ok(!fs.existsSync(argsFile), 'systemd-run must not be used once the kill switch exists');
    assert.ok(pid, 'the direct agent must start once the kill switch exists');
    console.log('PASS launcher: unit is opt-in, a unit start excludes the direct agent, and the kill switch wins');
} finally {
    stopChild();
    fs.rmSync(unitMarker, {force: true});
    fs.rmSync(directMarker, {force: true});
    fs.rmSync(tmp, {recursive: true, force: true});
}
