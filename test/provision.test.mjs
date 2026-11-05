/** Adversarial tests use disposable databases and random dummy keys, never live T3 state. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHmac, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { apply, issue, keygen, policyHash, readPrivate, sessionId, validatePolicy } from '../src/provision.mjs';

const NOW = Date.parse('2026-11-05T12:00:00Z');
const fixture = fs.readFileSync(new URL('./fixtures/v0.1.6.sql', import.meta.url), 'utf8');
const cli = new URL('../src/cli.mjs', import.meta.url).pathname;
const ids = { ops: '11111111-1111-4111-8111-111111111111', worker: '22222222-2222-4222-8222-222222222222', hp: '33333333-3333-4333-8333-333333333333' };

/** Requirements fixture: ops may operate worker, worker may read hp, and hp may operate worker. */
function policy() {
  return {
    format: 1, t3Version: '0.1.6', revision: 1,
    environments: Object.fromEntries(Object.entries(ids).map(([name, id]) => [name, { id, label: name, urls: [`https://${name}.example.ts.net`] }])),
    links: [
      { from: 'ops', to: 'worker', access: 'approval-required', generation: 1 },
      { from: 'worker', to: 'hp', access: 'read-only', generation: 1 },
      { from: 'hp', to: 'worker', access: 'auto-accept-edits', generation: 1 },
    ],
  };
}

/** Create an initialized T3-shaped home with an existing signing key and ownership lock. */
function environment(root, name, key) {
  const dir = path.join(root, name);
  fs.mkdirSync(path.join(dir, 'secrets'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(dir, 'environment-id'), `${ids[name]}\n`, { mode: 0o600 });
  fs.writeFileSync(path.join(dir, 'secrets/server-signing-key.bin'), key, { mode: 0o600 });
  new DatabaseSync(path.join(dir, 'server-owner.sqlite')).close();
  const db = new DatabaseSync(path.join(dir, 'statev2.sqlite'));
  db.exec(fixture);
  db.close();
  return dir;
}

/** Provide a new private directory per test and always remove its disposable credentials. */
function setup(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 't3router-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const keysDir = path.join(root, 'keys');
  fs.mkdirSync(keysDir, { mode: 0o700 });
  const keys = Object.fromEntries(Object.keys(ids).map(name => [name, randomBytes(32)]));
  for (const [name, key] of Object.entries(keys)) fs.writeFileSync(path.join(keysDir, `${name}.bin`), key, { mode: 0o600 });
  const states = Object.fromEntries(Object.keys(ids).map(name => [name, environment(root, name, keys[name])]));
  let serial = 0;
  return {
    root, keysDir, keys, states,
    bundles(p = policy(), now = NOW) {
      const out = path.join(root, `bundles-${serial++}`);
      issue(p, keysDir, out, { now });
      return Object.fromEntries(Object.keys(ids).map(name => [name, JSON.parse(readPrivate(path.join(out, `${name}.json`)))]));
    },
  };
}

/** Open disposable state only for the duration of a test query or mutation. */
function sql(state, run) {
  const db = new DatabaseSync(path.join(state, 'statev2.sqlite'));
  try { return run(db); } finally { db.close(); }
}

/** Apply with an explicit installed-version assertion; production cannot infer it from the bundle. */
function install(p, name, bundle, state, now = NOW) {
  return apply(p, name, bundle, state, { now, t3Version: '0.1.6' });
}

/** Independent acceptance oracle reproduces v0.1.6 verification, not our issuance helpers. */
function authenticate(token, key, state, now = NOW) {
  const [body, signature] = token.split('.');
  assert.equal(signature, createHmac('sha256', key).update(body).digest('base64url'));
  const claims = JSON.parse(Buffer.from(body, 'base64url'));
  assert.equal(claims.sub, 'mcp-client');
  assert.equal(claims.method, 'bearer-access-token');
  assert.equal(claims.plk, 1);
  assert.ok(claims.exp > now);
  const row = sql(state, db => db.prepare('SELECT * FROM auth_sessions WHERE session_id=?').get(claims.sid));
  assert.ok(row, 'A signature without destination registration is insufficient');
  assert.equal(row.revoked_at, null);
  return { sessionId: claims.sid, access: JSON.parse(row.scopes).includes('orchestration:operate') ? (claims.rtc ?? 'approval-required') : 'read-only' };
}

test('exact directed policy produces distinct fenced principals and no reverse grant', t => {
  const f = setup(t), p = policy(), bundles = f.bundles(p);
  for (const name of Object.keys(ids)) install(p, name, bundles[name], f.states[name]);
  const callers = [];
  for (const link of p.links) {
    const token = bundles[link.from].outgoing.find(e => e.to === link.to).token;
    const caller = authenticate(token, f.keys[link.to], f.states[link.to]);
    assert.equal(caller.access, link.access);
    callers.push(caller.sessionId);
    const row = sql(f.states[link.from], db => db.prepare('SELECT * FROM peer_environment_links WHERE environment_id=?').get(ids[link.to]));
    assert.equal(row.fenced, 1);
    assert.deepEqual(JSON.parse(row.urls_json), p.environments[link.to].urls);
    const file = path.join(f.states[link.from], 'secrets', `${row.secret_name}.bin`);
    assert.equal(readPrivate(file).toString(), token);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  }
  assert.equal(new Set(callers).size, 3);
  assert.equal(sql(f.states.hp, db => db.prepare('SELECT * FROM auth_sessions').all()).length, 1);
  assert.equal(bundles.ops.outgoing.length, 1);
  assert.equal(bundles.worker.signingKey, f.keys.worker.toString('base64'));
  assert.ok(!JSON.stringify(bundles.worker).includes(f.keys.hp.toString('base64')));
});

test('renewal preserves ownership, keeps old token valid until expiry, and is idempotent', t => {
  const f = setup(t), p = policy(), first = f.bundles(p);
  for (const name of Object.keys(ids)) install(p, name, first[name], f.states[name]);
  const later = NOW + 86400_000, renewed = f.bundles(p, later);
  for (const name of Object.keys(ids)) {
    install(p, name, renewed[name], f.states[name], later);
    install(p, name, renewed[name], f.states[name], later);
  }
  const before = authenticate(first.ops.outgoing[0].token, f.keys.worker, f.states.worker, later);
  const after = authenticate(renewed.ops.outgoing[0].token, f.keys.worker, f.states.worker, later);
  assert.equal(before.sessionId, after.sessionId);
  assert.notEqual(first.ops.outgoing[0].token, renewed.ops.outgoing[0].token);
  assert.equal(sql(f.states.worker, db => db.prepare('SELECT COUNT(*) AS n FROM auth_sessions').get()).n, 2);
});

test('removal revokes destination credentials and removes source metadata, leaving manual state untouched', t => {
  const f = setup(t), p = policy(), first = f.bundles(p);
  for (const name of Object.keys(ids)) install(p, name, first[name], f.states[name]);
  sql(f.states.worker, db => db.prepare("INSERT INTO auth_sessions(session_id,subject,method,scopes,issued_at,expires_at) VALUES ('manual','browser','browser-session-cookie','[]','x','y')").run());
  const removed = structuredClone(p);
  removed.revision++;
  removed.links = removed.links.filter(link => link.from !== 'ops');
  const next = f.bundles(removed, NOW + 1);
  for (const name of Object.keys(ids)) install(removed, name, next[name], f.states[name], NOW + 1);
  assert.throws(() => authenticate(first.ops.outgoing[0].token, f.keys.worker, f.states.worker));
  assert.equal(sql(f.states.ops, db => db.prepare('SELECT COUNT(*) AS n FROM peer_environment_links').get()).n, 0);
  assert.equal(sql(f.states.worker, db => db.prepare("SELECT revoked_at FROM auth_sessions WHERE session_id='manual'").get()).revoked_at, null);
});

test('manual revocation is never undone by reconciliation or renewal', t => {
  const f = setup(t), p = policy(), first = f.bundles(p);
  install(p, 'worker', first.worker, f.states.worker);
  const id = sessionId(p, p.links[0]);
  sql(f.states.worker, db => db.prepare('UPDATE auth_sessions SET revoked_at=? WHERE session_id=?').run(new Date(NOW).toISOString(), id));
  assert.throws(() => install(p, 'worker', f.bundles(p, NOW + 1).worker, f.states.worker, NOW + 1), /Revoked/);
  const reauthorized = structuredClone(p);
  reauthorized.revision++;
  reauthorized.links[0].generation++;
  install(reauthorized, 'worker', f.bundles(reauthorized, NOW + 2).worker, f.states.worker, NOW + 2);
  assert.ok(sql(f.states.worker, db => db.prepare('SELECT revoked_at FROM auth_sessions WHERE session_id=?').get(id)).revoked_at);
});

test('permission downgrade revokes the old wider token instead of reusing signed rtc', t => {
  const f = setup(t), p = policy(), first = f.bundles(p);
  install(p, 'worker', first.worker, f.states.worker);
  const reduced = structuredClone(p);
  reduced.revision++;
  reduced.links[0].access = 'read-only';
  const next = f.bundles(reduced, NOW + 1);
  install(reduced, 'worker', next.worker, f.states.worker, NOW + 1);
  assert.throws(() => authenticate(first.ops.outgoing[0].token, f.keys.worker, f.states.worker));
  assert.equal(authenticate(next.ops.outgoing[0].token, f.keys.worker, f.states.worker).access, 'read-only');
  assert.notEqual(sessionId(p, p.links[0]), sessionId(reduced, reduced.links[0]));
});

test('running-server lock is respected across processes and its inode is preserved', t => {
  const f = setup(t), p = policy(), bundles = f.bundles(p, Date.now());
  const policyFile = path.join(f.root, 'policy.json');
  const bundleFile = path.join(f.root, 'bundle.json');
  fs.writeFileSync(policyFile, JSON.stringify(p));
  fs.writeFileSync(bundleFile, JSON.stringify(bundles.worker), { mode: 0o600 });
  const args = [cli, 'apply', '--policy', policyFile, '--environment', 'worker', '--bundle-file', bundleFile, '--state-dir', f.states.worker, '--t3-version', '0.1.6'];
  const lockFile = path.join(f.states.worker, 'server-owner.sqlite');
  const inode = fs.statSync(lockFile).ino;
  const lock = new DatabaseSync(lockFile);
  lock.exec('BEGIN EXCLUSIVE');
  try {
    const result = spawnSync(process.execPath, args, { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /ownership lock/);
    assert.equal(sql(f.states.worker, db => db.prepare('SELECT COUNT(*) AS n FROM auth_sessions').get()).n, 0);
    assert.equal(fs.statSync(lockFile).ino, inode);
  } finally { lock.close(); }
  const unlocked = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.equal(unlocked.status, 0, 'The identical invocation must succeed once the lock is released');
  assert.equal(sql(f.states.worker, db => db.prepare('SELECT COUNT(*) AS n FROM auth_sessions').get()).n, 2);
});

test('wrong key, identity, version, schema and expired bundles fail before authentication state changes', t => {
  const f = setup(t), p = policy(), bundles = f.bundles(p);
  const wrongKey = structuredClone(bundles.worker);
  wrongKey.signingKey = randomBytes(32).toString('base64');
  assert.throws(() => install(p, 'worker', wrongKey, f.states.worker), /key mismatch/);
  assert.throws(() => install(p, 'worker', bundles.worker, f.states.hp), /identity/);
  assert.throws(() => apply(p, 'worker', bundles.worker, f.states.worker, { now: NOW, t3Version: '0.1.7' }), /version/);
  assert.throws(() => install(p, 'worker', bundles.worker, f.states.worker, bundles.worker.expiresAt), /lifetime/);
  assert.throws(() => install(p, 'worker', bundles.worker, f.states.worker, NOW - 60_001), /lifetime/);
  sql(f.states.worker, db => db.exec('ALTER TABLE auth_sessions ADD COLUMN unexpected TEXT'));
  assert.throws(() => install(p, 'worker', bundles.worker, f.states.worker), /schema/);
  assert.equal(sql(f.states.worker, db => db.prepare('SELECT COUNT(*) AS n FROM auth_sessions').get()).n, 0);
  assert.ok(readPrivate(path.join(f.states.worker, 'secrets/server-signing-key.bin')).equals(f.keys.worker));
});

test('rollback, changed same-revision policy, and resurrection after removal fail closed', t => {
  const f = setup(t), p = policy(), first = f.bundles(p);
  install(p, 'worker', first.worker, f.states.worker);
  const edited = structuredClone(p);
  edited.environments.ops.label = 'changed';
  assert.throws(() => install(edited, 'worker', f.bundles(edited, NOW + 1).worker, f.states.worker, NOW + 1), /revision/);
  const removed = structuredClone(p);
  removed.revision = 2;
  removed.links = [];
  install(removed, 'worker', f.bundles(removed, NOW + 2).worker, f.states.worker, NOW + 2);
  assert.throws(() => install(p, 'worker', first.worker, f.states.worker, NOW + 2), /stale/);
  const readded = structuredClone(p);
  readded.revision = 3;
  assert.throws(() => install(readded, 'worker', f.bundles(readded, NOW + 3).worker, f.states.worker, NOW + 3), /Revoked/);
});

test('policy rejects unknown fields, duplicate edges and identities, excessive lifetimes and unsafe origins', t => {
  const f = setup(t);
  const invalid = [
    p => { p.links.push(structuredClone(p.links[0])); },
    p => { p.environments.worker.id = ids.ops; },
    p => { p.links[0].from = 'missing'; },
    p => { p.links[0].to = 'ops'; },
    p => { p.links[0].acess = 'read-only'; },
    p => { p.links[0].generation = 0; },
    p => { p.environments.ops.urls = ['http://ops.example.ts.net']; },
    p => { p.environments.ops.urls = ['https://user:pass@example.com']; },
    p => { p.environments.ops.urls = ['https://example.com/mcp']; },
    p => { p.environments.ops.urls = ['https://example.com?token=hidden']; },
  ];
  for (const corrupt of invalid) { const p = policy(); corrupt(p); assert.throws(() => validatePolicy(p)); }
  assert.throws(() => issue(policy(), f.keysDir, path.join(f.root, 'bad'), { now: NOW, ttlMs: 30 * 86400_000 + 1 }));
  const p = policy();
  const reordered = { links: p.links, environments: p.environments, revision: p.revision, t3Version: p.t3Version, format: p.format };
  assert.equal(policyHash(p), policyHash(reordered));
});

test('shared keys, public secret files, secret-directory symlinks and unmanaged links are refused', t => {
  const f = setup(t), p = policy(), bundles = f.bundles(p);
  const hpKey = path.join(f.keysDir, 'hp.bin');
  fs.writeFileSync(hpKey, f.keys.worker);
  assert.throws(() => f.bundles(p), /share signing/);
  fs.writeFileSync(hpKey, f.keys.hp);
  fs.chmodSync(hpKey, 0o644);
  assert.throws(() => f.bundles(p), /private/);
  const secretDir = path.join(f.states.worker, 'secrets');
  fs.renameSync(secretDir, `${secretDir}-real`);
  fs.symlinkSync(`${secretDir}-real`, secretDir);
  assert.throws(() => install(p, 'worker', bundles.worker, f.states.worker), /Directory/);
  sql(f.states.ops, db => db.prepare("INSERT INTO peer_environment_links VALUES (?,'manual','manual','[]','read-only','x','y',NULL,NULL,1)").run(ids.worker));
  assert.throws(() => install(p, 'ops', bundles.ops, f.states.ops), /manually/);
});

test('malformed or tampered outgoing claims, incomplete bundles, and token-bearing errors reveal no credentials', t => {
  const f = setup(t), p = policy(), bundles = f.bundles(p);
  const bad = structuredClone(bundles.ops);
  const [body, signature] = bad.outgoing[0].token.split('.');
  const claims = JSON.parse(Buffer.from(body, 'base64url'));
  delete claims.plk;
  bad.outgoing[0].token = `${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${signature}`;
  assert.throws(() => install(p, 'ops', bad, f.states.ops), /claims/);
  const incomplete = structuredClone(bundles.ops);
  incomplete.outgoing = [];
  assert.throws(() => install(p, 'ops', incomplete, f.states.ops), /credential set/);
  const file = path.join(f.root, 'bad.json');
  const sentinel = 'DO-NOT-PRINT-THIS-CREDENTIAL';
  fs.writeFileSync(file, sentinel, { mode: 0o600 });
  const out = spawnSync(process.execPath, [cli, 'apply', '--policy', file, '--environment', 'ops', '--bundle-file', file, '--state-dir', f.states.ops, '--t3-version', '0.1.6'], { encoding: 'utf8' });
  assert.equal(out.status, 1);
  assert.ok(!(out.stderr + out.stdout).includes(sentinel));
});

test('key generation never overwrites and respects private permissions', t => {
  const f = setup(t), file = path.join(f.root, 'fresh.bin');
  keygen(file);
  const first = readPrivate(file);
  assert.equal(first.length, 32);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.throws(() => keygen(file));
  assert.ok(readPrivate(file).equals(first));
});
