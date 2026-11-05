/** Offline, version-pinned provisioning of T3's native peer links. No network calls. */
import * as fs from 'node:fs';
import path from 'node:path';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

export const T3_VERSION = '0.1.6';
export const UPSTREAM_REVISION = '2359643cffa6ba9ee84d6f2694b935de54a8013e';
const MAX_TTL = 30 * 24 * 60 * 60 * 1000;
const MODES = ['read-only', 'approval-required', 'auto-accept-edits', 'auto', 'full-access'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NAME = /^[a-z][a-z0-9-]{0,62}$/;

/** An explicitly safe diagnostic that contains no user-supplied values or secrets. */
export class ProvisionError extends Error {}

/** Reject unsafe input without including credential values in diagnostics. */
function requireThat(condition, message) {
  if (!condition) throw new ProvisionError(message);
}

/** Canonicalize public policy so attribute ordering never changes its identity. */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/** Reject misspelled fields rather than silently ignoring intended restrictions. */
function fields(value, allowed) {
  requireThat(value !== null && typeof value === 'object' && !Array.isArray(value), 'Expected an object');
  requireThat(Object.keys(value).every(k => allowed.includes(k)), 'Unknown configuration field');
}

/** Validate an explicit, default-deny inventory. URLs must be origins, not credential-bearing URLs. */
export function validatePolicy(policy) {
  fields(policy, ['format', 't3Version', 'revision', 'environments', 'links']);
  requireThat(policy.format === 1 && policy.t3Version === T3_VERSION, 'Unsupported policy or T3 version');
  requireThat(Number.isSafeInteger(policy.revision) && policy.revision > 0, 'Invalid policy revision');
  fields(policy.environments, Object.keys(policy.environments ?? {}));
  requireThat(Object.keys(policy.environments).length > 0, 'Empty inventory');
  const ids = new Set();
  for (const [name, env] of Object.entries(policy.environments)) {
    fields(env, ['id', 'label', 'urls']);
    requireThat(NAME.test(name) && UUID.test(env.id) && !ids.has(env.id), 'Invalid or duplicate environment identity');
    ids.add(env.id);
    requireThat(typeof env.label === 'string' && env.label.length > 0 && env.label.length <= 100 && !/[\x00-\x1f\x7f]/.test(env.label), 'Invalid environment label');
    requireThat(Array.isArray(env.urls) && env.urls.length > 0 && env.urls.length <= 8, 'Missing environment URLs');
    for (const raw of env.urls) {
      let url;
      try { url = new URL(raw); } catch { throw new Error('Invalid environment URL'); }
      const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
      requireThat((url.protocol === 'https:' || (url.protocol === 'http:' && loopback)) &&
        !url.username && !url.password && !url.search && !url.hash &&
        url.pathname === '/' && raw === url.origin, 'Require HTTPS origins (HTTP only on loopback)');
    }
  }
  requireThat(Array.isArray(policy.links), 'Missing link policy');
  const edges = new Set();
  for (const link of policy.links) {
    fields(link, ['from', 'to', 'access', 'generation']);
    requireThat(Object.hasOwn(policy.environments, link.from) && Object.hasOwn(policy.environments, link.to) && link.from !== link.to, 'Unknown or self-directed link');
    requireThat(MODES.includes(link.access), 'Invalid link access');
    requireThat(Number.isSafeInteger(link.generation) && link.generation > 0, 'Invalid credential generation');
    const edge = `${link.from}:${link.to}`;
    requireThat(!edges.has(edge), 'Duplicate directed link');
    edges.add(edge);
  }
  return policy;
}

/** Hash public policy only; no credential is placed in the digest input. */
export function policyHash(policy) {
  return createHash('sha256').update(canonical(validatePolicy(policy))).digest('hex');
}

/** Keep ownership stable on renewal; permission changes and explicit generations get new owners. */
export function sessionId(policy, link) {
  const bytes = createHash('sha256').update(canonical([
    't3router/v1', policy.environments[link.from].id, policy.environments[link.to].id,
    link.access, link.generation,
  ])).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x80;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Match v0.1.6 mcpClientScopes, including full-access administrative scopes. */
export function scopes(access) {
  return ['orchestration:read',
    ...(access === 'read-only' ? [] : ['orchestration:operate']),
    ...(access === 'full-access' ? ['settings:write', 'source-control:write'] : []),
  ];
}

/** Signed plk and rtc claims are required; SQL fenced=1 alone is not sufficient. */
function claimsFor(policy, link, issuedAt, expiresAt) {
  return {
    v: 1, kind: 'session', sid: sessionId(policy, link), sub: 'mcp-client',
    scopes: scopes(link.access), method: 'bearer-access-token',
    ...(link.access === 'read-only' ? {} : { rtc: link.access }),
    plk: 1, iat: issuedAt, exp: expiresAt,
  };
}

/** Read runtime secrets, following sops-nix's symlink but refusing public or foreign-owned targets. */
export function readPrivate(file) {
  const fd = fs.openSync(fs.realpathSync(file), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const st = fs.fstatSync(fd);
    requireThat(st.isFile() && (st.uid === process.getuid() || st.uid === 0) && (st.mode & 0o077) === 0, 'Secret file must be private and owned by this user or root');
    requireThat(st.size <= 4 * 1024 * 1024, 'Secret file is too large');
    return fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
}

/** Make a published filename durable before committing a SQLite row that refers to it. */
function syncDirectory(dir) {
  const fd = fs.openSync(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

/** Create one private directory; its parent must already exist and new entries must be durable. */
function privateDirectory(dir) {
  try { fs.mkdirSync(dir, { mode: 0o700 }); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  const st = fs.lstatSync(dir);
  requireThat(st.isDirectory() && !st.isSymbolicLink() && st.uid === process.getuid() && (st.mode & 0o077) === 0, 'Directory must be private and owned by this user');
  syncDirectory(dir);
  syncDirectory(path.dirname(dir));
}

/** Write new secret material exclusively; an existing file is never silently overwritten. */
export function writePrivate(file, bytes) {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  syncDirectory(path.dirname(file));
}

/** Generate a fresh environment key only when explicitly requested; never print it. */
export function keygen(file) {
  writePrivate(file, randomBytes(32));
}

/** Issue private per-environment bundles. Keys never leave their destination's bundle. */
export function issue(policy, keysDir, outputDir, { now = Date.now(), ttlMs = MAX_TTL } = {}) {
  validatePolicy(policy);
  requireThat(Number.isSafeInteger(now) && now > 0 && Number.isSafeInteger(ttlMs) && ttlMs > 0 && ttlMs <= MAX_TTL, 'Invalid credential lifetime (maximum 30 days)');
  requireThat(!fs.existsSync(outputDir), 'Output directory already exists; use a new private directory');
  const keys = new Map();
  for (const name of Object.keys(policy.environments)) {
    const key = readPrivate(path.join(keysDir, `${name}.bin`));
    requireThat(key.length === 32, 'Signing keys must be exactly 32 raw bytes');
    requireThat(![...keys.values()].some(previous => previous.equals(key)), 'Environments must not share signing keys');
    keys.set(name, key);
  }
  const bundles = new Map(Object.entries(policy.environments).map(([name, env]) => [name, {
    format: 1, t3Version: T3_VERSION, environmentId: env.id,
    policyHash: policyHash(policy), issuedAt: now, expiresAt: now + ttlMs,
    signingKey: keys.get(name).toString('base64'), outgoing: [],
  }]));
  for (const link of policy.links) {
    const payload = Buffer.from(JSON.stringify(claimsFor(policy, link, now, now + ttlMs))).toString('base64url');
    const signature = createHmac('sha256', keys.get(link.to)).update(payload).digest('base64url');
    bundles.get(link.from).outgoing.push({ to: link.to, token: `${payload}.${signature}` });
  }
  privateDirectory(outputDir);
  for (const [name, bundle] of bundles) writePrivate(path.join(outputDir, `${name}.json`), `${JSON.stringify(bundle)}\n`);
  return { environments: bundles.size, links: policy.links.length };
}

/** Validate all bundle metadata and outgoing claims before touching persistent state. */
function validateBundle(policy, name, bundle, now) {
  const env = policy.environments[name];
  requireThat(env !== undefined, 'Unknown local environment');
  fields(bundle, ['format', 't3Version', 'environmentId', 'policyHash', 'issuedAt', 'expiresAt', 'signingKey', 'outgoing']);
  requireThat(bundle.format === 1 && bundle.t3Version === T3_VERSION && bundle.environmentId === env.id && bundle.policyHash === policyHash(policy), 'Bundle does not match declared environment and policy');
  requireThat(Number.isSafeInteger(bundle.issuedAt) && Number.isSafeInteger(bundle.expiresAt) && bundle.issuedAt > 0 && bundle.issuedAt <= now + 60_000 && bundle.expiresAt > now && bundle.expiresAt > bundle.issuedAt && bundle.expiresAt - bundle.issuedAt <= MAX_TTL, 'Expired, future, or invalid bundle lifetime');
  requireThat(typeof bundle.signingKey === 'string', 'Missing signing key');
  const key = Buffer.from(bundle.signingKey, 'base64');
  requireThat(key.length === 32 && key.toString('base64') === bundle.signingKey, 'Invalid signing key encoding');
  const expected = policy.links.filter(link => link.from === name);
  requireThat(Array.isArray(bundle.outgoing) && bundle.outgoing.length === expected.length, 'Incorrect outgoing credential set');
  const seen = new Set();
  for (const entry of bundle.outgoing) {
    fields(entry, ['to', 'token']);
    const link = expected.find(link => link.to === entry.to);
    requireThat(link !== undefined && !seen.has(entry.to) && typeof entry.token === 'string', 'Unexpected or duplicate outgoing credential');
    seen.add(entry.to);
    const parts = entry.token.split('.');
    requireThat(parts.length === 2 && /^[A-Za-z0-9_-]+$/.test(parts[0]) && /^[A-Za-z0-9_-]{43}$/.test(parts[1]), 'Malformed outgoing credential');
    let claims;
    try { claims = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); } catch { throw new Error('Malformed outgoing credential'); }
    requireThat(canonical(claims) === canonical(claimsFor(policy, link, bundle.issuedAt, bundle.expiresAt)), 'Outgoing credential claims do not match policy');
  }
  return key;
}

const AUTH_COLUMNS = ['session_id', 'subject', 'scopes', 'method', 'issued_at', 'expires_at', 'revoked_at', 'client_label', 'client_ip_address', 'client_user_agent', 'client_device_type', 'client_os', 'client_browser', 'last_connected_at', 'client_surface', 'client_app_version'];
const LINK_COLUMNS = ['environment_id', 'secret_name', 'label', 'urls_json', 'access', 'linked_at', 'expires_at', 'last_reached_at', 'last_error', 'fenced'];

/** Refuse uninitialized, upgraded, or altered databases; never run T3's migrations ourselves. */
function checkSchema(db) {
  for (const [table, columns] of [['auth_sessions', AUTH_COLUMNS], ['peer_environment_links', LINK_COLUMNS]]) {
    const actual = db.prepare(`PRAGMA table_info(${table})`).all();
    requireThat(canonical(actual.map(row => row.name).sort()) === canonical([...columns].sort()), 'Unsupported T3 database schema');
    requireThat(actual.find(row => row.name === columns[0])?.pk === 1, 'Unsupported T3 primary key');
  }
  const head = db.prepare('SELECT MAX(migration_id) AS head FROM effect_sql_migrations').get();
  requireThat(head.head === 76, 'Unsupported T3 migration head (expected v0.1.6 / 76)');
}

/** Refuse nonregular or foreign-owned state files before opening SQLite or changing secrets. */
function ownedFile(file) {
  const st = fs.lstatSync(file);
  requireThat(st.isFile() && !st.isSymbolicLink() && st.uid === process.getuid() && st.nlink === 1, 'State files must be regular files owned by this user');
}

/** Use T3's own lifetime lock; a running server causes refusal, never a stop or restart. */
function withStoppedState(stateDir, run) {
  const real = fs.realpathSync(stateDir);
  const st = fs.statSync(real);
  requireThat(st.isDirectory() && st.uid === process.getuid() && (st.mode & 0o022) === 0, 'Unsafe T3 state directory');
  for (const name of ['statev2.sqlite', 'server-owner.sqlite', 'environment-id']) ownedFile(path.join(real, name));
  const lock = new DatabaseSync(path.join(real, 'server-owner.sqlite'));
  let db;
  try {
    try { lock.exec('PRAGMA busy_timeout=0; BEGIN EXCLUSIVE'); }
    catch { throw new ProvisionError('T3 is running or its ownership lock is unavailable; no changes made'); }
    db = new DatabaseSync(path.join(real, 'statev2.sqlite'));
    db.exec('PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; BEGIN IMMEDIATE');
    checkSchema(db);
    const result = run(db, real);
    db.exec('COMMIT');
    return result;
  } finally {
    // Closing rolls back on failure. The lock inode is never removed or replaced.
    db?.close();
    lock.close();
  }
}

/** Track only our objects in the same SQL transaction; revoked rows remain tombstones. */
function ensureTracking(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS t3router_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL,
    policy_hash TEXT NOT NULL, issued_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS t3router_sessions (
    session_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, access TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS t3router_links (
    environment_id TEXT PRIMARY KEY, secret_name TEXT NOT NULL);`);
  // Tracking data is persistent input too. Never turn a corrupt filename into an unlink path.
  for (const row of db.prepare('SELECT * FROM t3router_links').all()) {
    requireThat(UUID.test(row.environment_id) && /^peer-link-t3router-[0-9a-f]{64}$/.test(row.secret_name), 'Corrupt managed link tracking');
  }
  for (const row of db.prepare('SELECT * FROM t3router_sessions').all()) {
    requireThat(UUID.test(row.session_id) && UUID.test(row.source_id) && MODES.includes(row.access), 'Corrupt managed session tracking');
  }
}

/** Apply a bundle offline. Renewal keeps session IDs; revoked IDs can never be resurrected. */
export function apply(policy, name, bundle, stateDir, { now = Date.now(), t3Version } = {}) {
  validatePolicy(policy);
  requireThat(t3Version === T3_VERSION, 'Explicit matching installed T3 version is required');
  const key = validateBundle(policy, name, bundle, now);
  const cleanup = [];
  const result = withStoppedState(stateDir, (db, real) => {
    requireThat(fs.readFileSync(path.join(real, 'environment-id'), 'utf8').trim() === bundle.environmentId, 'Local T3 identity does not match; refusing to replace it');
    const secretsDir = path.join(real, 'secrets');
    // Validate before creating anything. Existing signing authority is never replaced.
    const keyPath = path.join(secretsDir, 'server-signing-key.bin');
    const existingKey = fs.existsSync(keyPath) ? readPrivate(keyPath) : undefined;
    requireThat(existingKey === undefined || (existingKey.length === key.length && timingSafeEqual(existingKey, key)), 'Signing key mismatch; rotation requires a separate migration');
    requireThat(existingKey !== undefined || db.prepare('SELECT COUNT(*) AS n FROM auth_sessions').get().n === 0, 'Missing signing key on an existing authenticated environment');
    ensureTracking(db);
    const previous = db.prepare('SELECT * FROM t3router_state WHERE singleton=1').get();
    requireThat(previous === undefined || (policy.revision >= previous.revision && bundle.issuedAt >= previous.issued_at && (policy.revision !== previous.revision || bundle.policyHash === previous.policy_hash)), 'Refusing stale policy, changed policy without revision, or older credentials');
    const incoming = policy.links.filter(link => link.to === name);
    const incomingIds = new Set(incoming.map(link => sessionId(policy, link)));
    const stamp = new Date(now).toISOString();
    // Preflight every conflict before any secret file is published.
    for (const link of incoming) {
      const id = sessionId(policy, link);
      const row = db.prepare('SELECT * FROM auth_sessions WHERE session_id=?').get(id);
      const owned = db.prepare('SELECT * FROM t3router_sessions WHERE session_id=?').get(id);
      requireThat(row === undefined || owned !== undefined, 'Session collision with unmanaged state');
      requireThat(row === undefined || row.revoked_at === null, 'Revoked credential cannot be restored; increase its generation');
      requireThat(row === undefined || (row.subject === 'mcp-client' && row.method === 'bearer-access-token' && canonical(JSON.parse(row.scopes)) === canonical(scopes(link.access))), 'Managed session was altered outside provisioning');
      requireThat(owned === undefined || row !== undefined, 'Managed session was deleted; increase its generation');
    }
    for (const entry of bundle.outgoing) {
      const destId = policy.environments[entry.to].id;
      const row = db.prepare('SELECT * FROM peer_environment_links WHERE environment_id=?').get(destId);
      const owned = db.prepare('SELECT * FROM t3router_links WHERE environment_id=?').get(destId);
      requireThat(row === undefined || (owned !== undefined && owned.secret_name === row.secret_name), 'Link collision with manually managed state');
    }
    privateDirectory(secretsDir);
    if (existingKey === undefined) writePrivate(keyPath, key);
    for (const row of db.prepare('SELECT session_id FROM t3router_sessions').all()) {
      if (!incomingIds.has(row.session_id)) db.prepare('UPDATE auth_sessions SET revoked_at=? WHERE session_id=? AND revoked_at IS NULL').run(stamp, row.session_id);
    }
    for (const link of incoming) {
      const id = sessionId(policy, link);
      const issued = new Date(bundle.issuedAt).toISOString();
      const expires = new Date(bundle.expiresAt).toISOString();
      db.prepare(`INSERT INTO auth_sessions
        (session_id,subject,scopes,method,client_label,client_ip_address,client_user_agent,client_device_type,client_os,client_browser,issued_at,expires_at,revoked_at)
        VALUES (?,'mcp-client',?,'bearer-access-token',?,NULL,NULL,'bot',NULL,NULL,?,?,NULL)
        ON CONFLICT(session_id) DO UPDATE SET expires_at=excluded.expires_at`).run(id, JSON.stringify(scopes(link.access)), `t3router: ${policy.environments[link.from].label}`, issued, expires);
      db.prepare('INSERT OR IGNORE INTO t3router_sessions VALUES (?,?,?)').run(id, policy.environments[link.from].id, link.access);
    }
    const desired = new Set(bundle.outgoing.map(entry => policy.environments[entry.to].id));
    for (const row of db.prepare('SELECT * FROM t3router_links').all()) {
      if (desired.has(row.environment_id)) continue;
      // Do not erase a link the operator replaced manually after our last run.
      db.prepare('DELETE FROM peer_environment_links WHERE environment_id=? AND secret_name=?').run(row.environment_id, row.secret_name);
      db.prepare('DELETE FROM t3router_links WHERE environment_id=?').run(row.environment_id);
      cleanup.push(path.join(secretsDir, `${row.secret_name}.bin`));
    }
    for (const entry of bundle.outgoing) {
      const env = policy.environments[entry.to];
      const digest = createHash('sha256').update(entry.token).digest('hex');
      const secretName = `peer-link-t3router-${digest}`;
      const secretPath = path.join(secretsDir, `${secretName}.bin`);
      const previousLink = db.prepare('SELECT * FROM t3router_links WHERE environment_id=?').get(env.id);
      if (fs.existsSync(secretPath)) requireThat(readPrivate(secretPath).equals(Buffer.from(entry.token)), 'Existing secret conflicts with bundle');
      else writePrivate(secretPath, entry.token);
      db.prepare(`INSERT INTO peer_environment_links
        (environment_id,secret_name,label,urls_json,access,linked_at,expires_at,last_reached_at,last_error,fenced)
        VALUES (?,?,?,?,?,?,?,NULL,NULL,1)
        ON CONFLICT(environment_id) DO UPDATE SET secret_name=excluded.secret_name,label=excluded.label,
        urls_json=excluded.urls_json,access=excluded.access,expires_at=excluded.expires_at,last_error=NULL,fenced=1`).run(
          env.id, secretName, env.label, JSON.stringify(env.urls),
          policy.links.find(link => link.from === name && link.to === entry.to).access,
          new Date(bundle.issuedAt).toISOString(), new Date(bundle.expiresAt).toISOString());
      db.prepare('INSERT INTO t3router_links VALUES (?,?) ON CONFLICT(environment_id) DO UPDATE SET secret_name=excluded.secret_name').run(env.id, secretName);
      if (previousLink !== undefined && previousLink.secret_name !== secretName) cleanup.push(path.join(secretsDir, `${previousLink.secret_name}.bin`));
    }
    db.prepare('INSERT INTO t3router_state VALUES (1,?,?,?) ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,policy_hash=excluded.policy_hash,issued_at=excluded.issued_at').run(policy.revision, bundle.policyHash, bundle.issuedAt);
    return { incoming: incoming.length, outgoing: bundle.outgoing.length };
  });
  // Delete only after commit. A crash can leave unused files, never a row naming a missing token.
  for (const file of cleanup) fs.rmSync(file, { force: true });
  return result;
}
