/** Optional acceptance against the real pinned T3 runtime, using only disposable homes. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { createHmac } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { apply, issue, readPrivate } from '../src/provision.mjs';

/** Reserve an ephemeral loopback port; no fixed fleet port is used by this test. */
async function availablePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

/** Parse both JSON and streamable-HTTP SSE replies without logging bearer material. */
function rpcResult(text) {
  const data = text.split('\n').find(line => line.startsWith('data: '));
  return JSON.parse(data ? data.slice(6) : text);
}

test('real v0.1.6 accepts presigned peers, native CLI resolves installed links, and revocation blocks old tokens',
  { skip: !process.env.T3ROUTER_T3_BIN, timeout: 120_000 }, async t => {
    const binary = process.env.T3ROUTER_T3_BIN;
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 't3router-live-'));
    let server;
    t.after(async () => {
      await stop();
      fs.rmSync(root, { recursive: true, force: true });
    });
    const port = await availablePort();
    const url = `http://127.0.0.1:${port}`;
    const keys = path.join(root, 'keys');
    fs.mkdirSync(keys, { mode: 0o700 });
    const environments = {};
    for (const name of ['source', 'other', 'destination']) {
      const base = path.join(root, name);
      // Only auth metadata is returned, and it is not printed by the test harness.
      const init = spawnSync(binary, ['auth', 'session', 'list', '--base-dir', base, '--json'], { encoding: 'utf8', timeout: 30_000 });
      assert.equal(init.status, 0, 'Pinned T3 must initialize a disposable home');
      const state = path.join(base, 'userdata');
      const id = fs.readFileSync(path.join(state, 'environment-id'), 'utf8').trim();
      fs.copyFileSync(path.join(state, 'secrets/server-signing-key.bin'), path.join(keys, `${name}.bin`));
      fs.chmodSync(path.join(keys, `${name}.bin`), 0o600);
      fs.writeFileSync(path.join(state, 'settings.json'), JSON.stringify({ linkedEnvironmentsEnabled: true }), { mode: 0o600 });
      // A non-serving auth CLI may not create the server lifetime lock yet.
      fs.closeSync(fs.openSync(path.join(state, 'server-owner.sqlite'), 'a', 0o600));
      environments[name] = { id, label: name, urls: [url] };
    }
    const policy = { format: 1, t3Version: '0.1.6', revision: 1, environments,
      links: [
        { from: 'source', to: 'destination', access: 'approval-required', generation: 1 },
        { from: 'other', to: 'destination', access: 'approval-required', generation: 1 },
      ] };
    const issuedAt = Date.now();
    const output = path.join(root, 'bundles');
    issue(policy, keys, output, { now: issuedAt });
    const bundles = {};
    for (const name of Object.keys(environments)) {
      bundles[name] = JSON.parse(readPrivate(path.join(output, `${name}.json`)));
      try { apply(policy, name, bundles[name], path.join(root, name, 'userdata'), { t3Version: '0.1.6' }); }
      catch (error) {
        const db = new DatabaseSync(path.join(root, name, 'userdata/statev2.sqlite'));
        try {
          // Schema metadata only, from a disposable home; never print rows or credentials.
          t.diagnostic(JSON.stringify({ authColumns: db.prepare('PRAGMA table_info(auth_sessions)').all().map(row => row.name),
            peerColumns: db.prepare('PRAGMA table_info(peer_environment_links)').all().map(row => row.name),
            head: db.prepare('SELECT MAX(migration_id) AS head FROM effect_sql_migrations').get() }));
        } finally { db.close(); }
        throw error;
      }
    }
    /** Start only the disposable destination; capture no startup pairing URLs in test output. */
    async function start() {
      server = spawn(binary, ['serve', '--base-dir', path.join(root, 'destination'), '--host', '127.0.0.1', '--port', String(port)], { stdio: 'ignore', detached: true });
      server.on('error', () => {});
      for (let i = 0; i < 200; i++) {
        assert.equal(server.exitCode, null, 'Disposable server exited during startup');
        try {
          const response = await fetch(`${url}/mcp`, { signal: AbortSignal.timeout(1000) });
          await response.body?.cancel();
          if (response.status !== 503) return;
        } catch { /* The new listener or its MCP service is not ready yet. */ }
        await setTimeout(50);
      }
      throw new Error('Disposable server did not start');
    }
    /** Stop only the test-owned process group, never an existing T3 or build process. */
    async function stop() {
      if (!server || server.exitCode !== null) return;
      const exited = once(server, 'exit');
      process.kill(-server.pid, 'SIGTERM');
      await exited;
    }
    /** Initialize the actual /mcp endpoint with a pre-signed peer credential. */
    async function initialize(token) {
      return fetch(`${url}/mcp`, { method: 'POST', headers: {
        authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream',
      }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
        protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't3router-acceptance', version: '0.1.0' },
      } }), signal: AbortSignal.timeout(10_000) });
    }
    /** Call native tools without launching any model/provider turn. */
    async function callTool(token, session, name, args) {
      const response = await fetch(`${url}/mcp`, { method: 'POST', headers: {
        authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream',
        ...(session ? { 'mcp-session-id': session } : {}),
      }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name, arguments: args } }), signal: AbortSignal.timeout(10_000) });
      assert.equal(response.status, 200);
      return rpcResult(await response.text());
    }
    /** Decode a successful MCP tool result; error content is never mistaken for success. */
    function toolValue(reply) {
      assert.equal(reply.error, undefined);
      assert.notEqual(reply.result?.isError, true,
        String(reply.result?.content?.find(item => item.type === 'text')?.text ?? 'Tool failed').replace(/[A-Za-z0-9_-]{60,}/g, '[redacted]'));
      return reply.result.structuredContent ?? JSON.parse(reply.result.content.find(item => item.type === 'text').text);
    }
    await start();
    const token = bundles.source.outgoing[0].token;
    const accepted = await initialize(token);
    assert.equal(accepted.status, 200, 'Unmodified T3 must accept the pre-signed registered peer');
    const body = rpcResult(await accepted.text());
    const brokenSignature = await initialize(`${token.split('.')[0]}.${'A'.repeat(43)}`);
    assert.ok([401, 403].includes(brokenSignature.status), 'Invalid signature must be rejected');
    await brokenSignature.body?.cancel();
    const unregistered = JSON.parse(Buffer.from(token.split('.')[0], 'base64url'));
    unregistered.sid = '99999999-9999-4999-8999-999999999999';
    const unregisteredBody = Buffer.from(JSON.stringify(unregistered)).toString('base64url');
    const unregisteredSignature = createHmac('sha256', Buffer.from(bundles.destination.signingKey, 'base64')).update(unregisteredBody).digest('base64url');
    const unknownSession = await initialize(`${unregisteredBody}.${unregisteredSignature}`);
    assert.ok([401, 403].includes(unknownSession.status), 'Valid signature without a destination row must be rejected');
    await unknownSession.body?.cancel();
    assert.equal(body.error, undefined);
    assert.ok(body.result.serverInfo);
    const session = accepted.headers.get('mcp-session-id');
    const audience = await fetch(`${url}/api/auth/session`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(audience.status, 200);
    assert.equal((await audience.json()).authenticated, false, 'The auth-status endpoint must report the MCP token unauthenticated');
    const ticket = await fetch(`${url}/api/auth/websocket-ticket`, { method: 'POST', headers: { authorization: `Bearer ${token}` } });
    assert.equal(ticket.status, 401, 'A peer token must not mint a general WebSocket credential');
    await ticket.body?.cancel();
    // Idle threads need model metadata even though omitting messages starts no provider turn.
    const modelSelection = { instanceId: 'codex', model: 'idle-test-no-provider' };
    const own = toolValue(await callTool(token, session, 't3_thread_launch', { scratch: true, title: 'Idle source-owned test thread', modelSelection }));
    assert.equal(own.runId, null, 'An idle launch must not start a provider');
    const otherToken = bundles.other.outgoing[0].token;
    const otherInit = await initialize(otherToken);
    assert.equal(otherInit.status, 200);
    await otherInit.body?.cancel();
    const foreign = toolValue(await callTool(otherToken, otherInit.headers.get('mcp-session-id'), 't3_thread_launch', { scratch: true, title: 'Idle other-owned test thread', modelSelection }));
    assert.equal(foreign.runId, null);
    toolValue(await callTool(token, session, 't3_thread_update', { threadId: own.threadId, action: 'rename', title: 'Own rename permitted' }));
    const forbidden = await callTool(token, session, 't3_thread_update', { threadId: foreign.threadId, action: 'rename', title: 'Must never be applied' });
    assert.match(JSON.stringify(forbidden), /only threads that link started/, 'The real signed peer fence must reject another source principal');
    const listing = spawnSync(binary, ['environment', 'list', '--base-dir', path.join(root, 'source'), '--json'], { encoding: 'utf8', timeout: 30_000 });
    assert.equal(listing.status, 0);
    const links = JSON.parse(listing.stdout);
    assert.equal(links.length, 1);
    assert.equal(links[0].environmentId, environments.destination.id);
    assert.equal(links[0].status, 'reachable');
    await stop();
    const renewedDir = path.join(root, 'renewed');
    issue(policy, keys, renewedDir);
    const renewed = {};
    for (const name of Object.keys(environments)) {
      renewed[name] = JSON.parse(readPrivate(path.join(renewedDir, `${name}.json`)));
      apply(policy, name, renewed[name], path.join(root, name, 'userdata'), { t3Version: '0.1.6' });
    }
    await start();
    const renewedToken = renewed.source.outgoing[0].token;
    const renewedInit = await initialize(renewedToken);
    assert.equal(renewedInit.status, 200);
    await renewedInit.body?.cancel();
    toolValue(await callTool(renewedToken, renewedInit.headers.get('mcp-session-id'), 't3_thread_update', { threadId: own.threadId, action: 'rename', title: 'Renewed credential retains ownership' }));
    const stillForbidden = await callTool(renewedToken, renewedInit.headers.get('mcp-session-id'), 't3_thread_update', { threadId: foreign.threadId, action: 'rename', title: 'Still forbidden after renewal' });
    assert.match(JSON.stringify(stillForbidden), /only threads that link started/);
    await stop();
    const removed = structuredClone(policy);
    removed.revision++;
    removed.links = [];
    const next = path.join(root, 'removed');
    issue(removed, keys, next);
    apply(removed, 'destination', JSON.parse(readPrivate(path.join(next, 'destination.json'))), path.join(root, 'destination/userdata'), { t3Version: '0.1.6' });
    await start();
    const rejected = await initialize(token);
    assert.ok([401, 403].includes(rejected.status), 'Revoked pre-signed credential must stop authenticating');
  });
