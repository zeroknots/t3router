/** Prove security regressions are detected using temporary source copies, never the working tree. */
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const source = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mutations = [
  { name: 'missing destination revocation', from: 'if (!incomingIds.has(row.session_id))', to: 'if (false)', test: 'removal revokes' },
  { name: 'revoked credential resurrection', from: "requireThat(row === undefined || row.revoked_at === null, 'Revoked credential cannot be restored; increase its generation');", to: '', test: 'manual revocation' },
  { name: 'missing signed peer fence', from: 'plk: 1, iat:', to: 'iat:', test: 'exact directed policy' },
  { name: 'missing server ownership lock', from: "lock.exec('PRAGMA busy_timeout=0; BEGIN EXCLUSIVE');", to: "lock.exec('PRAGMA busy_timeout=0');", test: 'running-server lock' },
  { name: 'nondurable secret filename', from: 'syncDirectory(path.dirname(file));', to: '', test: 'secret publication', file: 'durability.test.mjs' },
];
for (const mutation of mutations) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 't3router-break-'));
  try {
    for (const dir of ['src', 'test']) fs.cpSync(path.join(source, dir), path.join(root, dir), { recursive: true });
    const file = path.join(root, 'src/provision.mjs');
    const original = fs.readFileSync(file, 'utf8');
    assert.equal(original.split(mutation.from).length, 2, 'Mutation must target exactly one implementation site');
    fs.writeFileSync(file, original.replace(mutation.from, mutation.to));
    const run = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--test', `--test-name-pattern=${mutation.test}`, path.join(root, 'test', mutation.file ?? 'provision.test.mjs')], { encoding: 'utf8', timeout: 30_000 });
    assert.equal(run.error, undefined);
    assert.equal(run.status, 1, `Security test must reject: ${mutation.name}`);
    assert.match(run.stdout, /fail 1/, 'A failed assertion, not an import/syntax failure, must kill the mutation');
    process.stdout.write(`Rejected mutation: ${mutation.name}\n`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
