/** The filename must be durable, not just the file contents, before a referencing SQL commit. */
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import { writePrivate } from '../src/provision.mjs';

test('secret publication syncs both the file and the containing directory', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 't3router-durability-'));
  const synced = [];
  const original = fs.fsyncSync;
  const spy = mock.method(fs, 'fsyncSync', fd => {
    synced.push(fs.fstatSync(fd).isDirectory() ? 'directory' : 'file');
    original(fd);
  });
  syncBuiltinESMExports();
  try {
    writePrivate(path.join(root, 'dummy-secret'), 'dummy-value');
    assert.deepEqual(synced, ['file', 'directory'], 'File data without a durable directory entry is not a durable publication');
  } finally {
    spy.mock.restore();
    syncBuiltinESMExports();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
