#!/usr/bin/env node
/** Small CLI: all secret inputs and outputs are file paths, never command-line values. */
import * as fs from 'node:fs';
import { parseArgs } from 'node:util';
import { apply, issue, keygen, ProvisionError, readPrivate, validatePolicy } from './provision.mjs';

process.umask(0o077);

/** Require a named path or identifier; do not echo supplied data in errors. */
function required(values, key) {
  if (typeof values[key] !== 'string' || values[key].length === 0) throw new Error(`Missing --${key}`);
  return values[key];
}

try {
  const command = process.argv[2];
  const schemas = {
    keygen: ['output'],
    issue: ['policy', 'keys-dir', 'output-dir', 'ttl-hours'],
    apply: ['policy', 'environment', 'bundle-file', 'state-dir', 't3-version'],
    validate: ['policy'],
  };
  if (!Object.hasOwn(schemas, command)) throw new Error('Use: t3router keygen|issue|apply|validate (see README)');
  // Parse per command: an ignored flag must never disguise a missing safety condition.
  const { values } = parseArgs({ args: process.argv.slice(3), strict: true,
    options: Object.fromEntries(schemas[command].map(name => [name, { type: 'string' }])) });
  if (command === 'keygen') {
    keygen(required(values, 'output'));
    process.stdout.write('Created private signing-key file.\n');
  } else {
    const policy = validatePolicy(JSON.parse(fs.readFileSync(required(values, 'policy'), 'utf8')));
    let result;
    if (command === 'issue') {
      result = issue(policy, required(values, 'keys-dir'), required(values, 'output-dir'),
        values['ttl-hours'] === undefined ? {} : { ttlMs: Number(values['ttl-hours']) * 3600_000 });
    } else if (command === 'apply') {
      const bundle = JSON.parse(readPrivate(required(values, 'bundle-file')).toString('utf8'));
      result = apply(policy, required(values, 'environment'), bundle, required(values, 'state-dir'),
        { t3Version: required(values, 't3-version') });
    } else result = { valid: true };
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }
} catch (error) {
  // Parser, JSON and SQLite exceptions may embed untrusted input, SQL parameters or paths.
  // Only our constant diagnostics are safe to log; never dump arbitrary causes or stacks.
  const message = error instanceof ProvisionError ? error.message : 'Refused; check input files and syntax (see README troubleshooting)';
  process.stderr.write(`t3router: ${message}.\n`);
  process.exitCode = 1;
}
