# t3router

Provision native T3 Code environment links from one fleet policy, without
interactive pairwise enrollment or a routing daemon. T3 keeps its own MCP,
remote-task routing, completion delivery, permission ceilings and link fences.

**Supported: T3 v0.1.6 only. Experimental; review before activating.**

This is a **version-pinned offline state adapter**, not an upstream-supported
import API. Stock T3 cannot import a pre-signed peer through its CLI. The adapter
writes the existing T3 schema and adds three small tracking tables. It refuses
unknown schemas and never migrates T3. An upstream issuance/import API should
replace this adapter when available.

## Security contract

- Each environment has its own 32-byte HMAC signing key. Sharing keys is refused.
- The trusted issuer can read all signing keys. Targets receive only their own
  key and their explicitly allowed outgoing bearer tokens. Never give a source
  its destination's signing key. CI receives **no real keys or bundles**.
- SOPS encrypts keys/bundles at rest. Decryption is a runtime operation; never put
  plaintext in Git, Nix strings, derivations, environment variables, arguments or logs.
- Every directed source/destination/access/generation has a distinct session ID.
  Renewal preserves that ID, so existing remote threads retain their owner.
- Removing a link revokes its destination session. Source deletion alone is not
  revocation. Manually revoked or deleted destination sessions cannot be restored
  by reconciliation: explicitly increase the link's `generation` to reauthorize.
- Access changes create a new session and revoke the old one. This prevents an
  old token's signed permission ceiling from surviving a downgrade. **Existing
  tasks belong to the old session; changing access/generation does not migrate them.**
- The adapter obtains T3's exclusive `server-owner.sqlite` lock. It refuses a
  running server; it never stops one or deletes/replaces the lock. Apply as the
  environment's Unix account, not as a privileged workaround.
- Existing environment IDs and signing keys are never replaced. Manual sessions
  remain untouched. Conflicting manually created outgoing links cause refusal.

These are **native T3 permissions**, not a new sandbox. Below full-access, T3
fences writes by the originating session, but **does not fence reads the same
way**. A remote task executes as the destination's configured Unix user.
Tailscale controls reachability, not the source Unix account on a shared node.
Use separate destination accounts/hosts for stronger isolation. Full-access is
unfenced and includes administrative scopes; it must be an explicit choice.

## Policy

A public inventory contains no secret material. `examples/policy.json` is a
synthetic three-environment example, not an authorization for anyone's fleet.
Use each environment's existing `userdata/environment-id`. URLs are HTTPS
origins; HTTP is allowed only on literal loopback/localhost for local use.
Declare only the directed links you want. Everything else is absent by default.

```json
{
  "format": 1,
  "t3Version": "0.1.6",
  "revision": 1,
  "environments": {
    "laptop": {
      "id": "11111111-1111-4111-8111-111111111111",
      "label": "laptop",
      "urls": ["http://127.0.0.1:3773"]
    },
    "worker": {
      "id": "22222222-2222-4222-8222-222222222222",
      "label": "worker",
      "urls": ["https://worker.example.ts.net"]
    }
  },
  "links": [
    {"from": "laptop", "to": "worker", "access": "approval-required", "generation": 1}
  ]
}
```

Increase `revision` whenever any policy field changes. Never roll it back to
regrant removed access. Keep a link's `generation` unchanged during ordinary
renewal. Increase it for explicit reauthorization after revocation or deletion.
Previously issued permissions are not erased by editing the source policy:
**apply the new declaration to the destinations to revoke their old sessions**.

## Provision and renew

Prerequisites: Node 24.10+, initialized T3 v0.1.6 homes, verified environment IDs,
reviewed ACLs, and an authorized SOPS editing identity. Use temporary private
storage on a trusted issuer; it holds fleet-wide signing authority.

1. Preserve existing keys. Securely enroll each environment's raw
   `userdata/secrets/server-signing-key.bin` into SOPS under its own recipient
   rule. Do not print or replace it. A target may decrypt only its own bundle;
   the authorized issuer/person recovery identities may decrypt its key.
   For a genuinely new key, `t3router keygen --output /private/keys/worker.bin`
   creates 32 raw bytes exclusively. It is **not** a rotation command.
2. Decrypt enrolled keys to private runtime files named `<environment>.bin`
   in `/private/keys`. With `umask 077`, issue all bundles in one operation:

   ```sh
   t3router validate --policy /path/to/policy.json
   t3router issue --policy /path/to/policy.json \
     --keys-dir /private/keys --output-dir /private/new-bundles
   ```

   The output directory must not exist. Each `<environment>.json` contains
   that environment's signing key and outgoing bearer tokens. These are
   **plaintext secrets** until encrypted. Do not inspect them in terminal output.
   Credentials last at most 30 days; `--ttl-hours` can shorten that period.
3. Encrypt each bundle immediately for **its destination host and authorized
   recovery people only**. For sops-nix `format = "binary"`, encrypt the entire
   original JSON as binary data:

   ```sh
   sops --encrypt --input-type binary --output-type binary \
     --filename-override secrets/t3-fleet/worker.json \
     /private/new-bundles/worker.json > secrets/t3-fleet/worker.json
   ```

   Configure the exact recipient rule first. The ciphertext contains a binary
   payload; do not make it a public unencrypted JSON document.
4. Review and deploy the public policy and encrypted bundles. Arrange an
   explicit maintenance window before stopping an existing T3 environment.
   Applying requires the server/desktop app to be closed; do not interrupt
   active work. Run as that environment's account:

   ```sh
   t3router apply --policy /path/to/policy.json --environment worker \
     --bundle-file /run/secrets/t3-fleet-worker \
     --state-dir "$HOME/.t3/userdata" --t3-version 0.1.6
   ```

   Apply destinations before relying on new source links. For removals, prioritize
   destination revocation. Each home is transactional; fleet rollout is **not**
   an atomic transaction. Do not claim revocation until the target applied it.
5. Enable T3's `linkedEnvironmentsEnabled` public setting on both ends, then
   start T3 normally. Check `t3 environment list --json`, exercise an allowed
   operation, and verify a forbidden operation. Delete temporary plaintext keys
   and bundles from the trusted issuer when finished. Encrypted repository
   history is not a revocation mechanism.

Repeat issuance before expiry, using the same policy and generations unless
permissions change. This is one batch operation, not interactive per-edge
pairing. **There is no automatic renewal timer in this release.** New ciphertext
must reach each host and be applied during its next safe restart. A changed
SOPS file does not by itself restart a user service.

### Retire an environment

Retirement is a two-stage operation. First keep the destination in the inventory,
remove every incident link, increase the revision, issue bundles and apply that
policy on the destination. Verify its old incoming credentials no longer work.
Only then remove it from the inventory in another revision. Removing an entry
immediately produces no bundle for that retired destination and **does not
revoke its existing sessions**. If the destination is unreachable, treat its
credentials as still valid until expiry or independently verified revocation.

## Nix

```sh
nix run github:zeroknots/t3router/<reviewed-commit> -- validate --policy policy.json
```

The flake exports `packages.<system>.t3router` (also `default`) for x86_64-linux
and aarch64-linux. Pin the reviewed revision in the consuming flake. No secrets
are needed for builds or tests. The Nix fleet integration owns sops-nix
recipient rules, public policy generation and the pre-start apply hook.

NixOS rollback restores configuration, not mutable auth state. The importer
rejects old revisions and older bundles. Restore access with a new reviewed
revision/generation, never by restoring an old database over revocation records.

## Tests and compatibility

```sh
npm run check
npm test
npm run test:mutation
T3ROUTER_T3_BIN=/absolute/path/to/pinned/t3 node --test test/live.test.mjs
```

The default suite uses private disposable homes, random dummy keys and SQL
fixtures. Mutation checks deliberately remove revocation, resurrection protection,
the signed fence, the server lock and directory durability; each must fail a test.
The optional real-runtime test initializes three fresh T3 homes and starts only
its own loopback server. It verifies native MCP acceptance/discovery, rejects
unregistered sessions and non-MCP audiences, and creates idle threads to check
cross-source write fencing. Renewal preserves the original thread owner; removal
revokes old tokens after a safe test-owned restart. It never reads production
keys, mutates production homes, or starts provider turns. It is skipped unless
the binary path is supplied.

Compatibility references: [upstream v0.1.6](https://github.com/pingdotgg/t3code/tree/2359643cffa6ba9ee84d6f2694b935de54a8013e),
`SessionStore.ts`, `EnvironmentAuth.ts`, `AuthSessions.ts`, `PeerLinks.ts`,
`ServerSecretStore.ts`, `serverOwnership.ts`, migrations 031/041/070/071,
and migration head 76. Re-test against the actual runtime before updating this
pin; a matching version string alone is not a compatibility proof.

### Troubleshooting

Safe policy/permission diagnostics are printed without secret values. JSON,
SQLite and filesystem exceptions are deliberately not dumped because their
messages can contain input. Check:

- policy syntax, fields, explicit version, UUIDs, URL origins and revision;
- private secret file/directory ownership and mode; no symlinked secrets directory;
- actual pinned T3 version and fully initialized migration head 76;
- local environment ID and unchanged signing key;
- bundle lifetime, clock, policy hash and monotonic issuance;
- a stopped server/desktop app, no conflicting manual link, and no revoked ID.

On failure, the SQL transaction rolls back. Files are written before commit so
no link names an unpublished token. A crash may leave private unreferenced
secret files; it does not grant additional incoming sessions. Do not manually
unlink the ownership lock or expose a key to bypass a refusal.
