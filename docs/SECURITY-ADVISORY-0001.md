# SECURITY-ADVISORY-0001 — Private key exposure in encryption-helper 0.0.1

| Field | Value |
| ----- | ----- |
| Identifier | `SECURITY-ADVISORY-0001` |
| Affected versions | `<= 0.0.1` (all commits up to and including `6bfd51d`) |
| Fixed in | `0.0.2` |
| Severity | **High** |
| Impact | Disclosure of RSA private key material |
| Action required | **Rotate every key pair generated with an affected version.** |

## Summary

Version 0.0.1 of `encryption-helper` generated RSA private keys and then
exposed them in three separate ways: it wrote the private key file with
world-readable permissions, printed the full private key to standard output,
and emitted it again through the debug log. Any private key produced by an
affected version must be considered compromised.

## Details

### 1. Private key written world-readable (0644)

`encryption_helper/main.py` wrote the key with a plain `open(path, "wb")`, which
creates files using the process umask — typically `0644`. Observed on an
affected version:

```
-rw-r--r--  1 user user  1704  keys/pem/private-key.pem
-rw-r--r--  1 user user   451  keys/pem/public-key.pem
```

Any local account on the machine could read the private key. On shared
workstations, build agents, and multi-tenant hosts this is a direct compromise.

### 2. Private key printed to standard output

The tool printed the complete PEM-encoded private key to stdout on every run.
This places the secret in terminal scrollback, `script`/`tee` captures, CI job
logs (which are public for public repositories), container stdout collectors,
and any downstream log-shipping pipeline.

### 3. Private key written to the debug log

The same material was passed to `logger.debug()`, so any consumer running the
package at `DEBUG` level recorded the private key into its own log sinks.

### 4. Contributing factors

- Keys were stored unencrypted (`NoEncryption()`), with no supported way to set
  a passphrase.
- Re-running the tool silently overwrote an existing `private-key.pem` with no
  prompt, backup, or error, so a key could be destroyed as easily as leaked.

## Impact

An attacker with local read access to the filesystem, or with access to any log
or terminal capture from a key generation run, obtains the private key in full.
They can then decrypt anything encrypted to the corresponding public key and
impersonate the key holder in any protocol where it is trusted.

## Affected users

Anyone who ran `encryption-helper`, `python -m encryption_helper`, or called
`generate_rsa_key()` from an affected version, and retained or deployed the
resulting key.

## Remediation

1. **Upgrade** to `0.0.2` or later.
2. **Rotate.** Generate a fresh key pair and replace the old one everywhere it
   is trusted — certificates, `authorized_keys`, JWT verification, service
   configuration, partner integrations.
3. **Revoke** any certificate issued against an affected key.
4. **Re-encrypt** any data that was encrypted to an affected public key.
5. **Purge** the old key material from logs, CI artefacts, and backups where
   your retention policy permits.
6. **Audit** for use of the compromised key between generation and rotation.

Deleting the key file alone is not sufficient — assume any copy that reached a
log or another user's view is already retained elsewhere.

## Fixes in 0.0.2

- Private keys are created with `O_EXCL` at mode `0600`, and the containing
  directory at `0700`.
- Private key material is never printed or logged. The CLI reports the file
  path and a SHA-256 fingerprint instead.
- Passphrase protection is supported via `--passphrase-env` and
  `--passphrase-file`.
- An existing key file is an error; replacing one requires an explicit
  `--force` and produces a timestamped `0600` backup.

## Credit

Identified during an internal security review of the repository.

## References

- `docs/IMPLEMENTATION_PLAN.md` — findings C2, C3, C4, C6
