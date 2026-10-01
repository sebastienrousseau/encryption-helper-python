<!-- SPDX-License-Identifier: Apache-2.0 -->

# Container sandbox

A portable, throwaway container in which to run the `encryption-helper`
command-line interface. The host supplies a container engine and one directory;
it does not need Python, the `cryptography` wheel, or this package.

The sandbox is intended for two situations:

- An operator must perform a key or encryption operation on a workstation or
  jump host where installing software is not permitted, or where an
  uncontrolled Python environment is itself a finding.
- A reviewer wants to exercise the tool, and demonstrate what it does and does
  not touch, without trusting it with an installed footprint.

**Files:** [`Containerfile`](../Containerfile) defines the image,
[`.dockerignore`](../.dockerignore) constrains the build context, and
[`scripts/sandbox.sh`](../scripts/sandbox.sh) applies the run-time hardening
described below.

---

## 1. Quick start

```bash
# Build on first use and report the supported algorithms.
./scripts/sandbox.sh --json capabilities

# Generate a passphrase-protected Ed25519 key pair into ./secrets.
read -rsp 'Passphrase: ' EH_PASS && export EH_PASS
./scripts/sandbox.sh keygen --algorithm ed25519 --out-dir ./secrets \
  --name service --passphrase-env EH_PASS
```

The files appear in `./secrets` on the host, owned by the invoking user, with
the private key at mode 0600.

The wrapper selects Podman where both engines are present, reports which it
chose on stderr, and builds the image if it is not already present. Force a
rebuild with `--rebuild` and override the choice with
`--engine docker`.

## 2. Security properties

### 2.1 What the sandbox provides

| Flag | Prevents |
| --- | --- |
| `--network=none` | Any network access from the tool. The package makes no network calls; removing the network namespace turns that from a documented intention into an enforced property, so key material cannot be exfiltrated and no code can be fetched at run time. |
| `--read-only` | Writes anywhere outside the bind mount and the `/tmp` tmpfs. A modified interpreter, an injected module or a cached artefact cannot persist in the image. |
| `--tmpfs=/tmp:...,noexec,nosuid,nodev` | Execution of anything written to the scratch area, use of setuid bits there, and device nodes. The tmpfs is discarded when the container exits. |
| `--cap-drop=ALL` | Every Linux capability, including `CAP_DAC_OVERRIDE`. Without `CAP_DAC_OVERRIDE` the 0600 permissions this tool sets on private keys are enforced against the process itself, not merely advisory. |
| `--security-opt=no-new-privileges` | Privilege gain through a setuid or setgid binary inherited from the base image, for the process and anything it spawns. |
| `USER 10001:10001` (image) | Execution as root. Owner-only key permissions are meaningless under uid 0, which bypasses the bits it has just set, and bind-mounted output would be written back to the host as root-owned. |
| `--userns=keep-id` (Podman) / `--user` (Docker) | Ownership mismatch in the bind mount. Files created in `/work` are owned by the invoking host user rather than by root or by a container-local uid. |
| `--rm` | Accumulation of stopped containers holding a filesystem layer that may contain plaintext or key material. |
| Bind mount at `/work` only | Visibility of the rest of the host filesystem. The tool can read and write exactly one directory, which the operator names. |
| Multi-stage build | The source tree, the PEP 517 build backend and pip's build scratch space reaching the shipped image. What is installed is the wheel and its dependency closure. |
| `.dockerignore` | Key material, caches and local virtual environments entering the build context, where they could be captured in a layer. |

### 2.2 What the sandbox does not provide

The sandbox narrows what the tool can reach. It is not a trust boundary
against the host, and it changes nothing about the cryptography performed.

- **It does not protect key material from the host.** `/work` is an ordinary
  host directory. Any process running as the same user, and any process running
  as root, can read the private keys written there. The sandbox constrains the
  tool, not the operator's workstation.
- **It is not a substitute for a hardware security module or a key management
  service.** Private keys are files on disk, protected by filesystem
  permissions and, where a passphrase is supplied, by passphrase-based
  encryption at rest.
- **It does not harden passphrase handling on the host.** `--passphrase-env`
  names an environment variable; the value is readable through `/proc` by the
  same user, and by root, on both sides of the boundary. The wrapper forwards
  the variable by name so the value never appears in the engine's argument
  list, which is the most it can do.
- **It is not a hypervisor boundary.** A container shares the host kernel. A
  kernel vulnerability, or a side channel in shared hardware, is not mitigated
  here. Where that matters, run the sandbox inside a virtual machine.
- **The build is not offline.** `--network=none` applies at run time. Building
  the image fetches the base image and the dependency wheels, and that step
  should be performed on a host and against a registry that the organisation
  trusts.
- **The base image is not yet pinned.** The `Containerfile` references
  `python:3.12-slim` by tag and carries a `TODO` with the exact command to
  obtain the digest. Until it is pinned, the build is not reproducible and a
  provenance attestation over it is of limited value. Pin the digest before
  promoting the image to a controlled registry.
- **Rootful Docker still involves a root daemon.** With Docker, the client
  hands work to a daemon running as root, and membership of the `docker` group
  is equivalent to root on the host. The container process is unprivileged, but
  the path to it is not. Podman rootless, or rootless Docker, avoids this.
- **No seccomp or SELinux policy is authored here.** The engine's default
  seccomp profile applies. On an SELinux host the bind mount may need a label
  option; see section 5.
- **No audit trail, no key escrow, no telemetry.** The tool writes to stdout,
  stderr and the files it is told to write. Nothing is reported anywhere, by
  design.
- **It does not make a weak choice safe.** `--no-passphrase` still stores an
  unencrypted private key, and a 2048-bit RSA key is still a 2048-bit RSA key.
  Use `encryption-helper scan` and `encryption-helper capabilities` to assess
  the material and the algorithms.

## 3. Running each operation

All commands below are run through the wrapper from the directory holding the
data. Paths are relative to that directory, which is mounted at `/work`.

Global options — `--json`, `-q`/`--quiet`, `-v`/`--verbose`, `--log-level`,
`--version` — precede the command. Input and output are selected with `--in`
and `--out`, each of which accepts `-` for stdin or stdout.

### 3.1 Inventory and capability reporting

```bash
# Algorithms this build supports, and their status against NIST IR 8547.
./scripts/sandbox.sh --json capabilities

# Inventory the current tree for keys, certificates and encrypted files.
./scripts/sandbox.sh scan .

# Gate a pipeline on the result. Exits non-zero if anything needs migration
# or manual review.
./scripts/sandbox.sh --json scan . --fail-on-finding
```

### 3.2 Key generation

```bash
# RSA, the default algorithm, with an explicit modulus size.
./scripts/sandbox.sh keygen --algorithm rsa --key-size 3072 \
  --out-dir ./secrets --name service --passphrase-env EH_PASS

# Ed25519 for signing.
./scripts/sandbox.sh keygen --algorithm ed25519 --out-dir ./secrets \
  --name service --passphrase-env EH_PASS

# Post-quantum: ML-KEM for encryption, ML-DSA for signing.
./scripts/sandbox.sh keygen --algorithm mlkem --level 768 \
  --out-dir ./secrets --name pq-enc --passphrase-env EH_PASS
./scripts/sandbox.sh keygen --algorithm mldsa --level 65 \
  --out-dir ./secrets --name pq-sig --passphrase-env EH_PASS

# ECDSA on an explicit curve, in OpenSSH encoding.
./scripts/sandbox.sh keygen --algorithm ecdsa --curve p384 \
  --format openssh --out-dir ./secrets --name service \
  --passphrase-env EH_PASS

# Unprotected, for a test fixture or an ephemeral CI key only.
./scripts/sandbox.sh keygen --algorithm ed25519 --no-passphrase \
  --out-dir ./secrets --name throwaway

# Replace an existing pair. The previous files are backed up to timestamped
# siblings first.
./scripts/sandbox.sh keygen --algorithm ed25519 --out-dir ./secrets \
  --name service --force --passphrase-env EH_PASS
```

`keygen` writes a private key with mode 0600 and a public key beside it, into
`--out-dir`, which defaults to the working directory. The names follow
`--format`: `<name>.pem` and `<name>.pub.pem` for PEM, `<name>.der` and
`<name>.pub.der` for DER, and `<name>` and `<name>.pub` for OpenSSH. Add
`--show-public` to write the public key to stdout as well; the private key is
never printed.

A passphrase may also be read from a file with `--passphrase-file PATH`. The
file must be inside `/work` to be visible to the container.

### 3.3 Encryption and decryption

```bash
./scripts/sandbox.sh encrypt --public-key secrets/service.pub.pem \
  --in report.csv --out report.csv.enc

./scripts/sandbox.sh decrypt --private-key secrets/service.pem \
  --in report.csv.enc --out report.csv --passphrase-env EH_PASS

# Streaming through the sandbox. Both commands default to stdin and stdout.
cat report.csv \
  | ./scripts/sandbox.sh encrypt --public-key secrets/service.pub.pem \
  > report.csv.enc

# Progress on stderr for a large file, with a larger segment.
./scripts/sandbox.sh encrypt --public-key secrets/service.pub.pem \
  --in archive.tar --out archive.tar.enc --progress --segment-size 1048576

# Overwrite an existing output, backing it up first.
./scripts/sandbox.sh encrypt --public-key secrets/service.pub.pem \
  --in report.csv --out report.csv.enc --force
```

### 3.4 Signing and verification

```bash
./scripts/sandbox.sh sign --private-key secrets/service.pem \
  --in report.csv --out report.csv.sig --passphrase-env EH_PASS

./scripts/sandbox.sh verify --public-key secrets/service.pub.pem \
  --signature report.csv.sig --in report.csv
```

`verify` exits 4 if the signature does not verify. The full set is 0 success,
1 error, 2 usage, 3 key already exists, 4 cryptographic failure.

### 3.5 Inspection, fingerprinting and conversion

```bash
# Report which algorithms protect a container, reading only its header. No
# private key is required and no plaintext is recovered.
./scripts/sandbox.sh --json inspect --in report.csv.enc

# SHA-256 fingerprint of a public key, in the form `ssh-keygen -lf` prints.
./scripts/sandbox.sh fingerprint secrets/service.pub.pem

# Convert a public key to OpenSSH encoding on stdout.
./scripts/sandbox.sh convert --to openssh --in secrets/service.pub.pem --out -

# Convert a private key to DER. The output is written owner-only and
# unencrypted, so direct it carefully.
./scripts/sandbox.sh convert --to der --private \
  --in secrets/service.pem --out secrets/service.der \
  --passphrase-env EH_PASS
```

### 3.6 Interactive passphrase prompts

Where no `--passphrase-env` or `--passphrase-file` is given, and the operation
needs a passphrase, the tool prompts on the terminal. The wrapper allocates a
pseudo-terminal only when both stdin and stdout are attached to one, so the
prompt works interactively while piped and redirected output remains byte-exact.

## 4. Using the engines directly

The wrapper is a convenience. The equivalent explicit commands are below, and
either engine can be used without it.

### 4.1 Build

```bash
# Podman reads Containerfile by default.
podman build -t encryption-helper:local .

# Docker reads Dockerfile by default. A Dockerfile symlink to Containerfile is
# provided, so `docker build .` also works; -f is the explicit form.
docker build -f Containerfile -t encryption-helper:local .

# Stamp the OCI version label from a release pipeline.
docker build -f Containerfile --build-arg VERSION=0.0.2 \
  -t encryption-helper:0.0.2 .
```

### 4.2 Run with Podman (rootless)

```bash
podman run --rm --interactive \
  --network=none \
  --read-only \
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --userns=keep-id \
  --volume "$PWD:/work" \
  --workdir /work \
  --env HOME=/tmp \
  --env EH_PASS \
  encryption-helper:local \
  keygen --algorithm ed25519 --out-dir ./secrets --name service \
    --passphrase-env EH_PASS
```

`--userns=keep-id` maps the invoking user to the same uid inside the container.
Without it, rootless Podman maps that user to the container's root, and files
written to `/work` come back owned by a subordinate uid.

### 4.3 Run with Docker

```bash
docker run --rm --interactive \
  --network=none \
  --read-only \
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user "$(id -u):$(id -g)" \
  --volume "$PWD:/work" \
  --workdir /work \
  --env HOME=/tmp \
  --env EH_PASS \
  encryption-helper:local \
  keygen --algorithm ed25519 --out-dir ./secrets --name service \
    --passphrase-env EH_PASS
```

Docker performs no uid mapping, so `--user` is required for the bind-mounted
output to be owned by the invoking user. It overrides the image's own
unprivileged user; the result is still unprivileged, provided the invoking user
is not root.

`--env EH_PASS` with no value forwards the value from the calling shell, so the
passphrase does not appear in the engine's argument list. Never pass a
passphrase as a command-line argument.

The entry point is the `encryption-helper` console script and there is no
`CMD`, so arguments after the image reference are the tool's own. A bare
`docker run encryption-helper:local` reports a usage error listing the
available commands.

## 5. Host-specific notes

- **SELinux.** On a host with SELinux in enforcing mode, a bind mount may be
  inaccessible to the container until it is labelled. Re-run with
  `EH_SANDBOX_MOUNT_OPTS=z` to add the shared-content label. The wrapper does
  not do this by default, because relabelling modifies the host directory.
- **Working directories with spaces.** Supported; the wrapper quotes the mount
  specification.
- **Symbolic links.** Only the mounted directory is visible, so a symbolic link
  in `/work` that points outside it will not resolve. `scan` does not follow
  symbolic links in any case.
- **Tilde expansion.** The tool expands a leading `~` in path arguments, and
  inside the container `HOME` is the scratch tmpfs. Address key material by a
  path relative to the working directory.

## 6. Wrapper reference

```text
Usage: scripts/sandbox.sh [--rebuild] [--engine podman|docker] [--] ARGS...

  --rebuild              Rebuild the image even if it already exists.
  --engine ENGINE        Force podman or docker instead of auto-detecting.
  -h, --help             Show the wrapper's help. Use `-- --help` to reach the
                         tool's own help instead.
```

| Variable | Effect |
| --- | --- |
| `EH_SANDBOX_IMAGE` | Image reference to build and run. Default `encryption-helper:local`. |
| `EH_SANDBOX_ENGINE` | Same effect as `--engine`. |
| `EH_SANDBOX_MOUNT_OPTS` | Extra comma-separated bind-mount options, for example `z` on an SELinux host. |
| `EH_SANDBOX_FORWARD_ENV` | Space-separated list of additional environment variable names to forward. Variables named by `--passphrase-env` are forwarded automatically. |

The wrapper exits 1 when no engine is available, 2 on a wrapper usage error,
and otherwise passes the tool's own exit code through unchanged.
