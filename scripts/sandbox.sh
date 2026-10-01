#!/usr/bin/env bash
#
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
#
# Run the `encryption-helper` command-line interface inside a hardened,
# throwaway container. Nothing is installed on the host beyond a container
# engine, and the container is given no network access, no writable root
# filesystem, no Linux capabilities and no route to privilege escalation.
#
# The current directory is bind-mounted at /work and is the container's working
# directory, so relative paths behave as they would on the host.
#
# See docs/SANDBOX.md for the security properties this does and does not
# provide.

set -euo pipefail

# Resolve the repository from this script's own location rather than from the
# current directory. The current directory is the operator's data directory and
# is usually somewhere else entirely.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"

# Overridable so that a release pipeline can test a candidate tag without
# editing this script.
image="${EH_SANDBOX_IMAGE:-encryption-helper:local}"

# Additional bind-mount options, appended to the mount specification. Left
# empty by default because the useful values are host-specific and some of them
# modify host state: on an SELinux host, `z` or `Z` relabels the mounted
# directory on the host filesystem, which is not something to do without the
# operator asking for it.
#
#   EH_SANDBOX_MOUNT_OPTS=z ./scripts/sandbox.sh capabilities
#
mount_opts="${EH_SANDBOX_MOUNT_OPTS:-}"

engine_override="${EH_SANDBOX_ENGINE:-}"
rebuild=0

usage() {
  cat <<'USAGE'
Usage: scripts/sandbox.sh [--rebuild] [--engine podman|docker] [--] ARGS...

Runs `encryption-helper ARGS...` inside a hardened container. The current
directory is mounted at /work and is the container's working directory.

Wrapper options (must precede the tool's own arguments):
  --rebuild              Rebuild the image even if it already exists.
  --engine ENGINE        Force `podman` or `docker` instead of auto-detecting.
  -h, --help             Show this message. Use `-- --help` to reach the
                         tool's own help instead.

Environment:
  EH_SANDBOX_IMAGE       Image reference to build and run (default
                         encryption-helper:local).
  EH_SANDBOX_ENGINE      Same effect as --engine.
  EH_SANDBOX_MOUNT_OPTS  Extra comma-separated bind-mount options, for example
                         `z` on an SELinux host.

Examples. Global options such as --json and -q precede the command; input and
output are selected with --in and --out.

  # Report the supported algorithms and their post-quantum status as JSON.
  scripts/sandbox.sh --json capabilities

  # Generate a passphrase-protected Ed25519 key pair into ./secrets.
  EH_PASS=... scripts/sandbox.sh keygen --algorithm ed25519 \
    --out-dir ./secrets --name service --passphrase-env EH_PASS

  # Generate an unprotected RSA-3072 key pair (CI and test use only).
  scripts/sandbox.sh keygen --algorithm rsa --key-size 3072 \
    --out-dir ./secrets --name service --no-passphrase

  # Encrypt and decrypt a file.
  scripts/sandbox.sh encrypt --public-key secrets/service.pub.pem \
    --in report.csv --out report.csv.enc
  scripts/sandbox.sh decrypt --private-key secrets/service.pem \
    --in report.csv.enc --out report.csv --passphrase-env EH_PASS

  # Sign and verify. `verify` exits 4 if the signature does not verify.
  scripts/sandbox.sh sign --private-key secrets/service.pem \
    --in report.csv --out report.csv.sig --passphrase-env EH_PASS
  scripts/sandbox.sh verify --public-key secrets/service.pub.pem \
    --signature report.csv.sig --in report.csv

  # Report a container's algorithms without decrypting it.
  scripts/sandbox.sh inspect --in report.csv.enc

  # Fingerprint a public key, and inventory a tree for deprecated algorithms.
  scripts/sandbox.sh fingerprint secrets/service.pub.pem
  scripts/sandbox.sh --json scan . --fail-on-finding

  # Convert a public key to OpenSSH encoding on stdout.
  scripts/sandbox.sh convert --to openssh --in secrets/service.pub.pem --out -

  # Pipe through the sandbox. The tool defaults to stdin and stdout.
  cat report.csv | scripts/sandbox.sh encrypt \
    --public-key secrets/service.pub.pem > report.csv.enc
USAGE
}

# Wrapper options are consumed only while they appear before the first
# tool argument. Parsing stops at the first token that is not a wrapper option,
# or at an explicit `--`, so that the tool's own options -- including its
# `--help` -- are passed through untouched.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rebuild)
      rebuild=1
      shift
      ;;
    --engine)
      if [[ $# -lt 2 ]]; then
        printf 'sandbox: --engine requires an argument\n' >&2
        exit 2
      fi
      engine_override="$2"
      shift 2
      ;;
    --engine=*)
      engine_override="${1#--engine=}"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -eq 0 ]]; then
  printf 'sandbox: no arguments given; nothing to run.\n\n' >&2
  usage >&2
  exit 2
fi

# --- Engine selection ------------------------------------------------------
#
# Podman is preferred where both are available: rootless by default, no
# long-running daemon holding root, and no requirement for the invoking user to
# belong to a group equivalent to root.
#
# Assigns to the global `engine`. A function that printed the result would have
# to be called in a command substitution, where `exit` terminates only the
# subshell; assigning directly keeps the failure paths able to stop the script.
engine=""
select_engine() {
  if [[ -n "$engine_override" ]]; then
    if ! command -v -- "$engine_override" >/dev/null 2>&1; then
      printf 'sandbox: requested engine %s is not on PATH.\n' "$engine_override" >&2
      exit 1
    fi
    engine="$engine_override"
    return 0
  fi
  local candidate
  for candidate in podman docker; do
    if command -v -- "$candidate" >/dev/null 2>&1; then
      engine="$candidate"
      return 0
    fi
  done
  printf 'sandbox: neither podman nor docker was found on PATH.\n' >&2
  exit 1
}

select_engine
engine_name="$(basename -- "$engine")"
printf 'sandbox: using %s\n' "$engine_name" >&2

# --- Image build -----------------------------------------------------------
#
# `image inspect` is the portable existence check; both engines return
# non-zero when the reference is unknown locally.
image_present=0
if "$engine" image inspect "$image" >/dev/null 2>&1; then
  image_present=1
fi

if [[ "$rebuild" -eq 1 || "$image_present" -eq 0 ]]; then
  printf 'sandbox: building %s from %s\n' "$image" "${repo_root}/Containerfile" >&2
  "$engine" build \
    --file "${repo_root}/Containerfile" \
    --tag "$image" \
    "$repo_root"
fi

# --- Run -------------------------------------------------------------------

host_dir="$(pwd -P)"
mount_spec="${host_dir}:/work"
if [[ -n "$mount_opts" ]]; then
  mount_spec="${mount_spec}:${mount_opts}"
fi

run_args=(
  # Discard the container when the command exits. Each invocation is a fresh
  # filesystem, so nothing persists except what was written to /work.
  --rm

  # No network namespace connectivity at all. The tool performs no network
  # calls, and removing the network turns that claim into an enforced property
  # rather than a documented intention: key material cannot be exfiltrated and
  # no dependency can be fetched at run time.
  --network=none

  # The container's own root filesystem is immutable. Combined with the
  # bind mount, every write the tool makes must land in /work, where the
  # operator can see it.
  --read-only

  # /work is the only writable path by default, and the tool writes its atomic
  # temporary files alongside their targets rather than in /tmp. This tmpfs is
  # therefore a small, non-executable scratch area for the interpreter rather
  # than a data path, and it is discarded with the container.
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777

  # Drop every Linux capability. Nothing this tool does requires one: it reads
  # and writes files as the invoking user and performs computation.
  --cap-drop=ALL

  # Prevent the process, or anything it spawns, gaining privileges through a
  # setuid or setgid binary inherited from the base image.
  --security-opt=no-new-privileges

  # The operator's data directory, mounted at the container's working
  # directory so that relative paths given on the command line resolve as they
  # would on the host.
  --volume "$mount_spec"
  --workdir /work

  # The mapped uid may have no entry in the image's /etc/passwd, leaving HOME
  # undefined; the tool expands a leading `~` in path arguments, which would
  # then resolve against `/`. Pointing HOME at the tmpfs makes that expansion
  # defined, writable and discarded with the container. Key material should
  # still be addressed by a path under /work.
  --env HOME=/tmp
)

# Keep stdin open so that the tool can read piped input, which is its default
# for --in. Allocate a terminal only when one is genuinely attached at both
# ends: a terminal is required for the interactive passphrase prompt, but
# requesting one when stdout is redirected corrupts binary output with
# carriage returns.
run_args+=(--interactive)
if [[ -t 0 && -t 1 ]]; then
  run_args+=(--tty)
fi

# Identity mapping differs between the engines, and getting it wrong is the
# usual cause of files in the bind mount being unreadable afterwards.
#
# Rootless Podman already runs inside a user namespace in which the invoking
# user is mapped to the container's root by default. `--userns=keep-id` instead
# maps the invoking user to the same uid inside the container, so files created
# in /work are owned by that user on the host and the process is not uid 0.
#
# Docker's daemon runs as root and performs no such mapping, so the uid and gid
# are set explicitly. This overrides the image's own unprivileged user, which
# is intentional: ownership in the bind mount must match the caller.
if [[ "$engine_name" == "podman" && "$(id -u)" -ne 0 ]]; then
  run_args+=(--userns=keep-id)
else
  run_args+=(--user "$(id -u):$(id -g)")
fi

# Passphrases are passed by reference, never by value. `--passphrase-env` names
# a variable rather than carrying the secret in the arguments, which are
# visible to anything that can read the engine's process list; that variable
# must therefore exist inside the container. The names are taken from the
# command line so the caller does not have to declare them twice, and
# EH_SANDBOX_FORWARD_ENV covers anything else that needs forwarding.
forward_env=()
previous=""
for arg in "$@"; do
  if [[ "$previous" == "--passphrase-env" ]]; then
    forward_env+=("$arg")
  fi
  case "$arg" in
    --passphrase-env=*) forward_env+=("${arg#--passphrase-env=}") ;;
  esac
  previous="$arg"
done

# EH_SANDBOX_FORWARD_ENV holds a whitespace-separated list of variable names,
# so splitting it on whitespace is the intended reading. The `${a[@]+...}`
# form is used throughout because `set -u` treats an empty array expansion as
# an unset variable on older releases of bash.
read -r -a extra_env <<<"${EH_SANDBOX_FORWARD_ENV:-}"
forward_env+=(${extra_env[@]+"${extra_env[@]}"})

for var in ${forward_env[@]+"${forward_env[@]}"}; do
  if [[ -z "${!var-}" ]]; then
    printf 'sandbox: %s is to be forwarded but is unset or empty in this shell; the container would see no value for it.\n' "$var" >&2
    exit 2
  fi
  # `--env NAME` with no value forwards the value from this process, so the
  # secret never appears in the engine's own argument list.
  run_args+=(--env "$var")
done

# The image reference is the first operand, so every argument after it is
# passed to the entry point rather than parsed by the engine.
exec "$engine" run "${run_args[@]}" "$image" "$@"
