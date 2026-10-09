<!-- SPDX-License-Identifier: Apache-2.0 -->

# encryption-helper-mcp

A read-only [Model Context Protocol][mcp] server exposing the assessment side
of [`encryption-helper`](../../README.md) to an AI assistant.

---

## What it is for

Planning a post-quantum migration begins with scoping it, and scoping means
answering questions about material that already exists: which keys and
certificates use an algorithm that stops being acceptable, when it stops, and
what replaces it. Those are questions an assistant can usefully help with, so
this server makes them available as tools.

## What it deliberately does not do

It cannot generate, encrypt, decrypt, sign, convert or write anything.

That is not an oversight. A model's context is transmitted to a third party,
logged and retained, so routing private key material through it would
contradict the purpose of a tool whose job is to keep that material on the
operator's machine. Where an operation is required rather than an answer, use
the `encryption-helper` command directly.

Two properties are enforced by tests rather than stated in documentation:

| Property | How it is enforced |
| --- | --- |
| No module can act on key material | `test_boundary.py` parses every module's imports and fails if any name that generates, encrypts, decrypts, signs or writes a key is in scope |
| No module writes to the filesystem | the same test rejects any `open()` call in a write or append mode |
| No tool accepts a passphrase | every tool's JSON Schema is checked for `passphrase` and `password` arguments |
| Reads stay inside one directory | paths are resolved before being checked against the root, so a symbolic link pointing outside it is refused rather than followed |

## Installation

```sh
pip install encryption-helper-mcp
```

The only dependency is `encryption-helper` itself. The protocol is implemented
against the standard library, so a tool that answers questions about key
material does not bring a dependency tree with it.

## Configuration

The server speaks JSON-RPC 2.0 over standard input and output. Register it
with any MCP client:

```json
{
  "mcpServers": {
    "encryption-helper": {
      "command": "encryption-helper-mcp",
      "args": ["--root", "/path/to/inspect"]
    }
  }
}
```

`--root` is the only directory the server will read within, and it defaults to
the working directory. Paths outside it are refused. Set it to the narrowest
directory that contains what needs assessing.

> [!CAUTION]
> Tool results include file paths and certificate subjects, and the client
> passes them to its model. Follow your organisation's policy on what may be
> shared with an AI service, and choose `--root` accordingly.

To run the server without installing Python, use the container sandbox:
`scripts/sandbox.sh --target mcp` serves the current directory read-only. See
[docs/SANDBOX.md](../../docs/SANDBOX.md#38-the-mcp-server).

## Tools

| Tool | Answers | Reads from disk |
| --- | --- | --- |
| `pq_horizon` | The NIST IR 8547 dates, the publications they come from, and the validation note that accompanies them | no |
| `assess_algorithm` | Whether one algorithm choice is quantum-vulnerable, when it stops being acceptable, and what replaces it | no |
| `algorithm_inventory` | The same for every supported algorithm, in one call | no |
| `inspect_container` | Which algorithms protect an encrypted file, from its 10-byte header | header only |
| `scan_directory` | Which keys, certificates and encrypted files under a path need migrating | yes, within the root |
| `fingerprint_public_key` | The SHA-256 fingerprint of a public key file | yes, within the root |

### Notes on `scan_directory`

Classification is by file contents, not by filename. Symbolic links are not
followed, only regular files are read, and at most 64 KiB is read from any one
file.

An encrypted private key is reported as needing manual review rather than
being unlocked, because its algorithm is inside the encrypted structure and no
passphrase is requested. Gate on `summary.needs_attention` rather than
`summary.action_required`: a well-protected RSA-2048 key reports
`action_required` as false only because its algorithm could not be read, and
treating that as a pass would be the wrong conclusion to draw from a
passphrase.

### Notes on `assess_algorithm`

RSA can both encrypt and sign, and no single post-quantum algorithm replaces
both. Assessing `rsa` without a `purpose` therefore returns two
`replacements` and a null `replacement`; supply `purpose` as `encrypt` or
`sign` to resolve it.

## Verifying it by hand

The transport is plain text, so a session can be driven from a shell:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | encryption-helper-mcp --root .
```

## Licence

Apache-2.0. See [LICENSE](../../LICENSE).

[mcp]: https://modelcontextprotocol.io
