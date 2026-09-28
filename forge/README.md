# forge

Intent-driven code design. You describe what a network of services *should be*;
forge derives the code, commits to it with a Bitcoin-style merkle root, signs
the manifest with detached OpenPGP, prices the build in SEI, and stores every
artifact content-addressed.

Zero runtime dependencies. Python 3.11+ standard library only.

```
intent graph  ->  plan  ->  generated code  ->  SHA-256d merkle root
                                                  |
                                     +------------+------------+
                                     |                         |
                            detached PGP signature      SEI payment request
                                     |                         |
                                     +------------+------------+
                                                  |
                                       iceberg content store
```

---

## Table of contents

- [Quick start](#quick-start)
- [The intent document](#the-intent-document)
- [Rigor levels](#rigor-levels)
- [Transform objects](#transform-objects)
- [Commitments: SHA-256d, merkle, PGP](#commitments-sha-256d-merkle-pgp)
- [The iceberg store](#the-iceberg-store)
- [Paying in SEI](#paying-in-sei)
- [NixOS](#nixos)
- [CLI reference](#cli-reference)
- [HTTP API](#http-api)
- [Design decisions](#design-decisions)
- [Testing](#testing)

---

## Quick start

```bash
cd forge
export PYTHONPATH=src:.

python -m forge doctor                                  # what's available here
python -m forge catalog                                 # what costs what, in SEI
python -m forge validate examples/scan-billing.intent.json
python -m forge design   examples/scan-billing.intent.json
python -m forge build    examples/scan-billing.intent.json --out ./generated
python -m forge verify   ./generated
```

Or with `make`: `make test`, `make build`, `make reproducible`, `make serve`.

Nothing above touches the network, needs a wallet, or needs a key.

---

## The intent document

An intent is a typed, acyclic graph. **Nodes** are participants; **edges** are
data flows under constraints. That graph is the single source of truth — the
generated code is a pure function of it.

```json
{
  "schema": "forge.intent/v1",
  "name": "scan_billing",
  "objective": "Meter scan analyses and settle them in SEI.",
  "rigor": "strict",
  "network": {
    "nodes": [
      { "id": "scan_intake", "kind": "endpoint", "description": "Front door." },
      { "id": "charge_ledger", "kind": "store", "description": "Append-only." }
    ],
    "edges": [
      {
        "from": "scan_intake",
        "to": "charge_ledger",
        "carries": "ScanJob",
        "constraints": {
          "auth": "required",
          "idempotent": true,
          "max_bytes": 67108864,
          "pii": true
        }
      }
    ]
  }
}
```

**Node kinds:** `endpoint`, `service`, `worker`, `store`, `gateway`, `model`.

**Edge constraints** — and what each one *compiles into*:

| Constraint | Type | Becomes |
|---|---|---|
| `auth` | `none` \| `required` \| `service` | DRF permission class |
| `idempotent` | bool | `Idempotency-Key` contract, replay cache |
| `max_bytes` | int | size guard returning HTTP 413 |
| `pii` | bool | redacting `__repr__`, logging suppressed |
| `rate_limit` | int/min | scoped DRF throttle |
| `retries` | int | validated against `idempotent` |
| `timeout_ms` | int | recorded in the plan |

An unrecognised constraint is a **hard error**, never ignored. A typo'd
constraint that silently does nothing is worse than a crash, because it looks
like it's protecting you.

### Constraint resolution

A node's obligations come from its **inbound** edges — those describe the calls
it must police. Where several inbound edges disagree, the **tightest** wins:
strongest auth, smallest `max_bytes`, lowest `rate_limit`. Idempotency requires
**unanimity** — one non-idempotent caller makes replay unsafe for everyone.

A node with no inbound edges is an **origin**: entered from outside the graph,
where no edge exists to describe the call. Resolving it to "no constraints"
would leave the system's front door unguarded — precisely the node that most
needs guarding. So an origin inherits from its *outbound* edges instead. If the
data leaving is authenticated and size-capped, the data arriving from outside
gets the same treatment. An explicit `params.auth` on the node overrides this.

---

## Rigor levels

Each level is a strict superset of the one before.

| Level | Warnings | Reproducibility | Signature | Payment | Price |
|---|---|---|---|---|---|
| `lax` | printed | – | – | – | 0.75× |
| `standard` | printed | – | – | – | 1.00× |
| `strict` | **fatal** | **enforced** | – | – | 1.50× |
| `extreme` | **fatal** | **enforced** | **required** | **must settle first** | 2.50× |

`strict` runs the whole generation pass **twice** and requires an identical
chain root. A generator that reads a clock, a PRNG, the environment, or
unordered state dies there. There is a test that plants a deliberately
non-deterministic generator and asserts the build fails.

An intent's own `rigor` field is a **floor**, never a ceiling. Marking a network
`extreme` means nobody can quietly build it at `lax`; a stricter flag can still
raise it.

---

## Transform objects

Every build step is an immutable, content-addressed `TransformObject`:

```
inputs + operation + parameters  ->  outputs
```

They chain. Each names its parents by digest, so a completed build is a DAG
whose root commits to every input, parameter, and output byte that produced it.
Change one character of an intent and every downstream digest changes — the test
suite asserts exactly that.

Artifact digests bind **path and mode**, not just content, so moving a file or
flipping its executable bit changes its identity. Outputs are hashed in
path-sorted order, so a generator that reorders its internal loops does not
change the commitment.

---

## Commitments: SHA-256d, merkle, PGP

**`hash256` = SHA-256 applied twice**, Bitcoin's construction. The merkle tree
uses Bitcoin's duplicate-the-last-node rule for odd levels, and digests display
reversed (big-endian hex) exactly as Bitcoin renders txids.

**CVE-2012-2459 is handled.** Bitcoin's odd-node duplication means `[a,b,c]` and
`[a,b,c,c]` produce the same root. forge's default `strict=True` rejects
duplicate leaves outright, removing the ambiguity. The test suite demonstrates
the collision under `strict=False` and asserts it's blocked under `strict=True`.

The manifest carries an **`OP_RETURN` payload** (`FORGE1` + the 32-byte root, 38
bytes, well inside Bitcoin's 80-byte relay limit) ready to anchor to a chain.
forge *builds* the payload and stops there — constructing, signing, or
broadcasting a transaction would require key custody.

**Signing shells out to GnuPG.** forge does not implement OpenPGP; a hand-rolled
signature implementation is the kind of thing that demos fine and fails
catastrophically. GnuPG owns the keyring, the agent, pinentry, and smartcards.
No key material passes through forge — you name a key (`FORGE_GPG_KEY`) and
gpg-agent does the rest.

**Verification is two independent steps, and both must pass:**

1. **Integrity** — recompute every digest and the merkle root from files on disk.
2. **Authenticity** — check the detached signature over the manifest bytes.

Step 1 alone proves the files match a manifest *anyone* could have written. Step
2 alone proves someone signed a document that might describe different files.
`forge verify` reports them separately and only prints `VERIFIED` when both hold.
An unsigned tree exits non-zero even when its contents match perfectly.

A signature that is cryptographically valid but made by an **unknown, expired, or
revoked key** is reported as *invalid*. "The maths checks out" is not the same as
"I trust this", and conflating them is how signature checks become decorative.

---

## The iceberg store

Three invariants, enforced in code:

**Tip above water.** Every object has a small public record — digest, size,
media type, path — safe to publish, index, or price. The tip never contains
content. You can hand someone the entire tip index and leak nothing but shape.

**No blocks.** Bodies are never chunked or striped. One object, one whole file,
written atomically via temp-file + `os.replace` + directory `fsync`. No
reassembly step, so no partial-read failure mode and no chunk index to corrupt.

**No key cut.** The address is the full 64-character digest, used whole. No
`ab/cd/rest` fan-out directories, no truncated lookups, no prefix matching, no
key splitting. Prefix addressing invites collisions and ambiguous resolution;
this store resolves a digest exactly or errors.

Reads always re-verify: bytes are re-hashed against the key they were filed
under, so bit-rot surfaces as an error rather than as bad data handed back.
`forge iceberg --fsck` walks the whole store.

---

## Paying in SEI

### Non-custodial, stated plainly

> **forge never holds, reads, derives, imports, or transmits a private key.**

There is no wallet in this codebase. The flow:

1. **Quote** — forge prices the build from the published catalog.
2. **Request** — forge emits a payment request: payee, exact integer amount, and
   a memo reference derived from the build's merkle root.
3. **Pay** — *you* pay from your own wallet (Compass, Keplr, `seid`, or any EVM
   wallet). forge is not involved and could not intercept it if it tried.
4. **Verify** — forge queries the chain **read-only** and confirms the transfer
   reached the payee, cleared the amount, carried the reference, and has enough
   confirmations.

The blast radius of a bug here is "a payment is reported unsettled" — never
"funds moved". And no secret can leak from this repo, because there is none.

Two tests enforce this structurally: one tokenizes the payment modules (skipping
comments and strings, so prose can't fool it) and asserts no key-handling
identifiers exist; another asserts `SeiClient`'s entire public surface is
`find_transfer` and `latest_height`.

### The reference binds a payment to one build

The memo reference is derived from the merkle root **plus** the amount **plus**
the payee. Paying for build A cannot unlock build B, cannot unlock A at a
different price, and cannot be redirected to a different recipient.

### Integer money, always

All arithmetic is integer `usei` (1 SEI = 1,000,000 usei). **The canonical
serialiser rejects floats outright** — not rounds them, rejects them. Float
money is how you charge someone `0.30000000000000004 SEI`, and since prices go
into a signed manifest, a rounding difference between two machines would break
the signature. Percentages are basis points applied with ceiling division.

### Both chain surfaces

SEI exposes one chain two ways, and a payer can use either:

- **Cosmos LCD** — bech32 `sei1...`, `MsgSend`, memo field
- **EVM JSON-RPC** — `0x...`, native transfer, reference in calldata

Addresses are validated with **real checksum arithmetic**: bech32 polymod for
Cosmos, and EIP-55 for EVM. EIP-55 needs Keccak-256, and `hashlib.sha3_256` is
*not* Keccak (NIST changed the padding byte from `0x01` to `0x06`), so forge
includes a pure-Python Keccak-f[1600]. It's validated against the published
empty-string and `abc` vectors, and against all four reference addresses from
EIP-55 itself. A mistyped payout address is unrecoverable, so forge refuses
anything it cannot fully verify.

### The mainnet guardrail

**Default is testnet (`atlantic-2`).** Mainnet requires **two independent
signals**:

```bash
export FORGE_SEI_NETWORK=pacific-1
export FORGE_ALLOW_MAINNET=1        # separate, explicit
```

Selecting a mainnet endpoint alone is *not* sufficient, so no default, typo, or
copied command can move real value by itself. Under NixOS the same rule is an
evaluation-time assertion — a misconfigured machine fails to build.

For real funds, also set `FORGE_SEI_LCD` to a node you control. Public RPC is
rate-limited and can serve a stale or forked view; on NixOS, mainnet without a
custom endpoint is a hard assertion failure.

---

## NixOS

```nix
{
  inputs.forge.url = "path:./forge";

  outputs = { nixpkgs, forge, ... }: {
    nixosConfigurations.build-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        forge.nixosModules.default
        {
          services.forge = {
            enable = true;
            rigor = "strict";
            network = "atlantic-2";
            listenAddress = "127.0.0.1";
            gpgKey = "0xDEADBEEFCAFEBABE";
            environmentFile = "/run/secrets/forge.env";
          };
        }
      ];
    };
  };
}
```

The module refuses to evaluate — before anything is deployed — if:

- `network` is mainnet but `allowMainnet` isn't explicitly `true`
- mainnet has no `payee`, or no custom `lcdEndpoint`
- `rigor = "extreme"` but no `gpgKey` (every build would fail)
- `environmentFile` points into the **Nix store**, which is world-readable —
  a secret there is a published secret

Plus warnings for non-loopback binds (the API has no auth of its own) and for
mainnet with fewer than 2 confirmations.

The systemd unit is hardened: `ProtectSystem=strict`, `PrivateUsers`,
`ProtectProc=invisible`, empty `CapabilityBoundingSet`, `MemoryDenyWriteExecute`,
and `SystemCallFilter=@system-service ~@privileged ~@resources`.

`nix flake check` runs the full test suite **and** a separate derivation that
builds the same intent twice in isolated sandboxes and diffs the merkle roots —
reproducibility gated by the build system rather than trusted.

---

## CLI reference

| Command | Purpose |
|---|---|
| `forge doctor` | what's available in this environment |
| `forge catalog` | published price list — no auth, no wallet, no chain |
| `forge validate <intent>` | validate the graph |
| `forge design <intent>` | resolve into an ordered plan |
| `forge build <intent>` | generate, price, sign, store, write |
| `forge quote <intent>` | price and issue a payment request |
| `forge verify-payment --request r.json --tx <hash>` | check settlement |
| `forge verify <dir>` | integrity + authenticity of a built tree |
| `forge iceberg [--fsck] [--show DIGEST]` | inspect the store |
| `forge serve` | run the REST API |
| `forge generators` | list generators |

Every command takes `--json` for canonical output. Global flags work **before or
after** the subcommand. Errors map to distinct exit codes (`ConfigError` → 78,
`IntentError` → 65, `IntegrityError` → 66, `PaymentError` → 75, `PolicyError` →
77) so scripts can branch on failure category.

### Environment

| Variable | Default | Meaning |
|---|---|---|
| `FORGE_RIGOR` | `standard` | rigor level |
| `FORGE_WORKDIR` | `.forge` | state directory |
| `FORGE_SEI_NETWORK` | `atlantic-2` | testnet by default |
| `FORGE_ALLOW_MAINNET` | unset | **required** for mainnet |
| `FORGE_SEI_PAYEE` | – | receiving address |
| `FORGE_SEI_LCD` / `FORGE_SEI_EVM_RPC` | public | your own node |
| `FORGE_MIN_CONFIRMATIONS` | `1` | raise for real money |
| `FORGE_GPG_KEY` | – | signing key **id**, not key material |
| `GEMINI_API_KEY` | – | optional designer; never logged or persisted |
| `SOURCE_DATE_EPOCH` | `0` | reproducible-builds timestamp |

---

## HTTP API

```
GET  /healthz                     GET  /v1/catalog
GET  /v1/networks                 GET  /v1/generators
POST /v1/validate                 POST /v1/design
POST /v1/quote                    POST /v1/build
POST /v1/verify-payment
GET  /v1/objects                  GET  /v1/objects/{digest}[/body]
```

```bash
python -m forge serve --host 0.0.0.0 --port 8787

curl -s localhost:8787/v1/catalog | jq .
curl -s -X POST localhost:8787/v1/build \
  -H 'content-type: application/json' \
  -d "{\"intent\": $(cat examples/scan-billing.intent.json)}" | jq .summary
```

`/v1/build` returns artifact **tips** by default and content only when
`"include_content": true` — the iceberg rule applied to the wire.

The API is **unauthenticated by design** and meant to sit behind a reverse
proxy. It exposes no key because there is none, but it will generate code for
anyone who can reach it.

---

## Design decisions

**Zero dependencies.** A tool whose job is to establish a trust boundary
shouldn't drag a dependency tree across it. Canonical JSON, SHA-256d, merkle
trees, Keccak-256, bech32, EIP-55, the SEI client, and the REST server are all
standard library.

**Floats are rejected, not rounded.** A silent rounding rule is a silent
consensus bug. The canonical serialiser refuses `float` anywhere in a document.

**Determinism is tested, not asserted.** `SOURCE_DATE_EPOCH`, sorted iteration
everywhere, a min-heap tie-break in the topological sort (a plain `set` would
make build order depend on Python's hash seed), and a double-build check that a
deliberately-cheating generator is proven to trip.

**The LLM advises; the graph decides.** The optional Gemini designer runs at
`temperature=0, topP=0, topK=1` with a fixed response schema, and everything it
returns is filtered against the intent graph. It may suggest *parameters* for
nodes the author already declared — it cannot add a node, add an edge, rename
anything, or override an author-set value. Hallucinated nodes are silently
dropped; six tests cover the sanitiser. The default designer needs no model and
no network, because a build that needs a network call to reproduce is not
reproducible.

**Generators are pure functions.** `(Step, Plan) -> list[Artifact]`. No clock,
no randomness, no environment, no filesystem. Everything they may know arrives
through their arguments — which is what makes the reproducibility check mean
something.

**Path traversal is blocked twice.** `Artifact` rejects absolute paths,
backslashes, and `..` segments at construction; the writer independently
re-resolves every path against the output root.

---

## Testing

```bash
cd forge && PYTHONPATH=src:. python -m unittest discover -s tests -t . -v
```

**178 tests**, no third-party test runner. They cover published Keccak-256 and
EIP-55 vectors, the CVE-2012-2459 merkle collision, bech32 single-character
typo detection, float rejection, reference binding, the mainnet guardrail, the
iceberg's three invariants, tamper detection, generated-code compilation, the
Gemini sanitiser, CLI exit codes, and the HTTP API over a real loopback socket.

One test is skipped unless `gpg` is installed (the sign/verify round-trip).

---

## Scope

This is a self-contained tool under `forge/`. It does not modify, import from,
or depend on the Canceralyze backend, frontend, or ML models. The example intent
models Canceralyze's billing domain, and the DRF generator matches the
conventions in `backend/cancer`, but nothing is wired into the app — adding
payments to a medical-diagnostics flow is a product and compliance decision, not
a refactor.
