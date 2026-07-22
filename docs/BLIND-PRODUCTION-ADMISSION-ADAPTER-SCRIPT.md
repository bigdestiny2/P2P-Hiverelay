# Blind production admission adapter script

The explicit production `CELL_*` profiles load admission policy from one
root- or daemon-owned, hash-pinned JavaScript Script file. This boundary exists
to keep the daemon entrypoint import-free and to prevent an adapter from
receiving Node.js objects or ambient host APIs. It is an origin-integrity and
authority-confinement boundary for reviewed operator code. It is not a sandbox
for hostile code, and it does not make the currently blocked production release
deployable.

## Configuration and protected-file rules

A CELL profile requires both variables:

```text
HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE=/canonical/absolute/adapter.js
HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256=<64 lowercase hex characters>
```

`HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE` and
`HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256` belong to the retired executable
module contract and are rejected. `DESCRIBE_ONLY_V1` rejects all adapter script
configuration.

The configured path must be canonical and absolute. The loader opens it with
`O_NOFOLLOW`, then requires a regular file with exactly one hard link, no group
or world write bits, ownership by root or the daemon uid, a stable canonical
path, and a size from 1 byte through 256 KiB. Device, inode, link count, owner,
mode, size, modification time, and change time must remain identical before and
after the exact bytes are read. The bytes must match the configured SHA-256,
decode as fatal UTF-8, and contain no NUL.

Replacing the path after a successful load does not change the running adapter.
A restart rereads and revalidates the replacement.

## Script completion contract

The file is a classic `node:vm` Script, not an ES module. Its completion value
must have exactly these two enumerable keys:

```js
({
  schema: 'hiverelay-admission-adapter-script-v1',
  createAdmissionAdapterResolver (context) {
    return function resolveAdmissionAdapter (input) {
      return Object.freeze({
        prepare (input) { /* return proof data */ },
        preparePreflight (input) { return Object.freeze({}) },
        confirmAfterEof (input) { /* return proof data */ }
      })
    }
  }
})
```

The factory, resolver, and all three adapter methods must be synchronous and
non-thenable. The resolver must return an adapter for every required signed
`CELL.PUT` profile/endpoint pair at startup. The adapter object must have exactly
the three methods shown above. A null resolution, extra or missing key, async
function result, throwing `then` property, initialization error, or malformed
completion value fails startup.

The script may not use static or dynamic imports. It receives no `process`,
`require`, CommonJS state, `Buffer`, console, timers, fetch, crypto, performance,
shared-memory, WebAssembly, or string-code-generation authority. String and wasm
code generation are disabled in the VM context. `FinalizationRegistry`, `WeakRef`,
and the global `Promise` constructor are also unavailable. Source containing
`Promise`, `async`, `await`, or direct `Array.fromAsync` syntax is rejected
fail-closed. A trusted context-hardening prelude additionally replaces
`Array.fromAsync` with an immutable `undefined`, including for computed-property
access. These restrictions prevent adapter code from scheduling promise jobs or
garbage-collection finalizers that could escape the bounded call lifecycle.
Script evaluation, factory, resolution, lifecycle methods, and private bridge
operations all execute through `Script.runInContext()` with a 250 ms timeout.
The implementation uses stable `node:vm` APIs and requires no experimental
VM-module feature. The deferred-work surface assessment is bound to the sealed
Node runtime; a Node upgrade requires re-audit for newly added promise-producing
intrinsics before promotion.

A value thrown inside the VM is discarded without host inspection. The loader
reports only a fixed host-owned diagnostic and never exposes the thrown value as
an `Error.cause`, so later logging or inspection cannot invoke VM-owned traps or
custom inspection hooks outside the timeout.

## Data and capability membrane

Host records are checked through own property descriptors. Accessors, Proxies,
cycles, symbols, exotic prototypes, sparse arrays, unsafe numbers, and
unsupported values are rejected without invoking caller getters or Proxy traps.
The bridge transfers only bounded primitive JSON. It reconstructs arrays and
null-prototype records inside the VM and deep-freezes them before calling adapter
code. The graph limit is 16,384 nodes, the depth limit is 32, and an encoded
message is limited to 1 MiB.

Two tagged null-prototype records preserve non-JSON values:

```js
{ $hiverelayType: 'bytes', hex: '<lowercase even-length hex>' }
{ $hiverelayType: 'u64', value: '<canonical unsigned decimal>' }
```

No host-realm object enters the VM. In particular, a caller cannot use
`input.constructor.constructor` to recover host authority because the input is a
new null-prototype VM record. A direct `AbortSignal` remains outside the bridge
and is checked with the captured native `AbortSignal.prototype.aborted` getter
before and after each synchronous call.

`preparePreflight` must return one empty frozen VM-realm object. The host returns
a different empty frozen token to the coordinator. A WeakMap retains the VM
capability only while that host token is live; confirmation burns the mapping
before invocation and reinjects only the original same-context VM object. There
is no strong preflight registry or numeric capability id. Adapter code that
tracks live capabilities must also use a `WeakSet` or `WeakMap`, so an abandoned
request cannot create permanent adapter-owned state.

## Fail-closed startup order

The packaged CLI follows this order for an explicit CELL profile:

1. Validate bootstrap, entrypoint, and runtime configuration.
2. Execute the production release gate.
3. Read and validate the signed descriptor and admission parameters.
4. Open, hash, compile, and initialize the protected adapter script.
5. Resolve and capture every required signed `CELL.PUT` adapter.
6. Replace live resolution with the captured map; no fallback resolver remains.
7. Open stores and assemble the daemon.
8. Create the private IPC listeners only after assembly succeeds.

Script load, digest, export, initialization, required-profile resolution,
missing-method, or zero-required-profile failure therefore occurs before either
private IPC socket exists. Direct programmatic assembly retains its explicit
non-strict/degraded seam for tests and incomplete development profiles; the
packaged CELL CLI always requests complete capture.

To roll back, select `DESCRIBE_ONLY_V1` and remove both script variables. That
profile refuses adapter configuration and cannot silently retain CELL authority.
The independent production runtime and gateway release blockers remain in force
until their separate evidence and approval gates are satisfied.
