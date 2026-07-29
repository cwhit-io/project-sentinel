The intended lifecycle is `discover -> normalize -> plan -> review -> execute -> verify`.
The v3 milestone is **mocked-only and non-applicable**. Discovery policy tests use
an exact inert canned-response transport with no HTTP, endpoint, credentials, or
retry. Execution cannot consume that client: it accepts only the exact dedicated
`InMemoryStateSimulator` type and performs an atomic pure state transition.
`validate_plan_v3` deterministically recomputes closed desired, snapshot, plan,
operation, ownership/scope, precondition, and digest bindings before transition.
Discovery accepts exactly Zabbix API `7.0.14`; every other version, including
other `7.0.x` releases, is rejected. It first makes bounded identity/tag queries
for the exact target scope and desired names, then fully normalizes only selected
hosts. Unrelated unmanaged and other-scope interface payloads are not consumed.
The future update renderer emits a non-executable sequence with `templates_clear`
and labels timeout/partial outcomes; it never sends commands.

Sentinel owns every `sentinel.*` tag. Exact `sentinel.scope=<target_id>` ownership
is required, foreign tags are preserved, and fresh collisions block transitions.
In-memory simulator receipts require full plan-v3 recomputation, exact complete
baseline-to-final snapshot transition (including unchanged top-level state,
unrelated hosts, and non-reused host/interface identities), exact per-operation
after-state binding, complete fixed-enum results, and an injected-clock UTC
completion timestamp. Receipt persistence is hard-disabled before pathname
handling; durable persistence requires future protected design and verification.
Deletion eligibility is unconditionally non-applicable because identity-bound
authenticated timestamp provenance is absent. Its entry point rejects before
parsing, and no delete executor exists. `sentinel apply` remains hard-disabled.
No runtime acceptance is claimed.

The protected-live scaffold is reduced to read-only discovery. Its lowest
network boundary has an immutable four-method allowlist (`apiinfo.version`,
`host.get`, `template.get`, and `hostgroup.get`) and requires the exact read
credential-handle type. It rejects every other method before parameters,
credential resolution, or network setup. The exact read client accepts no duck
transport. HTTPS is the default; commissioning HTTP is limited to explicitly
opted-in numeric loopback endpoints with canonical nonzero ports.

The target binding is computed internally from the exact client's canonical
endpoint contract, trust ID, read-handle ID, and a fixed no-write marker. Closed
semantic validation reconstructs desired/snapshot/plan digests and identifiers
before persistence and after bundle loading. Artifacts are bounded, owner-only,
outside the module-derived worktree, and remain non-applicable. Bundle content
is staged in memory and rejects malformed tags or any non-`sentinel.*` tag
before creating its run directory or files; only the five closed, value-checked
Sentinel ownership tags may persist. Exact locator/secret-like fields and values
also fail before directory creation. Approval
verification and live execution both reject before inspecting any input. No
mutation client, available mutation policy method, write handle/provider,
signature acceptance, signing code, retry, apply, or receipt persistence exists.
`host.delete` exists only in a separate inert unavailable tombstone policy with
`executor: none`; there is no delete execution path.
Runtime endpoint trust and filesystem durability are not established.
