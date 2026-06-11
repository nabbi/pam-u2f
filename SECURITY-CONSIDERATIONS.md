# Security considerations

## Untrusted authenticators and libcbor

pam-u2f, via `libfido2`, parses CTAP2/CBOR messages received from any FIDO
authenticator presented to it, before any cryptographic verification takes
place. `libcbor` (the CBOR library used by `libfido2`) allocates memory for
array and map elements based on a count taken directly from the CBOR
header, without bounding it against the amount of input data actually
available. A handful of bytes can therefore declare an array or map with
hundreds of millions of elements and cause `cbor_load()` to attempt a
multi-gigabyte allocation.

This is documented, working-as-intended `libcbor` behavior: it was reported
as [PJK/libcbor#418](https://github.com/PJK/libcbor/issues/418) and closed
as "invalid". The maintainer's response,
[PJK/libcbor#422](https://github.com/PJK/libcbor/pull/422), confirms the
design and recommends that applications parsing untrusted CBOR install a
capping allocator via `cbor_set_allocs()` (see `examples/capped_alloc.c`)
or use the streaming decoder instead of `cbor_load()`.

pam-u2f does not depend on `libcbor` directly -- it is a private, transitive
dependency pulled in by `libfido2` -- so it cannot reliably call
`cbor_set_allocs()` itself: doing so would add a build and runtime
dependency on an otherwise-internal component of `libfido2`, with no
guarantee that the allocator it configures is the same instance `libfido2`
uses to decode CTAP2 responses.

As defense in depth instead, pam-u2f temporarily lowers its own `RLIMIT_AS`
while communicating with an authenticator, so that an oversized allocation
-- whether from `libcbor` or anything else in that code path -- fails
cleanly with `ENOMEM` (handled by `libcbor`/`libfido2` as an ordinary parse
error) instead of growing the host process (which may be running as root,
e.g. inside `sshd`, `sudo`, or `login`) without bound. This requires no
dependency on `libcbor`'s internals and, per #422, is also necessary on
Linux specifically: with memory overcommit enabled, `malloc` can appear to
succeed for an allocation that cannot actually be backed.

pam-u2f's own fuzzing CI separately patches `libcbor`'s
`_cbor_alloc_multiple` to cap `item_count` at 1000 (see `libfido2`'s
`fuzz/README`), so that fuzzing under sanitizers stays within reasonable
memory bounds. That patch is fuzzing-specific and not suitable for
production use.
