# Lens: serial recovery / SMP surface (A2, P6)

Serial recovery is unauthenticated by design: staging an image is allowed. The
findings are **escaping the writable region**, **defeating the next boot's
P1/P2 checks**, and **pre-auth denial of service** of the recovery path.

## Questions

- **Request parsing:** CBOR/SMP decoding of every field — types, lengths,
  nesting depth, missing or duplicated fields, integer ranges (image number,
  offsets, lengths, slot indices). Can any field index an array or select a
  flash area out of range?
- **Upload state:** first vs subsequent chunks, offset continuity, total length
  vs area size, chunk length vs buffer size, behaviour after an error mid-upload.
  Can writes land outside the intended area, or before/after it?
- **Which slot is written** in each configuration (see the serial-recovery
  exception in the threat model) and what the next boot then trusts from it.
- **Other commands:** erase, reset, image list/state, custom and group
  extensions — can they modify state or flash beyond what they should, or be
  reached when they should not?
- **Availability:** can a single malformed request crash, hang or wedge the
  bootloader (pre-auth DoS, P6)?

## Not findings

- Uploading an arbitrary image to the writable slot (granted).
- Corruption that the next boot's signature check rejects (fails closed),
  unless it also denies the recovery path itself.
