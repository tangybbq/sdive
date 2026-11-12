# Lens: upgrade state machine and trailers

The swap algorithms (scratch, move, offset), overwrite-only mode and their
trailers (magic, flags, swap status, swap size, image-ok/copy-done) decide what
the bootloader copies where, and what it boots. Trailer data in attacker-writable
slots is attacker-controlled (flash-write boundary).

## Questions

- Which trailer fields are read from which slot, and can the attacker who can
  write that slot choose them? Are they bounded and cross-checked before they
  drive copy sizes, sector counts, offsets or the boot decision?
- Status parsing and resume after power loss: inconsistent, impossible or
  partially written status — is every state either handled correctly or
  rejected? Can a crafted status make the bootloader copy or erase the wrong
  sectors, or skip validation of what ends up in the primary slot?
- Sector-layout arithmetic: slot sizes, sector counts, scratch size, offset
  mode's shifted layout — off-by-one and overflow in the copy loops; images that
  do not fit; trailers overlapping image data.
- Revert and test/confirm: can attacker-written flags make a tested image
  permanent, or cause a revert to something unvalidated?
- Multi-image: per-image state and dependency handling, image indices.
- Error handling inside swaps: failures midway — fail closed, or continue?

## Not findings

- States reachable only by A3 writing the primary slot, unless a write path
  under A1/A2 can reach that trailer (check which slot recovery writes).
- Self-inflicted corruption that fails closed at the next boot.
