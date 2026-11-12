# Lens: anti-rollback and downgrade (P2)

With hardware rollback protection enabled, can an older (validly signed) image
be booted, or the stored security counter be lowered or desynchronized?

## Questions

- Where does the image's security counter come from — protected or unprotected
  data? Is it read from the same bytes that were validated?
- Comparison logic: `<` vs `<=`, signedness, widths, missing counter treated as
  zero or as "pass"?
- When is the stored counter updated — before or after the image is confirmed?
  Can an interrupted or reverted upgrade leave the counter and the running image
  inconsistent in the attacker's favour?
- Version-based downgrade prevention (`MCUBOOT_DOWNGRADE_PREVENTION`) and
  multi-image dependency checks: compare the right images, the right fields,
  in every upgrade mode?
- Revert/test/confirm flows: can the attacker make the bootloader treat an old
  image as the confirmed one?

## Not findings

- Rollback only possible when rollback protection is not configured (state the
  configuration instead, if a default is unsafe).
