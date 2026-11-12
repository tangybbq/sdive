# Lens: memory safety on attacker-controlled data

Find out-of-bounds reads and writes, integer errors and uninitialized memory
that an attacker can drive. Image headers, TLV areas, trailers and recovery
requests are the main sources of attacker-controlled sizes and offsets.

## Questions

- Where does each length, offset, count or index come from, and is it bounded
  *before* use — on every path, in every configuration?
- Integer arithmetic on those values: can `a + b` wrap, `a - b` underflow, a
  32-bit value truncate into 16 or 8 bits, a signed value go negative and pass an
  unsigned check (or vice versa)?
- Fixed-size buffers (stack, static, struct members): can a controlled length
  exceed them? Is the copy bounded by the destination or by the source's claim?
- Reads: can parsing walk past the end of the data actually read from flash, or
  past the end of the flash area?
- Uninitialized memory: is any buffer or struct used, hashed, compared or copied
  out before every byte is written?
- Pointers and lifetimes: NULL or stale pointers on error paths; use after the
  backing flash area was closed.
- Recursion and stack depth driven by attacker-controlled nesting.

## Not findings

- Bounds that are enforced earlier on every path (cite the check).
- Overflows only possible with values an A3 attacker controls, unless the lens
  run is explicitly about A3 — say so and lower confidence.
