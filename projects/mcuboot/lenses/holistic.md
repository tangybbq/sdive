# Lens: holistic (deep dive)

The default lens for **dives**: a careful, function-by-function examination of
the target functions against the *whole* threat model. You have time; depth
beats breadth.

## For each target function

1. **Inputs and their trust.** List every input: parameters, globals, flash
   reads (which slot? which region — header, protected TLVs, unprotected TLVs,
   payload, trailer, scratch?), recovery/SMP request fields, configuration
   macros. For each, decide who can control it, using the flash-write boundary
   and the attacker classes. Follow callers (search for call sites) far enough
   to know what was validated before this function is reached — and do not
   assume a check exists without reading it.
2. **What the function is responsible for.** Which property does correct
   behaviour here protect (P1–P6)? What would an attacker gain if it misbehaved?
3. **Look for the defect.** At minimum:
   - length/offset/index arithmetic on controlled values: overflow, underflow,
     truncation between integer widths, signedness, off-by-one, unchecked
     subtraction;
   - buffers sized by constants but filled by controlled lengths (stack and
     static), reads past the data actually loaded, uninitialized data used or
     copied out;
   - the gap between what is *verified* and what is *used*: bytes executed,
     copied, decrypted or trusted that the signature or hash did not cover;
     values re-read from flash after validation;
   - error paths: return values ignored or misinterpreted, cleanup that runs on
     uninitialized state, fail-open defaults;
   - state handling: decisions based on trailer or status data an attacker can
     write, inconsistent or impossible states, behaviour after power loss mid-way;
   - configuration variants: does the function behave safely in every
     supported `#if` branch, not just the default build?
4. **Decide.** If you have a concrete defect with an attacker path, raise a
   hypothesis. If the function is safe, say why in one line in the unit note,
   and record any invariant worth reusing in the dossier.

## Calibration

- Recall matters more than precision at this stage — an independent verifier
  checks every hypothesis — but every hypothesis must name a concrete defect, a
  concrete path from an attacker-controlled input, the attacker class and the
  property. "Could be risky" is not a hypothesis.
- Apply the scope rulings: fails-closed is not a bypass; pre-auth recovery DoS
  is in scope, self-inflicted corruption is not; data re-validated under the
  trusted key needs the key.
- Mark a unit `partial` when you could not examine it thoroughly. Honest
  coverage is worth more than complete-looking coverage.
