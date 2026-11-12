# Lens: image authenticity and attestation (P1, P5)

Can an image run, or be measured, without a valid signature over exactly what
runs? Think like an attacker who can write any bytes to the slots they can
reach (flash-write boundary) but has no private key.

## Questions

- **Coverage:** exactly which bytes does the hash cover (header, protected TLVs,
  payload)? Which bytes are then executed, copied, decompressed, decrypted or
  used for decisions? Any byte used but not covered is a lead.
- **TLV handling:** protected vs unprotected TLVs — which decisions consume
  unprotected TLVs? Duplicate TLVs, unexpected TLV order, zero/huge lengths,
  TLV areas overlapping each other or the payload.
- **Signature and key selection:** how is the key chosen (key hash, index, built-in
  or hardware key)? Can the attacker influence which key, or skip the check by
  presenting zero or several signatures? What happens with unknown TLV types?
- **Decision flow:** every way `validate` can return — are all failures fatal?
  Fault-injection-hardened returns (`FIH_*`): any path where a failure value is
  lost or a success value is set early? Default-success initializations.
- **Time of check vs time of use:** is the image re-read from flash after
  validation (e.g. during copy, RAM load, or decryption) where the attacker
  could change it in between?
- **Modes:** swap modes, overwrite-only, direct-XIP, RAM load, multi-image and
  dependency checks — does each mode validate what it boots?
- **Attestation (P5):** do boot records and shared data describe the image that
  actually booted, with values taken from validated data?

## Not findings

- Paths that end in a rejected boot (fails closed).
- Manipulating signed fields without the key.
