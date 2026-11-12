# Lens: key and plaintext confidentiality (P3, P4)

Encrypted images: the bootloader holds a private key (or a device-derived key)
and produces AES keys and plaintext. Can any of it leave the trust boundary, or
can an attacker learn plaintext they should not?

## Questions

- **Key unwrap / key exchange:** are TLV lengths and formats checked before
  use? Are MAC/tag checks done before decrypting, and compared in constant
  time? What happens on every failure path?
- **Residue:** private keys, derived keys, shared secrets and plaintext buffers
  on the stack or in static memory — are they zeroized after use, on success
  *and* on error paths, before jumping to the application?
- **Plaintext exposure:** can decrypted data be written to a slot or region the
  application or an attacker can read when it should stay encrypted (e.g. during
  swap, revert, recovery, RAM load)? Can a failed or interrupted operation leave
  plaintext behind?
- **Oracles:** do error codes, logs or timing reveal key or plaintext
  information to an attacker who can submit images?
- **Reference libraries:** confirm what crypto API calls actually check
  (lengths, return codes) in the library version used, rather than assuming.

## Notes

- Per the threat model, P3 stands on its own: missing zeroization is reportable
  (low) even without a known exfiltration channel.
