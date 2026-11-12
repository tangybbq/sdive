# MCUboot threat model — security properties, attacker classes, scope rulings

<!--
Derived from ../zepsec/threat-model.md (sha256 40afea81f19b6cb6, zepsec
e19af28) with every reference to a specific finding removed: no finding IDs,
and none of the per-finding re-dispositions. Analysis agents read this file,
so it must not hint at known bugs (blind benchmarking depends on it). It is
also the first draft of a public threat model for MCUboot's documentation
(PLAN.md, "Threat model upstreaming"). Keep the substance in step with the
zepsec original; add rules here only in general form.
-->

Every verdict must **name the security property violated and the attacker
class required**. A defect that violates no property below, or that needs an
attacker more capable than the one that can reach it, is not a vulnerability.

## Security properties (the assets we defend)

- **P1 Image authenticity** — only an image whose signature verifies against the
  provisioned trusted key executes. Violation = secure-boot bypass (critical).
- **P2 Anti-rollback** — with hardware rollback protection on, an image below
  the stored non-volatile security counter is rejected.
- **P3 Key confidentiality** — image-encryption and device-derived keys never
  leave the bootloader trust boundary. *A property in its own right — not
  contingent on a currently-open exfiltration channel.*
- **P4 Encrypted-image plaintext confidentiality.**
- **P5 Attestation integrity** — measured-boot records reflect the image that
  actually booted.
- **P6 Availability of the boot/recovery path** — best effort: a **pre-auth DoS
  reachable by the unauthenticated recovery attacker is in scope**;
  self-inflicted corruption that fails closed at the next boot is **not**.

## Attacker classes (capabilities)

- **A1 Remote/logical** — presents images/data over a product-exposed interface
  (e.g. an application-level firmware update); cannot toggle recovery straps.
- **A2 Recovery/DFU** — drives serial recovery / SMP (often physical-pin-gated).
  Serial recovery is **unauthenticated by design**: "can stage an image to a
  writable slot" is *granted*, not a finding. The findings are **escaping the
  writable region**, or **defeating the next boot's P1/P2 check**.
- **A3 Physical** — direct external-flash read/write, fault injection, JTAG.
  Fault-injection (FIH/glitch) resistance is **defense in depth**, not a
  guaranteed property.

## The load-bearing rule — the flash-write boundary

**The secondary slot (slot 1) and scratch — including their trailers and
metadata — are attacker-writable under A1/A2** (that is what an upload *is*).
**The primary slot (slot 0) is not, absent A3 or prior code execution** —
*except* under serial recovery (below). Therefore bootloader logic that
**trusts metadata read from an attacker-writable trailer** before, or
independently of, signature verification is a **real vulnerability** for the
attacker who can write it; the same logic reading a trailer only an A3 attacker
can write is gated on the stronger A3 (usually low or out of scope). This
boundary is **source-checkable**: decide it from the code, not from experiment.

### Serial-recovery exception

**Under `MCUBOOT_SERIAL_RECOVERY`, a serial-recovery image upload writes to the
*primary* slot**, not the secondary, from offset 0 and bounded only by the
area size — so it **can write the primary slot's trailer**. In serial-recovery
configurations the primary trailer is therefore A2-writable. When applying the
flash-write boundary, check which slot a trusted trailer actually sits in and
whether any configured write path (upload, recovery, swap) can reach it; the
answer is not always "the secondary".

## Scope rulings

- **DoS** — only a **pre-auth** DoS reachable by the unauthenticated recovery
  attacker (A2, P6) is in scope. Self-inflicted slot corruption that **fails
  closed** at the next boot is not a finding (the boot signature check catches
  it).
- **Defense in depth** — P3 (and fault-injection resistance) stand on their
  own. "No exfiltration channel is open today" is an accident of the current
  environment, not a fix; a confirmed P3 omission (e.g. key material left
  unzeroized) is reportable at low severity even without an open channel.
- **Fails closed ≠ bypass** — a path that ends in a rejected boot is not a P1/P2
  violation.
- **Post-authentication manipulation of signed data needs the key** —
  manipulating data that is re-validated under the trusted key afterwards is not
  an A1/A2 finding absent a key compromise.
- **Configuration matters** — state which configuration options a finding
  requires (upgrade mode, encryption, serial recovery, hardware keys, build
  type, …) and whether those are realistic for shipped products.
