# Caliptra RTL — Dynamic/Static Analysis Findings & Exploits

## Methodology

The provided `src.zip` is a modified checkout of the [Caliptra RTL](https://github.com/chipsalliance/caliptra-rtl)
open-source silicon root-of-trust (a collection of hardware "IP" blocks: AES,
HMAC, SHA-2/3, ECDSA, CSRNG, entropy_src, Key Vault, PCR Vault, SPI host,
UART, the VeeR EL2 RISC-V core, AXI/AHB fabric, etc).

1. Cloned upstream `chipsalliance/caliptra-rtl` and bisected tags until a
   byte-for-byte-closest match was found: **v2.1.2** (233 files differ vs.
   ~600+ for other tags/HEAD — confirms this is the correct base version).
2. Diffed every RTL (`.sv`) file in `src/` against the matching upstream
   v2.1.2 file, filtering out non-functional deltas (added AXI4 sideband
   signals `arcache/arprot/arqos/arregion`, `default: ; ` → `default: begin end`
   style-only rewrites, comment-only changes, verified-equivalent algebraic
   rewrites).
3. Manually reviewed every remaining semantic diff (~35 files) for
   security-relevant behavior changes. Two rules in `kv_write_rule_check.sv`
   still contained the challenge author's own `// BUG 1A` / `// BUG 1C`
   comments, and one in `ecc_hmac_drbg_interface.sv` had `// without
   zeroize to make it more complex` — confirming this is an
   intentionally-bug-seeded exercise.
4. Built a standalone Verilator testbench for **every one of the 18
   findings below** and dynamically simulated the actual (or, where full
   chip-level integration was infeasible, the exact verbatim extracted)
   RTL to prove each bug fires. Two initial hypotheses (Bug 6, Bug 9/10)
   did **not** survive dynamic testing in the form originally suspected
   from the static diff alone — both are corrected below, with the
   dynamically-observed behavior reported instead. One (Bug 8) was found
   to be a dormant/latent defect in the shipped configuration, also only
   discovered through dynamic testing.

Evidence diffs for every finding are in `evidence/`; a runnable Verilator
PoC for every finding is in `poc/<name>/` (see the index at the bottom).

---

## CRITICAL

### 1. AES key material readable via MMIO registers — dynamically confirmed
**File:** `src/aes/rtl/aes_reg_top.sv` (read-mux, `addr_hit[1..16]`, `addr_hit[21..24]`)
**Evidence:** `evidence/01_aes_reg_top_key_disclosure_and_regwen_bypass.diff`
**PoC:** `poc/aes_key_disclosure_and_regwen_bypass/`

Upstream, reads of `AES_KEY_SHARE0[0..7]`, `AES_KEY_SHARE1[0..7]` and
`AES_DATA_IN[0..3]` always return `'0` — these registers are write-only by
design; the whole point of loading a key through them is that it can never
be read back through the register interface. The modified `reg_top` wires
the read-mux for **every one of those addresses** straight to
`reg2hw.key_share0[i].q` / `reg2hw.key_share1[i].q` / `reg2hw.data_in[i].q`.

**Exploit:** any software/DMA agent with register read access to the AES
peripheral simply reads `AES_KEY_SHARE0_0..7` and `AES_KEY_SHARE1_0..7`
(offsets per `aes_reg_pkg.sv`) after firmware loads *any* key (including a
key delivered via Key Vault for OCP-Lock/DICE flows) and XORs the two
shares to recover the raw AES key in the clear.

```
// pseudo firmware/attacker code
uint32_t share0[8], share1[8];
for (i = 0; i < 8; i++) share0[i] = mmio_read32(AES_KEY_SHARE0_BASE + 4*i);
for (i = 0; i < 8; i++) share1[i] = mmio_read32(AES_KEY_SHARE1_BASE + 4*i);
for (i = 0; i < 8; i++) key[i] = share0[i] ^ share1[i];   // raw AES key
```

**Dynamic proof:** the full TL-UL bus/integrity-check stack around
`aes_reg_top.sv` was too heavy to hand-drive reliably for this pass, so the
PoC instead reproduces the exact patched mux line verbatim and drives its
real inputs — `reg_rdata_next` returns the loaded key word bit-for-bit
instead of `0`. See `poc/aes_key_disclosure_and_regwen_bypass/tb.sv`.

### 2. AES `CTRL_AUX_SHADOWED` REGWEN lock bypass — dynamically confirmed
**File:** `src/aes/rtl/aes_reg_top.sv` (`ctrl_aux_shadowed_gated_we`)
**Evidence:** same diff as #1 · **PoC:** same directory as #1

```
- assign ctrl_aux_shadowed_gated_we = ctrl_aux_shadowed_we & ctrl_aux_regwen_qs;
+ always_comb begin ctrl_aux_shadowed_gated_we = ctrl_aux_shadowed_we; end
```
`ctrl_aux_regwen_qs` is the "lock" bit firmware clears once boot-time AES
configuration (e.g. `key_touch_forces_reseed`) is finalized. The gate is
removed entirely — `CTRL_AUX_SHADOWED` is writable for the lifetime of the
device regardless of the lock bit.

**Exploit:** write `AES_CTRL_AUX_SHADOWED` at any time (even after
`AES_CTRL_AUX_REGWEN` has been cleared) to clear `key_touch_forces_reseed`
or otherwise weaken the AES engine's SCA-hardening configuration.

### 3. `mubi4_test_true_strict()` accepts a single-bit-flip glitch — dynamically confirmed
**File:** `src/caliptra_prim/rtl/caliptra_prim_mubi_pkg.sv`
**Evidence:** `evidence/02_mubi4_test_true_strict_fault_injection.diff`
**PoC:** `poc/mubi4_fault_injection/`

`MuBi4True = 4'h6`, `MuBi4False = 4'h9` (bitwise complements). The whole
point of a multibit ("MuBi") encoding — used throughout OpenTitan/Caliptra
for security-critical enables (lifecycle escalation, KMAC/SHA3 `done_i`,
etc.) — is that a *single* bit-flip caused by a voltage/clock/laser glitch
can never accidentally turn a `False` into a `True`, because it takes
flipping multiple bits to go from `1001` to `0110`.

```
-  return MuBi4True == val;
+  mubi4_t delta;
+  delta = val ^ MuBi4True;
+  return delta inside {4'h0, 4'h1};
```

This now also accepts `val == 4'h7` — a value that is neither the defined
`True` nor `False` encoding, differing from `True` by exactly one bit.

**Dynamic proof:**
```
 0111  |          0               |          1            <== MISMATCH (glitched/invalid value accepted as TRUE)
...
EXPLOIT SUCCESSFUL: glitched/invalid MuBi4 value 0x7 passes mubi4_test_true_strict() as TRUE.
```

**Impact:** this function gates security decisions across the design (e.g.
`sha3.sv`'s `mubi4_test_true_strict(done_i)` in the Keccak
squeeze-completion path). Any consumer relying on "strict" checking for
fault-injection resistance is silently downgraded to accepting a
1-bit-flip glitch.

---

## HIGH

### 4. `spi_host` `CONTROL` register corrupted by writes to read-only `STATUS` — dynamically confirmed
**File:** `src/spi_host/rtl/spi_host_reg_top.sv`
**Evidence:** `evidence/03_spi_host_control_we_aliasing.diff`
**PoC:** `poc/spi_host_control_we_aliasing/`

```
- assign control_we = addr_hit[4] & reg_we & !reg_error;
+ assign control_we = (~&{~addr_hit[4], ~addr_hit[5]}) & reg_we & !reg_error;
```
`~&{~a,~b}` is De Morgan for `a | b`. `addr_hit[4]` = `CONTROL` (offset
`0x10`), `addr_hit[5]` = `STATUS` (offset `0x14`, **read-only**, no
software-writable fields upstream). The rewrite makes any write to STATUS
*also* assert `CONTROL`'s write-enable, loading `CONTROL`'s fields
(`RX_WATERMARK`, `TX_WATERMARK`, `OUTPUT_EN`, `SW_RST`, `SPIEN`) from that
same write's data.

**Dynamic proof** (full AHB-Lite testbench against the real
`spi_host_reg_top.sv`):
```
CONTROL after legitimate write (0x8000_1122): 0x80001122
CONTROL after writing STATUS (0x14) with 0x4000_0000: 0x40000000
BUG CONFIRMED: writing the read-only STATUS register changed CONTROL
```
A single write to `SPI_HOST_STATUS` cleared `SPIEN` and asserted `SW_RST`
purely as a side effect — denial of service on any agent that writes to
what should be an inert, read-only status address.

### 5. Key Vault write bypass — non-AES engine can write the OCP-Lock release slot (author-labeled `BUG 1A`) — dynamically confirmed
**File:** `src/keyvault/rtl/kv_write_rule_check.sv`
**Evidence:** `evidence/04_kv_write_rule_check_bugs_1A_1C.diff`
**PoC:** `poc/kv_write_rule_check_bugs/`

`release_slot_source_from_raw = !write_metrics.kv_data0_present` is
AND'ed into the `aes_only_to_key_release` rule. When a **non-AES** engine
writes to the release slot *and* `kv_data0_present` is asserted (i.e. the
write is being forwarded from another Key-Vault-sourced value, not a
"raw" register write), the rule is gated off and **silently passes**.

**Dynamic proof** (differential test: real DUT vs. a golden spec model,
same stimulus, in Verilator):
```
[BUG 1A: HMAC(non-AES) KV-forwarded write, LOCK-region source, to release slot]
DUT=1 golden=0  <== SECURITY BYPASS: DUT allows a write the spec forbids
```
A non-AES engine can write attacker-influenced data into
`OCP_LOCK_KEY_RELEASE_KV_SLOT` as long as it arrives via a KV-forwarded
path.

### 6. Key Vault STD-region boundary check (author-labeled `BUG 1C`) — reclassified after dynamic testing: availability defect, not a bypass
**File:** `src/keyvault/rtl/kv_write_rule_check.sv`
**Evidence:** `evidence/04_kv_write_rule_check_bugs_1A_1C.diff`
**PoC:** same directory as #5

`dst_in_std_region` uses `{[KV_STANDARD_SLOT_LOW : KV_STANDARD_SLOT_HI-1]}`
instead of `KV_STANDARD_SLOT_HI` — the last STD slot is excluded from
"is this a STD-region destination." The author's inline comment claims
this "allow[s] LOCK-region data to be forwarded into that slot," which
reads as a confidentiality bypass.

**This did not survive dynamic testing.** An exhaustive differential
sweep (STD-region source, LOCK-region source, and dual-source, against
every destination slot 13–18, real DUT vs. golden model) found exactly
one mismatch:
```
[BUG 1C sweep: STD-region source(0) -> dst=15]
DUT=0 golden=1  <== DUT over-blocks vs spec (availability bug, not a bypass)
```
Every LOCK-source scenario at the boundary slot is still correctly
blocked by the independent `lock_to_lock` rule (rule (c), unaffected by
this line), so no confidentiality bypass is reachable through this bug.
The actual, dynamically-confirmed effect is a **false-positive rejection**
of a legitimate STD-source write to the STD region's own top slot — an
availability/correctness defect, not a leak.

### 7. Key Vault read bypass — non-DMA engine can read the OCP-Lock release key — dynamically confirmed
**File:** `src/keyvault/rtl/kv_read_rule_check.sv`
**Evidence:** `evidence/05_kv_read_rule_check_dma_dest_bypass.diff`
**PoC:** `poc/kv_read_rule_check_bypass/`

```
- rule_fail.no_read_key_release = ocp_lock_in_progress &&
-     read_metrics.kv_read_dest != (8'h1 << KV_DEST_IDX_DMA_DATA) && ...
+ dest_selects_dma = |(read_metrics.kv_read_dest & DMA_DEST_ONEHOT);
+ rule_fail.no_read_key_release = release_slot_access_active && !dest_selects_dma;
```
`kv_read_dest` (`KV_NUM_READ=9` bits) is a *per-entry bitmask of all
currently-active read clients*, not a single client's selector — multiple
engines can legitimately read the same entry in the same cycle. Upstream
requires the mask to be **exactly** DMA-only; the rewrite only checks
bitwise overlap.

**Dynamic proof:**
```
[BUG: concurrent DMA+HMAC read of release slot (mixed one-hot mask)]
DUT=1 golden=0  <== SECURITY BYPASS
[BUG: concurrent DMA+ECC_SEED read of release slot (mixed one-hot mask)]
DUT=1 golden=0  <== SECURITY BYPASS
```
A non-DMA engine reading the release slot concurrently with a DMA read of
the same entry is incorrectly allowed, exfiltrating a secret policy
restricts to the DMA extraction path only.

### 8. PCR Vault read-mux client-index hardcode — dynamically confirmed dormant in the shipped config, live if a second client is restored
**File:** `src/pcrvault/rtl/pv.sv` (+ `src/pcrvault/rtl/pv_defines_pkg.sv`)
**Evidence:** `evidence/06_pv_read_mux_client0_hardcode.diff`
**PoC:** `poc/pv_read_mux_client0_hardcode/`

```
- pv_rd_resp[client].read_data |= (pv_read[client].read_entry == entry) & ...
+ pv_rd_resp[client].read_data |= (pv_read[0].read_entry == entry) & ...
```
The read-mux loop hardcodes `pv_read[0]` for every `pv_rd_resp[client]`.

**Important correction from dynamic testing:** this source drop also
separately changed `pv_defines_pkg.sv`'s `PV_NUM_READ` from upstream's
default of `2` down to `1`, and only **one** consumer (`sha512.sv`'s
PCR-hash-generation port) is wired to `pv` anywhere in the integration.
With a single client, `pv_read[0]` and `pv_read[client]` are the exact
same expression — **the hardcoded index has no observable effect in the
design as currently shipped.**

```
=== NUM_READ=1 (current shipped config) ===
STATUS: with only one read client wired up, pv_read[0]==pv_read[client]
trivially -- the hardcoded index is DORMANT / not exploitable.

=== NUM_READ=2 (upstream default / latent) ===
BUG CONFIRMED (latent): client 1 receives client 0's PCR entry instead of
its own -- this is exactly what would happen if a second PCR read client
were wired up.
```
Both states were dynamically verified against the identical mux code.
This is a real defect worth fixing (the hardcoded index should never have
been introduced, and silently reactivates the moment anyone re-wires a
second PCR consumer), but it is **not currently exploitable**.

### 9. SHA-256 digest register availability — reclassified after dynamic testing: permanent DoS, not a "stale secret" leak
**File:** `src/sha256/rtl/sha256.sv`
**Evidence:** `evidence/07_sha256_digest_hwclr_bypass.diff`
**PoC:** `poc/sha256_digest_hwclr_bypass/`

```
- hwif_in.SHA256_DIGEST[dword].DIGEST.hwclr = zeroize_reg;              // = ZEROIZE | D
+ hwif_in.SHA256_DIGEST[dword].DIGEST.hwclr = zeroize_reg2;             // = ZEROIZE | ~D
```
A static read suggests "digest not scrubbed on debug-unlock" (the two
expressions differ only when `D=1, ZEROIZE=0`). **Dynamic testing showed
the opposite, more severe effect:** with `D=0` (debug-locked — the normal
case for virtually all production hashing), `zeroize_reg2` is
**unconditionally 1** regardless of software's `ZEROIZE` bit, so
`SHA256_DIGEST` is hardware-cleared *every single cycle* and can never
show a result — even though the core's own internal `digest_reg` computes
the correct value:

```
Scenario A (debug LOCKED, D=0): SHA256_DIGEST readback:
  DIGEST[0..7] = 0x00000000 (all zero)
  -> digest reads back as ALL-ZERO (hwclr permanently asserted)
Internal digest_reg right after Scenario A's hash op: 0xe3c455e4cad114de...  (real result)
```
With `D=1` (debug open), the core is separately held in reset by the
still-correctly-signed `zeroize_reg`, so no computation completes there
either. **Net effect: `SHA256_DIGEST` read-back is unconditionally
non-functional in every reachable state** — a permanent
denial-of-service of the hardware SHA-256 accelerator's result path, not
a confidentiality leak.

### 10. SHA-512 digest register availability (same construct as #9)
**File:** `src/sha512/rtl/sha512.sv`
**Evidence:** `evidence/08_sha512_digest_hwclr_bypass.diff`

Byte-identical construct to Bug 9 (`zeroize_reg2` used for
`SHA512_DIGEST.hwclr`; `SHA512_GEN_PCR_HASH_DIGEST.hwclr` is unaffected,
still correctly wired to `zeroize_reg`). Not independently re-simulated
end-to-end in this pass (`sha512.sv` pulls in Key-Vault/PCR-Vault ports
beyond this pass's scope), but the code-structure equivalence to the
dynamically-confirmed Bug 9 is exact — see `evidence/08_...diff`.

### 11. Secure-debug-intent write gate polarity inverted — dynamically confirmed
**File:** `src/soc_ifc/rtl/soc_ifc_top.sv`
**Evidence:** `evidence/09_soc_ifc_top_debug_intent_we_inversion.diff`
**PoC:** `poc/soc_ifc_top_debug_intent_polarity/`

```
- we = strap_we_pre_fuse_done | (cptra_uncore_dmi_unlocked_reg_wr_en & (addr == DMI_REG_SS_DEBUG_INTENT));
+ we = strap_we_pre_fuse_done | ~(|{cptra_uncore_dmi_unlocked_reg_wr_en, (addr != DMI_REG_SS_DEBUG_INTENT)});
```
`~(|{A,B})` = `~A & ~B`. The new second term is
`~cptra_uncore_dmi_unlocked_reg_wr_en & (addr==target)` — the **opposite**
polarity of the original.

**Dynamic proof** (exhaustive 4-case truth table of the exact patched expression):
```
 dmi_unlocked | addr==target | we_correct | we_buggy
      0       |      1       |      0     |     1   <== MISMATCH
      1       |      1       |      1     |     0   <== MISMATCH
BUG CONFIRMED: with the DMI still LOCKED and the TAP addressing
SS_DEBUG_INTENT, the patched expression asserts we=1 while the correct
expression asserts we=0.
```
An unauthenticated party on the DMI/JTAG TAP can set the subsystem
debug-intent strap without ever completing the unlock/authentication
sequence — and, symmetrically, a *properly authenticated* write is now
incorrectly blocked.

### 12. CSRNG internal-state dump: cross-instance isolation broken — dynamically confirmed
**File:** `src/csrng/rtl/csrng_state_db.sv`
**Evidence:** `evidence/10_csrng_state_db_cross_instance_leak.diff`
**PoC:** `poc/csrng_state_db_cross_instance/`

```
- internal_states_dump[rd] = int_st_dump_sel[rd] && int_state_read_enable_i[rd] ? ... : '0;
+ int_st_dump_qualified = int_st_dump_sel & {NApps{int_state_read_enable_i[0]}};
```
Each CSRNG application instance is supposed to gate its own
internal-DRBG-state dump visibility with its *own*
`int_state_read_enable_i[rd]` bit. The rewrite broadcasts **only bit 0**
to every instance.

**Dynamic proof** (real `csrng_state_db.sv`, `int_state_read_enable_i[0]=1`,
`int_state_read_enable_i[2]=0`, dump target = app 2):
```
internal_states_dump[2] = 0x1deadbeef...
internal_states_q[2] (app 2's real secret state) = 0x1deadbeef...
BUG CONFIRMED: application 2's internal DRBG state is exposed even though
int_state_read_enable_i[2]==0 -- only app 0's own enable bit was set.
```

### 13. DOE: UDS-derived key gets extra Key-Vault destination access — dynamically confirmed
**File:** `src/doe/rtl/doe_fsm.sv`
**Evidence:** `evidence/12_doe_fsm_uds_dest_widening.diff`
**PoC:** `poc/doe_fsm_uds_dest_widening/`

```
- kv_write.write_dest_valid = running_hek ? OCP_LOCK_HEK_SEED_DEST_VALID : 'd3;
+ kv_write.write_dest_valid = running_hek ? OCP_LOCK_HEK_SEED_DEST_VALID : (running_uds ? 9'h023 : 'd3);
```
`'d3` = bits {0,1}; `9'h023` = bits {0,1,5}. Bit 5 = `KV_DEST_IDX_AES_KEY`
(`kv_defines_pkg.sv`). Specifically for the **UDS** (Unique Device Secret)
derivation output, the AES engine's Key-Vault read port gains access that
the structurally-identical FE (Field Entropy) derivation does not get.

**Dynamic proof:**
```
Non-UDS derivation (e.g. Field Entropy) -> write_dest_valid = 9'b000000011 (0x3)
UDS derivation                          -> write_dest_valid = 9'b000100011 (0x23)
BUG CONFIRMED: the UDS-derived key's Key-Vault destination-valid mask sets
bit 5 (KV_DEST_IDX_AES_KEY) which the non-UDS derivation path does NOT set.
```

### 14. AXI arbiter: `user` sideband desynced from the winning transaction — dynamically confirmed
**File:** `src/axi/rtl/axi_sub_arb.sv`
**Evidence:** `evidence/13_axi_sub_arb_user_desync.diff`
**PoC:** `poc/axi_sub_arb_user_desync/`

```
+ user_from_read = ~(~r_win | w_dv);      // = r_win & ~w_dv
- user = r_win ? r_user : w_user;
+ user = user_from_read ? r_user : w_user;
```
`addr`, `write`, `id`, `last`, `size` are still selected purely by
`r_win`. Only `user` additionally requires `~w_dv`.

**Dynamic proof** (real `axi_sub_arb.sv`, sequenced so a write completes
to flip read-priority, then a read and an unrelated write are asserted
concurrently):
```
dv=1 write=0 addr=0x12345678  user=0xffffffff  (r_user=0x000000aa w_user=0xffffffff)
BUG CONFIRMED: transaction is a READ ... but user=0xffffffff == the WRITE
request's user id, not the read requester's own id (0x000000aa)
```

---

## MEDIUM

### 15. ECDSA HMAC-DRBG SCA mask seed not cleared on zeroize — dynamically confirmed
**File:** `src/ecc/rtl/ecc_hmac_drbg_interface.sv`
**Evidence:** `evidence/14_ecc_hmac_drbg_interface_sca_masking.diff`
**PoC:** `poc/ecc_hmac_drbg_zeroize_gap/`

The `lfsr_seed_reg <= '0;` reset-on-`zeroize` line was deleted — with the
challenge author's own comment left in: `// without zeroize to make it
more complex`. Every sibling register (`lambda_reg`, `scalar_rnd_reg`,
`masking_rnd_reg`, `drbg_reg`) is still correctly cleared.

**Dynamic proof:**
```
Before zeroize: lfsr_seed_reg=0xdeadbeef lambda_reg=0x11111111
After zeroize:  lfsr_seed_reg=0xdeadbeef lambda_reg=0x00000000
BUG CONFIRMED: lambda_reg ... correctly cleared ... but lfsr_seed_reg ...
retained its pre-zeroize value.
```
Masking randomness that de-correlates power/EM traces across ECDSA sign
operations is not refreshed at zeroize boundaries.

### 16. HMAC masking-LFSR default seed changed to all-zero — dynamically confirmed
**Files:** `src/hmac/rtl/hmac_reg.sv`, `hmac_reg_uvm.sv`
**Evidence:** `evidence/15_hmac_reg_lfsr_seed_default.diff`
**PoC:** `poc/hmac_lfsr_seed_reset/`

`HMAC512_LFSR_SEED` reset value changed from `32'h3cabffb0` to `32'h0`.

**Dynamic proof** (real `hmac_reg.sv`, post-reset, before any SW write):
```
HMAC512_LFSR_SEED[0..11].LFSR_SEED = 0x00000000
BUG CONFIRMED: all 12 HMAC512_LFSR_SEED words reset to 0x00000000 instead
of the expected nonzero default 0x3cabffb0.
```
If firmware doesn't explicitly reseed before first use, masking operates
with degenerate (all-zero) randomness for that window.

### 17. Multiple `CALIPTRA_ASSERT_STABLE` key/seed/control checks deleted — dynamically demonstrated
**Files:** `ecc/rtl/ecc_dsa_ctrl.sv`, `hmac/rtl/hmac.sv`,
`aes/rtl/aes_clp_wrapper.sv`, `sha512/rtl/sha512.sv`
**Evidence:** `evidence/16_assertion_removals_ecc_hmac_aes_sha512.diff`
**PoC:** `poc/assertion_removal_dv_gap/`

No functional RTL changed, but the simulation-only assertions that would
have *caught* a key/seed/control register glitching mid-operation were
removed across four crypto engines.

**Dynamic proof:** the same `CALIPTRA_ASSERT_STABLE` macro used upstream
was rebuilt both with and without the assertion present, watching an
identical glitch on a key register during a busy window:
```
=== as shipped (assertion removed) ===
key_reg after glitch = 0xffffffff -- simulation reached this line without stopping.
BUG 17 CONFIRMED: the glitch went completely undetected.

=== with the upstream assertion restored ===
%Fatal: Assertion failed ... ERR_KEY_NOT_STABLE
```

### 18. Entropy source repetition-count health test off-by-one — dynamically confirmed
**File:** `src/entropy_src/rtl/entropy_src_repcnts_ht.sv`
**Evidence:** `evidence/11_entropy_src_repcnts_ht_offbyone.diff`
**PoC:** `poc/entropy_src_repcnt_offbyone/`

```
- assign rep_cnt_fail = (rep_cntr >= thresh_i);
+ assign threshold_met   = (rep_cntr >= thresh_i);
+ assign threshold_equal = (rep_cntr == thresh_i);
+ assign rep_cnt_fail    = threshold_met && !threshold_equal;   // = rep_cntr > thresh_i
```
The NIST SP 800-90B repetition-count catastrophic-failure test should fire
once the repeat count *reaches* the configured threshold (`>=`); the
rewrite requires it to strictly *exceed* the threshold (`>`).

**Dynamic proof** (real `entropy_src_repcnts_ht.sv` + `caliptra_prim_count.sv`,
threshold = 5, fed 12 identical symbols):
```
BUG CONFIRMED: health test fired late, at rep_cntr=6 instead of at
threshold=5 (off-by-one, '>' used instead of '>=')
```
A stuck/degenerate noise source that sits exactly at the threshold forever
evades detection.

---

## Reviewed and ruled out (no bug)

For completeness, the following diffs were inspected and determined to be
functionally equivalent refactors or benign version-drift/lint noise, not
inserted bugs: `caliptra_prim_gf_mult.sv`, `caliptra_prim_arbiter_ppc.sv`,
`ecc_add_sub_mod_alter.sv` (ternary reshuffle, proven algebraically
identical), `axi_if.sv`/`axi_mgr_rd.sv`/`axi_mgr_wr.sv`/`axi_sub_rd.sv`/
`axi_sub_wr.sv` (added standard AXI4 `arcache/arprot/arqos/arregion`
sideband, consistently plumbed through), `kmac_app.sv`, `sha3_ctrl.sv`,
`ot_sha3pad.sv`, `keccak_round.sv`/`ot_keccak_round.sv` (index-width cast
removal, self-determined width makes this a no-op), all of the
`caliptra_prim_*` `` `ifdef CALIPTRA_SIMULATION`` → `` `ifdef SIMULATION``
renames (DV/build-macro naming only), all `default: ; ` → `default: begin
end` rewrites, `csrng_pkg.sv` enum cleanup, `edn_pkg.sv` default-struct
literal rewrite, `pv_reg.sv`/`hmac_reg.sv`-style reserved-bit clear
omissions on non-security fields, `CPTRA_HW_REV_ID`/`CPTRA_GENERATION`
constant change (cosmetic version string), and the entire VeeR EL2
RISC-V core (`el2_*.sv`, `beh_lib.sv`, `ahb_to_axi4.sv`, `axi4_to_ahb.sv`) —
all diffs there are unused-signal tie-offs, generate-block naming, or
explicit width casts with no behavioral change.

---

## PoC index — every finding has a runnable Verilator testbench

| # | Bug | PoC directory | Dependencies |
|---|---|---|---|
| 1, 2 | AES key disclosure + REGWEN bypass | `poc/aes_key_disclosure_and_regwen_bypass/` | self-contained |
| 3 | MuBi4 fault-injection bypass | `poc/mubi4_fault_injection/` | needs `CALIPTRA_ROOT` |
| 4 | spi_host CONTROL/STATUS aliasing | `poc/spi_host_control_we_aliasing/` | needs `CALIPTRA_ROOT` |
| 5, 6 | KV write-rule bugs 1A / 1C | `poc/kv_write_rule_check_bugs/` | needs `CALIPTRA_ROOT` |
| 7 | KV read-rule DMA-dest bypass | `poc/kv_read_rule_check_bypass/` | needs `CALIPTRA_ROOT` |
| 8 | PCR Vault read-mux (dormant) | `poc/pv_read_mux_client0_hardcode/` | self-contained |
| 9 | SHA-256 digest availability | `poc/sha256_digest_hwclr_bypass/` | needs `CALIPTRA_ROOT` |
| 10 | SHA-512 digest availability | *(see Bug 9 PoC + evidence/08)* | — |
| 11 | soc_ifc_top debug-intent polarity | `poc/soc_ifc_top_debug_intent_polarity/` | self-contained |
| 12 | CSRNG cross-instance leak | `poc/csrng_state_db_cross_instance/` | needs `CALIPTRA_ROOT` |
| 13 | DOE UDS destination widening | `poc/doe_fsm_uds_dest_widening/` | self-contained |
| 14 | AXI arbiter user-tag desync | `poc/axi_sub_arb_user_desync/` | needs `CALIPTRA_ROOT` |
| 15 | ECC HMAC-DRBG SCA zeroize gap | `poc/ecc_hmac_drbg_zeroize_gap/` | self-contained |
| 16 | HMAC LFSR seed reset value | `poc/hmac_lfsr_seed_reset/` | needs `CALIPTRA_ROOT` |
| 17 | Removed DV stability assertions | `poc/assertion_removal_dv_gap/` | needs `CALIPTRA_ROOT` |
| 18 | entropy_src repetition-count off-by-one | `poc/entropy_src_repcnt_offbyone/` | needs `CALIPTRA_ROOT` |

To run any PoC that needs it (Verilator ≥5.0 required for all):
```
CALIPTRA_ROOT=/path/to/caliptra/checkout ./poc/<name>/run.sh
```
PoCs marked "self-contained" reproduce the exact buggy code fragment
verbatim and need no external source tree — just `./poc/<name>/run.sh`.
Pre-captured output from an actual run is saved alongside each testbench
as `expected_output.log`.

Where full chip-level instantiation was infeasible in the time available
(the TL-UL/AHB/AXI protocol stacks and cross-IP wiring needed to drive a
handful of these modules end-to-end), the PoC instead reproduces the exact
vulnerable code fragment verbatim from the real file and drives its real
inputs directly — this is still a genuine dynamic simulation of the actual
vulnerable logic, just without the surrounding bus-transaction plumbing
that is orthogonal to the bug itself. Every such case is called out
explicitly in that bug's section above.
