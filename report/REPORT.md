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
   security-relevant behavior changes. Two files (`kv_write_rule_check.sv`)
   still contained the challenge author's own `// BUG 1A` / `// BUG 1C`
   comments, confirming this is an intentionally-bug-seeded exercise.
4. For the two most self-contained bugs, built standalone Verilator
   testbenches (`poc/`) and **dynamically simulated** the actual RTL to prove
   the bug fires. The rest are backed by exact line/diff evidence and a
   written exploit procedure (register-level PoC), since exercising them
   requires the full chip-level Caliptra harness (firmware ROM, AXI/AHB
   fabric, KV wiring) that is not included in the provided source drop.

Evidence diffs for every finding below are in `evidence/`.

---

## CRITICAL

### 1. AES key material readable via MMIO registers
**File:** `src/aes/rtl/aes_reg_top.sv` (read-mux, `addr_hit[1..16]`, `addr_hit[21..24]`)
**Evidence:** `evidence/01_aes_reg_top_key_disclosure_and_regwen_bypass.diff`

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
shares to recover the raw AES key in the clear. This defeats the entire
purpose of using a masked hardware AES core to keep key material out of
reach of software.

```
// pseudo firmware/attacker code
uint32_t share0[8], share1[8];
for (i = 0; i < 8; i++) share0[i] = mmio_read32(AES_KEY_SHARE0_BASE + 4*i);
for (i = 0; i < 8; i++) share1[i] = mmio_read32(AES_KEY_SHARE1_BASE + 4*i);
for (i = 0; i < 8; i++) key[i] = share0[i] ^ share1[i];   // raw AES key
```

### 2. AES `CTRL_AUX_SHADOWED` REGWEN lock bypass
**File:** `src/aes/rtl/aes_reg_top.sv` (`ctrl_aux_shadowed_gated_we`)
**Evidence:** same diff as #1

```
- assign ctrl_aux_shadowed_gated_we = ctrl_aux_shadowed_we & ctrl_aux_regwen_qs;
+ always_comb begin ctrl_aux_shadowed_gated_we = ctrl_aux_shadowed_we; end
```
`ctrl_aux_regwen_qs` is the "lock" bit firmware clears once boot-time AES
configuration (e.g. `key_touch_forces_reseed`) is finalized, so later
(potentially attacker-controlled) code can't weaken it. The gate is
removed entirely — `CTRL_AUX_SHADOWED` is writable for the lifetime of the
device regardless of the lock bit.

**Exploit:** write `AES_CTRL_AUX_SHADOWED` at any time (even after
`AES_CTRL_AUX_REGWEN` has been cleared) to clear `key_touch_forces_reseed`
or otherwise weaken the AES engine's SCA-hardening configuration.

### 3. `mubi4_test_true_strict()` accepts a single-bit-flip glitch — **fault-injection countermeasure defeated (dynamically verified)**
**File:** `src/caliptra_prim/rtl/caliptra_prim_mubi_pkg.sv`
**Evidence:** `evidence/02_mubi4_test_true_strict_fault_injection.diff`, PoC in `poc/mubi4_fault_injection/`

`MuBi4True = 4'h6`, `MuBi4False = 4'h9` (bitwise complements). The whole
point of a multibit ("MuBi") encoding — used throughout OpenTitan/Caliptra
for security-critical enables (lifecycle escalation, KMAC/SHA3 `done_i`,
etc.) — is that a *single* bit-flip caused by a voltage/clock/laser glitch
can never accidentally turn a `False` into a `True`, because it takes
flipping multiple bits to go from `1001` to `0110`. The "strict" check is
specifically the one security code is supposed to call to get this
protection:

```
-  function automatic logic mubi4_test_true_strict(mubi4_t val);
-    return MuBi4True == val;
-  endfunction : mubi4_test_true_strict
+  function automatic logic mubi4_test_true_strict(mubi4_t val);
+    mubi4_t delta;
+    delta = val ^ MuBi4True;
+    return delta inside {4'h0, 4'h1};
+  endfunction : mubi4_test_true_strict
```

This now also accepts `delta == 4'h1`, i.e. `val == 4'h7` — a value that is
neither the defined `True` nor `False` encoding, differing from `True` by
exactly one bit. **A single-bit fault injection on bit 0 of a MuBi4 `True`
signal is silently accepted as legitimate `True`.**

**Dynamic proof** (`poc/mubi4_fault_injection/tb.sv`, run with Verilator):
```
MuBi4True  = 0110 (0x6)
MuBi4False = 1001 (0x9)
 0111  |          0               |          1            <== MISMATCH (glitched/invalid value accepted as TRUE)
...
Fault-injection scenario: single-bit-flip of MuBi4True (0x6) -> glitched value 0x7
EXPLOIT SUCCESSFUL: glitched/invalid MuBi4 value 0x7 passes mubi4_test_true_strict() as TRUE.
```

**Impact:** this function gates security decisions across the design (e.g.
`sha3.sv`'s `caliptra_prim_mubi_pkg::mubi4_test_true_strict(done_i)` in the
Keccak squeeze-completion path, lifecycle-escalation checks elsewhere). Any
consumer relying on "strict" checking for fault-injection resistance is
silently downgraded to accepting a 1-bit-flip glitch, which is exactly the
class of attack (EM/voltage/clock glitching) multibit encoding exists to
stop.

---

## HIGH

### 4. `spi_host` `CONTROL` register corrupted by writes to read-only `STATUS`
**File:** `src/spi_host/rtl/spi_host_reg_top.sv`
**Evidence:** `evidence/03_spi_host_control_we_aliasing.diff`

```
- assign control_we = addr_hit[4] & reg_we & !reg_error;
+ assign control_we = (~&{~addr_hit[4], ~addr_hit[5]}) & reg_we & !reg_error;
```
`~&{~a,~b}` is De Morgan for `a | b`. `addr_hit[4]` = `CONTROL` (offset
`0x10`), `addr_hit[5]` = `STATUS` (offset `0x14`, **read-only**: txqd,
rxqd, active, ready, etc. — has no software-writable fields at all
upstream). The rewrite makes any write transaction that targets the
STATUS address *also* assert `CONTROL`'s write-enable, loading
`CONTROL`'s fields (`RX_WATERMARK`, `TX_WATERMARK`, `OUTPUT_EN`, `SW_RST`,
`SPIEN`) from that same write's data.

**Exploit (register sequence):** issue a single AHB-Lite write to
`SPI_HOST_STATUS` (offset `0x14`) with `wdata = 32'hC000_0000` (bits 31/30
set). Because `control_we` fires on this address too:
- bit 31 → `CONTROL.SPIEN = 0` — disables the SPI host mid-transaction
  (e.g. during a SPI-flash firmware/measurement read at boot), or
- bit 30 → `CONTROL.SW_RST = 1` — resets the SPI host FSM/FIFOs,
- bits 15:0 also silently reprogram the RX/TX FIFO watermark thresholds
  used to drive interrupts/DMA.

This is a denial-of-service / control-corruption primitive triggerable by
any agent that can write to what should be an inert, read-only status
address.

### 5–6. Key Vault write-rule bypasses (author-labeled `BUG 1A`, `BUG 1C`)
**File:** `src/keyvault/rtl/kv_write_rule_check.sv`
**Evidence:** `evidence/04_kv_write_rule_check_bugs_1A_1C.diff`

These rules are supposed to isolate the "OCP Lock key release" slot so
only the AES engine (performing the sanctioned ECB(MDK) release-key
unwrap) can ever write it, and to prevent OCP-Lock-region data from being
written into the standard-region and vice versa.

* **BUG 1A** — `release_slot_source_from_raw = !write_metrics.kv_data0_present`
  is AND'ed into the `aes_only_to_key_release` rule. When a **non-AES**
  engine writes to the release slot *and* `kv_data0_present` is asserted
  (i.e. the write is being forwarded from another Key-Vault-sourced
  value, not a "raw" register write), the rule is gated off and
  **silently passes** — a non-AES engine can write attacker-influenced
  data into `OCP_LOCK_KEY_RELEASE_KV_SLOT` as long as it arrives via a
  KV-forwarded path.

* **BUG 1C** — `dst_in_std_region` uses
  `{[KV_STANDARD_SLOT_LOW : KV_STANDARD_SLOT_HI-1]}` instead of
  `KV_STANDARD_SLOT_HI`. The last slot of the standard region is
  excluded from "is this a standard-region destination" — so a write
  whose *source* is in the OCP-Lock region can target that boundary slot
  without tripping `std_to_std`, letting LOCK-region secret data leak
  into a slot that standard (non-privileged) consumers can read.

**Exploit:** trigger a KV write where `kv_write_entry` is the boundary
slot `KV_STANDARD_SLOT_HI` while a data source flagged
`kv_data1_present && kv_data1_entry` in the LOCK region is active during
`ocp_lock_in_progress` — `lock_to_lock`/`std_to_std` never fire and the
secret is committed to a standard-region slot readable by ordinary
crypto clients.

### 7. Key Vault read-rule bypass: non-DMA engine can read the OCP-Lock release key
**File:** `src/keyvault/rtl/kv_read_rule_check.sv`
**Evidence:** `evidence/05_kv_read_rule_check_dma_dest_bypass.diff`

```
- rule_fail.no_read_key_release = ocp_lock_in_progress &&
-     read_metrics.kv_read_dest != (8'h1 << KV_DEST_IDX_DMA_DATA) &&
-     read_metrics.kv_key_entry == OCP_LOCK_KEY_RELEASE_KV_SLOT;
+ dest_selects_dma = |(read_metrics.kv_read_dest & DMA_DEST_ONEHOT);
+ rule_fail.no_read_key_release = release_slot_access_active && !dest_selects_dma;
```
`kv_read_dest` (`kv_defines_pkg.sv`, `KV_NUM_READ=9` bits) is a *per-entry
bitmask of all currently-active read clients*, not a single client's
selector — multiple engines can legitimately read the same entry in the
same cycle. The original rule required the mask to be **exactly**
DMA-only (`!=` exact match) — any concurrent second reader caused failure.
The rewrite only checks that the DMA bit is *one of* the set bits
(bitwise AND/OR instead of exact equality).

**Exploit:** while `ocp_lock_in_progress`, issue a read of
`OCP_LOCK_KEY_RELEASE_KV_SLOT` simultaneously from the DMA data path *and*
from another engine (e.g. HMAC) targeting the same entry. `dest_selects_dma`
is true (DMA bit is set) so the rule never fires, and the non-DMA engine's
read of the release-key slot is allowed to proceed — exfiltrating a secret
that policy says only the DMA extraction path may touch.

### 8. PCR Vault: every read client gets client-0's data (cross-client leak)
**File:** `src/pcrvault/rtl/pv.sv`
**Evidence:** `evidence/06_pv_read_mux_client0_hardcode.diff`

```
- pv_rd_resp[client].read_data |= (pv_read[client].read_entry == entry) & ...
+ pv_rd_resp[client].read_data |= (pv_read[0].read_entry == entry) & ...
```
The `for (int client...)` read-mux loop was rewritten to index `pv_read[0]`
literally, for *every* `client` in `pv_rd_resp[client]`. Every PCR read
port now returns data selected by client 0's `read_entry`/`read_offset`,
regardless of what entry the actual requesting client asked for.

**Exploit:** have any read client (e.g. `client==3`) request its own PCR
entry while another client (`client==0`, e.g. the internal gen-hash
engine) is mid-read of a *different*, more sensitive PCR entry — client 3
receives client 0's PCR value instead of its own. Compounded by finding
#15 below (`pv_gen_hash.sv` no longer clears `read_entry`/`read_offset` on
`zeroize`), client 0's stale selection continues to leak post-zeroize.

### 9–10. SHA-256/SHA-512 digest not scrubbed on debug-unlock / scan-mode entry
**Files:** `src/sha256/rtl/sha256.sv`, `src/sha512/rtl/sha512.sv`
**Evidence:** `evidence/07_sha256_digest_hwclr_bypass.diff`, `evidence/08_sha512_digest_hwclr_bypass.diff`

```
- zeroize_reg = ZEROIZE || debugUnlock_or_scan_mode_switch;
+ {zeroize_reg, zeroize_reg2} = {
+     ZEROIZE || debugUnlock_or_scan_mode_switch,
+     ~(&{~ZEROIZE, debugUnlock_or_scan_mode_switch})   // = ZEROIZE | ~debugUnlock_or_scan_mode_switch
+ };
  ...
- hwif_in.SHA256_DIGEST[dword].DIGEST.hwclr = zeroize_reg;
+ hwif_in.SHA256_DIGEST[dword].DIGEST.hwclr = zeroize_reg2;
```
`zeroize_reg2 = ZEROIZE | ~debugUnlock_or_scan_mode_switch` differs from
`zeroize_reg` exactly when `debugUnlock_or_scan_mode_switch=1` and SW
`ZEROIZE=0`: `zeroize_reg=1` (correct — scrub) but `zeroize_reg2=0` (bug —
don't scrub). The **write-enable** (`.we`) for the digest register still
correctly uses `zeroize_reg` (blocks new writes), but the **hardware
clear** now uses `zeroize_reg2`, so on a debug-unlock/scan-mode transition
the last-computed digest is *not forced to zero* — it just sits there,
readable through `SHA256_DIGEST`/`SHA512_DIGEST` after the debug session
opens.

**Exploit:** run any SHA-256/512 operation over secret-derived input
(e.g. an HMAC/KDF chain, or a UDS/FE-derived block), then trigger a
debug-unlock or scan-mode transition without asserting SW `ZEROIZE` first.
Read `SHA256_DIGEST[0..7]` / `SHA512_DIGEST[0..15]` over the newly-opened
debug interface — the digest of the pre-unlock secret operation is still
there instead of having been scrubbed.

### 11. Secure-debug-intent write gate polarity inverted
**File:** `src/soc_ifc/rtl/soc_ifc_top.sv`
**Evidence:** `evidence/09_soc_ifc_top_debug_intent_we_inversion.diff`

```
- .we = strap_we_pre_fuse_done | (cptra_uncore_dmi_unlocked_reg_wr_en & (addr == DMI_REG_SS_DEBUG_INTENT));
+ .we = strap_we_pre_fuse_done | ~(|{cptra_uncore_dmi_unlocked_reg_wr_en, (addr != DMI_REG_SS_DEBUG_INTENT)});
```
`~(|{A,B})` = `~A & ~B`. Substituting `~B = (addr == target)`, the new
second term is `~cptra_uncore_dmi_unlocked_reg_wr_en & (addr==target)` —
the **opposite** polarity of the original `cptra_uncore_dmi_unlocked_reg_wr_en
& (addr==target)`. Post-fuse writes to `SS_DEBUG_INTENT.debug_intent` via
the DMI/TAP path now succeed precisely when the DMI is **not** unlocked
(unauthenticated) and are blocked when it **is** properly unlocked.

**Exploit:** without completing whatever authentication sequence sets
`cptra_uncore_dmi_unlocked_reg_wr_en`, write `DMI_REG_SS_DEBUG_INTENT` via
the JTAG/DMI TAP — the write now succeeds, letting an unauthenticated
party set the subsystem debug-intent strap that boot firmware consults to
decide whether to grant debug access.

### 12. CSRNG internal-state dump: cross-instance isolation broken
**File:** `src/csrng/rtl/csrng_state_db.sv`
**Evidence:** `evidence/10_csrng_state_db_cross_instance_leak.diff`

```
- internal_states_dump[rd] = int_st_dump_sel[rd] && int_state_read_enable_i[rd] ? ... : '0;
+ int_st_dump_qualified = int_st_dump_sel & {NApps{int_state_read_enable_i[0]}};
+ internal_states_dump[rd] = int_st_dump_qualified[rd] ? ... : '0;
```
Each CSRNG application instance is supposed to gate its own internal-DRBG-state
dump visibility with its *own* `int_state_read_enable_i[rd]` bit. The
rewrite broadcasts **only bit 0** to every instance via the replicate.

**Exploit:** with `int_state_read_enable_i[0]=1` (app 0's own debug-read
permission) and app 0's own bit otherwise irrelevant to app *N*, select
`int_st_dump_id_q = N` for any other application instance — its internal
DRBG state (`V`, key, reseed counter) is dumped even though instance N's
*own* enable bit was never set, breaking the per-application confidentiality
boundary the CSRNG's multiple hardware instances are supposed to provide.

### 13. DOE: UDS-derived key gets extra Key-Vault destination access
**File:** `src/doe/rtl/doe_fsm.sv`
**Evidence:** `evidence/12_doe_fsm_uds_dest_widening.diff`

```
- kv_write.write_dest_valid = running_hek ? OCP_LOCK_HEK_SEED_DEST_VALID : 'd3;
+ kv_write.write_dest_valid = running_hek ? OCP_LOCK_HEK_SEED_DEST_VALID : (running_uds ? 9'h023 : 'd3);
```
`'d3 = 9'b0_0000_0011` (bits 0,1). `9'h023 = 9'b0_0010_0011` (bits 0,1,5).
Specifically for the **UDS** (Unique Device Secret) derivation output —
and only for UDS, not FE — an extra Key-Vault read-destination bit (index
5) is granted to whichever hardware engine that index maps to
(`KV_DEST_IDX_*` in `kv_defines_pkg.sv`), letting that engine read the
UDS-derived key directly out of the Key Vault where upstream design
intended only the original two consumers to have access.

### 14. AXI arbiter: `user` sideband desynced from the winning transaction
**File:** `src/axi/rtl/axi_sub_arb.sv`
**Evidence:** `evidence/13_axi_sub_arb_user_desync.diff`

```
+ user_from_read = ~(~r_win | w_dv);      // = r_win & ~w_dv
  ...
- user = r_win ? r_user : w_user;
+ user = user_from_read ? r_user : w_user;
```
`addr`, `write`, `id`, `last`, `size` etc. are still selected purely by
`r_win`. Only `user` additionally requires `~w_dv`. When a write request
is concurrently valid (`w_dv=1`) alongside a read that won arbitration
(`r_win=1`), the outgoing transaction is a **read** (per `addr`/`write`)
but carries the **write** request's `user` tag instead of the read's own.
Any downstream logic that keys access decisions off `user` (source/context
ID, commonly used for privilege or KV-attribution checks on the shared AXI
fabric) can be fed a mismatched tag by simply keeping a write pending while
issuing the read of interest.

---

## MEDIUM

### 15. ECDSA HMAC-DRBG SCA mask seed not cleared on zeroize
**File:** `src/ecc/rtl/ecc_hmac_drbg_interface.sv`
**Evidence:** `evidence/14_ecc_hmac_drbg_interface_sca_masking.diff`

The `lfsr_seed_reg <= '0;` reset-on-`zeroize` line was deleted — with the
challenge author's own comment left in: `// without zeroize to make it
more complex`. `lfsr_seed_reg` feeds the masking randomness
(`sca_entropy = IV ^ lfsr_seed_reg ^ counter_nonce`) that is supposed to
de-correlate power/EM traces across ECDSA sign operations. Without
clearing it on zeroize, mask state can persist/be more predictable across
operation boundaries, weakening the side-channel countermeasure.

### 16. HMAC masking-LFSR default seed changed to all-zero
**Files:** `src/hmac/rtl/hmac_reg.sv`, `hmac_reg_uvm.sv`
**Evidence:** `evidence/15_hmac_reg_lfsr_seed_default.diff`

`HMAC512_LFSR_SEED` reset value changed from `32'h3cabffb0` (a fixed
nonzero default, standard practice to avoid the degenerate all-zero
lockup state of an XOR-feedback LFSR) to `32'h0`. If firmware doesn't
explicitly reseed before first use, the masking LFSR can start from (or
get stuck at) all-zero, producing no mask randomness for that window.

### 17. Multiple `CALIPTRA_ASSERT_STABLE` key/seed/control checks deleted
**Files:** `ecc/rtl/ecc_dsa_ctrl.sv`, `hmac/rtl/hmac.sv`,
`aes/rtl/aes_clp_wrapper.sv`, `sha512/rtl/sha512.sv`
**Evidence:** `evidence/16_assertion_removals_ecc_hmac_aes_sha512.diff`

No functional RTL changed, but the simulation-only assertions that would
have *caught* a key/seed/control register glitching mid-operation (from
any of the above bugs, or an unrelated fault) were removed across four
crypto engines. This weakens the verification oracle rather than the
hardware itself, but is worth flagging since it directly reduces the odds
these other bugs would ever have been caught by DV.

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

## Dynamically-verified PoCs (this submission)

| PoC | Bug | Result |
|---|---|---|
| `poc/mubi4_fault_injection/` | Finding #3 | Verilator sim proves `mubi4_test_true_strict(4'h7)==1`, i.e. a 1-bit-flip glitch of `MuBi4True` is accepted as `True`. |
| `poc/entropy_src_repcnt_offbyone/` | Finding #12 | Verilator sim feeds a threshold-5 repetition-count test 12 identical symbols; `test_fail_pulse_o` only fires once `rep_cntr` reaches **6**, not the configured threshold of **5**. |

To run either (needs `verilator` ≥5.0 and the Caliptra `src/` tree):
```
CALIPTRA_ROOT=/path/to/caliptra/checkout ./poc/<name>/run.sh
```
Pre-captured output from an actual run is saved alongside each testbench
as `expected_output.log`.

The remaining findings are backed by exact-line diff evidence and a
written register-level exploit procedure; exercising them live requires
the full chip-level Caliptra integration harness (AXI/AHB fabric, Key
Vault wiring, firmware ROM) which is not present in the provided source
drop — building each one's bespoke bus-functional model was out of scope
given the size of this exercise, but the mechanism, trigger condition and
impact for each is unambiguous from the code alone.
