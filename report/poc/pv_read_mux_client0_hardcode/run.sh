#!/usr/bin/env bash
# Self-contained (reproduces the exact buggy mux from pv.sv verbatim,
# parameterized over NUM_READ) -- no CALIPTRA_ROOT needed.
set -euo pipefail
cd "$(dirname "$0")"
verilator --binary --timing --top-module tb -Wno-fatal -GNUM_READ=1 tb.sv -o tb_sim_1client
verilator --binary --timing --top-module tb -Wno-fatal -GNUM_READ=2 --Mdir obj_dir_2 tb.sv -o tb_sim_2client
echo "=== NUM_READ=1 (current shipped pv_defines_pkg.sv config) ==="
./obj_dir/tb_sim_1client
echo "=== NUM_READ=2 (upstream v2.1.2 default / latent-bug config) ==="
./obj_dir_2/tb_sim_2client
