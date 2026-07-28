#!/usr/bin/env bash
# This PoC is self-contained (reproduces the exact buggy lines from
# aes_reg_top.sv verbatim) -- no CALIPTRA_ROOT needed.
set -euo pipefail
cd "$(dirname "$0")"
verilator --binary --timing --top-module tb -Wno-fatal tb.sv -o tb_sim
./obj_dir/tb_sim
