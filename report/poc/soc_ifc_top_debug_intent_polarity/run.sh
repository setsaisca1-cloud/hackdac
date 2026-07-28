#!/usr/bin/env bash
# Self-contained (reproduces the exact buggy boolean expression from
# soc_ifc_top.sv verbatim) -- no CALIPTRA_ROOT needed.
set -euo pipefail
cd "$(dirname "$0")"
verilator --binary --timing --top-module tb -Wno-fatal tb.sv -o tb_sim
./obj_dir/tb_sim
