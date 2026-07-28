#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
verilator --binary --timing --top-module tb -Wno-fatal tb.sv -o tb_sim
./obj_dir/tb_sim
