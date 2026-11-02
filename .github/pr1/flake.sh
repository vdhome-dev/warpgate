#!/usr/bin/env bash
# Runs one test repeatedly in four parallel workers, so the machine is under load.
set -u
rustup show active-toolchain || rustup toolchain install
mkdir -p warpgate-web/dist
cargo test --features sqlite -p warpgate-core --lib --no-run > build.log 2>&1 || { tail -30 build.log; exit 2; }
EXE=$(grep -oE 'target[/\]debug[/\]deps[/\]warpgate_core-[0-9a-f]+(\.exe)?' build.log | tail -1)
EXE=${EXE//\//}
echo "code: $(git rev-parse --short HEAD) exe: $EXE"
worker() {
  local fails=0 runs=0
  for _ in $(seq 1 75); do
    runs=$((runs + 1))
    if ! "./$EXE" "$T" --exact > "out-$1.txt" 2>&1; then
      fails=$((fails + 1))
      grep -E 'panicked at|left:|right:' "out-$1.txt" | head -3
    fi
  done
  echo "RESULT worker $1: $fails of $runs failed"
}
for w in 1 2 3 4; do worker "$w" & done
wait
