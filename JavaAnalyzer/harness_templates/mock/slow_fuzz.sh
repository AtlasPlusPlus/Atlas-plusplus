#!/bin/bash
rm -rf out/
mkdir in &> /dev/null
dd if=/dev/urandom of=in/sample.bin bs=16 count=16 &> /dev/null
[ -e "main" ] || exit 1

export LD_LIBRARY_PATH=
export AFL_QEMU_INST_RANGES=
export AFL_QEMU_FORCE_DFL=1
export AFL_USE_QASAN=1

afl-fuzz -Q -c main -i in -o out -t 2000 -- ./main