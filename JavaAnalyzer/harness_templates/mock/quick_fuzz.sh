#!/bin/bash
rm -rf out/
mkdir in &> /dev/null
dd if=/dev/urandom of=in/sample.bin bs=16 count=16 &> /dev/null
[ -e "main" ] || exit 1

export LD_LIBRARY_PATH=
export AFL_QEMU_INST_RANGES=
export AFL_QEMU_FORCE_DFL=1
# export AFL_ENTRYPOINT=$(nm main | grep fuzz_one_input | awk '{printf "0x%x", 0x5500000000 + strtonum("0x"$1)}')
export AFL_QEMU_PERSISTENT_ADDR=$(nm main | grep fuzz_one_input | awk '{printf "0x%x", 0x5500000000 + strtonum("0x"$1)}')
export AFL_QEMU_PERSISTENT_GPR=1

afl-fuzz -Q -c main -i in -o out -t 2000 -- ./main