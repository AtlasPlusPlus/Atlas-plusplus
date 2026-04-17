export ASAN_OPTIONS=detect_leaks=0
LD_PRELOAD=libclang_rt.asan-aarch64-android.so ./main
