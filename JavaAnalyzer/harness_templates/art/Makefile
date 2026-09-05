CXX=/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++
LDFLAGS=-L/system/lib64 -Wl,-rpath=/system/lib64 -landroid_runtime

main: main.cpp harness.cpp property_compat.cpp
	$(CXX) $^ -o $@ $(LDFLAGS)
clean:
	$(RM) main
