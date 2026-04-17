CXX=/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++
LDFLAGS=-L/system/lib64 -Wl,-rpath=/system/lib64 -ljnimock

main: main.cpp harness.cpp
	$(CXX) $^ -o $@ $(LDFLAGS)
clean:
	$(RM) main
