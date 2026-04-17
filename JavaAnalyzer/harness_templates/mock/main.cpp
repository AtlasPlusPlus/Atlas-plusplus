#include "main.hpp"
#include <cstdio>

extern void fuzz_one_input();
pid_t pid{};

int main() {
    pid = getpid();
    fuzz_one_input();
    return 0;
}
