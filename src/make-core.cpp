
// make-core.cpp
// Crash and generate a core dump to analyze.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Trivial forward propagation.
// (Intel syntax)
// 1. mov rax, rdi
// 2. mov rdi, rsi
// 3. crash
//
// First we rewind insn #2. At this point the value of rdi before #2 is unknown.
//
// Then we rewind #1. This now teaches us the value of rdi before #2.
// We need forward propagation and forward execution to make full use of this.
// That probably means iterated backward and forward propagation until
// we reach a steady state.

__attribute__((naked))
void CRASH(uint64_t rdi, uint64_t rsi) {
    asm("\n .intel_syntax noprefix"
        "\n  mov rax, rdi"
        "\n  mov rdi, rsi"
        "\n  ud2"
        );
}

int main(int argc, char **argv)
{
    // Print the path to the core we're about to generate.
    printf("/cores/core.%d", getpid());
    fflush(stdout);

    CRASH(0x1111222233334444, 0x5555666677778888);
}
