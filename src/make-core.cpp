
// make-core.cpp
// Crash and generate a core dump to analyze.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline))
char CRASH(char *arg)
{
    if (arg) {
        return *arg;
    } else {
        return 1 + printf("null\n");
    }
}

int main(int argc, char **argv)
{
    // Print the path to the core we're about to generate.
    printf("/cores/core.%d", getpid());
    fflush(stdout);

    return CRASH((char *)0x1234);
}
