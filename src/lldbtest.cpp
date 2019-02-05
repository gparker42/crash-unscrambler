// lldbtest.cpp
// Open a core dump in lldb and interrogate it.

#include "LLDB/LLDB.h"
#include "capstone/capstone.h"
#include <libgen.h>

void die(const char *str, ...) {
    va_list va;
    va_start(va, str);
    vfprintf(stderr, str, va);
    fprintf(stderr, "\n");
    exit(1);
}

int main(int argc, char **argv)
{
    auto dir = dirname(argv[0]);
    char *crashapp; asprintf(&crashapp, "%s/make-core", dir);
    const char *corefile = "/cores/core-to-unscramble";

    lldb::SBDebugger::Initialize();
    lldb::SBError sberr;

    auto dump = lldb::SBStream();
    dump.RedirectToFileHandle(stdout, false/*don't transfer ownership*/);

    // Make an lldb.
    auto debugger = lldb::SBDebugger::Create(false);
    auto target = debugger.CreateTarget(crashapp);
    if (!target.IsValid()) {
        die("couldn't open executable %s (run `make /cores/core-to-unscramble` to regenerate it)", crashapp);
    }
    dump.Printf("TARGET TRIPLE %s\n", target.GetTriple());

    // Open the core dump and find the crashed frame.
    auto process = target.LoadCore(corefile);
    if (!process.IsValid()) {
        die("couldn't open core file %s (run `make /cores/core-to-unscramble` to regenerate it)", corefile);
    }
    auto thread = process.GetSelectedThread();
    dump.Printf("ANALYZING THREAD:\n");
    thread.GetDescription(dump);

    auto frame = thread.GetSelectedFrame();
    dump.Printf("ANALYZING FRAME:\n");
    frame.GetDescription(dump);

    // The frame's SBFunction is outside any inlining.
    // This is the instruction range for which we want to build a CFG.
    // Inlined functions are represented using SBBlock.
    auto function = frame.GetFunction();
    dump.Printf("ANALYZING FUNCTION:\n");
    function.GetDescription(dump);
    dump.Printf("\n");

    // Copy the function's instruction bytes.
    auto start = function.GetStartAddress().GetLoadAddress(target);
    auto end = function.GetEndAddress().GetLoadAddress(target);
    size_t byteSize = end - start;
    if (byteSize > 0x1000000) die("function too big (%zu bytes)", byteSize);
    dump.Printf("%zu instruction bytes\n", byteSize);
    auto insnbytes = (uint8_t *)malloc(byteSize);
    size_t readed = process.ReadMemory(start, insnbytes, byteSize, sberr);
    assert(sberr.Success());
    assert(readed == byteSize);

    // Disassemble.
    csh disassembler;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &disassembler) != CS_ERR_OK) {
        die("couldn't open disassembler");
    }
    cs_option(disassembler, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    cs_option(disassembler, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insns;
    auto insnCount = cs_disasm(disassembler, insnbytes, byteSize, start, 0, &insns);
    for (size_t i = 0; i < insnCount; i++) {
        printf("0x%llx: %s\t%s\n",
               insns[i].address, insns[i].mnemonic, insns[i].op_str);
    }
}
