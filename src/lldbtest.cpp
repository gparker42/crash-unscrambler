// lldbtest.cpp
// Open a core dump in lldb and interrogate it.

#include "LLDB/LLDB.h"
#include "capstone/capstone.h"
#include <libgen.h>
#include <unistd.h>
#include <sys/errno.h>

using namespace std;


void warn(const char* str, ...) {
    fprintf(stderr, "WARNING: ");
    va_list va;
    va_start(va, str);
    vfprintf(stderr, str, va);
    fprintf(stderr, "\n");
}

__attribute__((noreturn))
void die(const char* str, ...) {
    fprintf(stderr, "ERROR: ");
    va_list va;
    va_start(va, str);
    vfprintf(stderr, str, va);
    fprintf(stderr, "\n");
    exit(1);
}

__attribute__((noreturn))
void unimplemented(const char* str, ...) {
    fprintf(stderr, "UNIMPLEMENTED: ");
    va_list va;
    va_start(va, str);
    vfprintf(stderr, str, va);
    fprintf(stderr, "\n");
    exit(1);
}


struct BasicBlock {
    std::vector<cs_insn*> insns;
    std::vector<BasicBlock*> preds;
    std::vector<BasicBlock*> succs;
    uint64_t visited;
    int index;
    bool isEntry = false;
    bool isExit = false;
    bool isCallPlaceholder = false;

    BasicBlock(int i) : index(i) { }
};


bool isBranch(csh disassembler, cs_insn& insn) {
    // fixme syscall? int? ret?
    return
        cs_insn_group(disassembler, &insn, CS_GRP_JUMP) ||
        cs_insn_group(disassembler, &insn, CS_GRP_CALL) ||
        cs_insn_group(disassembler, &insn, CS_GRP_RET)  ||
        cs_insn_group(disassembler, &insn, CS_GRP_INT)  ||
        cs_insn_group(disassembler, &insn, CS_GRP_IRET) ||
        cs_insn_group(disassembler, &insn, CS_GRP_CALL);
}

bool isCall(csh disassembler, cs_insn& insn) {
    // fixme syscall?
    return cs_insn_group(disassembler, &insn, CS_GRP_CALL);
}

bool branchIsRelative(csh disassembler, cs_insn& insn) {
    assert(isBranch(disassembler, insn));
    return cs_insn_group(disassembler, &insn, CS_GRP_BRANCH_RELATIVE);
}

bool isUnconditionalBranch(csh disassembler, cs_insn& insn) {
    switch (insn.id) {
    case X86_INS_JMP:
    case X86_INS_CALL:
    case X86_INS_RET:
    case X86_INS_SYSENTER:
    case X86_INS_SYSEXIT:
    case X86_INS_SYSCALL:
    case X86_INS_SYSRET:
    case X86_INS_INT:
    case X86_INS_INT1:
    case X86_INS_INT3:
    case X86_INS_INTO:
        return true;
    default:
        return false;
    }
}

uint64_t branchTargetAddress(csh disassembler, cs_insn& insn)
{
    if (branchIsRelative(disassembler, insn)) {
        return X86_REL_ADDR(insn);
    } else {
        return ~0;
    }
}

struct CFG {
    vector<BasicBlock> blocks;

    // Artificial empty blocks for entry and exit.
    BasicBlock& entry() { return blocks[0]; }
    BasicBlock& exit() { return blocks[1]; }

    // fixme slow
    BasicBlock* blockForAddress(uint64_t address) {
        for (auto& block : blocks) {
            for (auto* insn : block.insns) {
                if (insn->address == address) return &block;
            }
        }
        return nullptr;
    }

    CFG(csh disassembler, cs_insn* insns, size_t insnCount,
        const char* functionName)
    {
        if (insnCount == 0) {
            die("function %s has zero instructions", functionName);
        }

        // Make the entry and exit blocks.
        blocks.emplace_back(0).isEntry = true;
        blocks.emplace_back(1).isExit = true;

        // Find every address that is a block start.
        // Block starts are:
        // 1. the first instruction
        // 2. the target of every branch instruction
        // 3. the instruction after any branch instruction, conditional or not
        vector<uint64_t> blockStarts;
        blockStarts.push_back(insns[0].address);  // #1
        for (auto i = 0; i < insnCount; i++) {
            if (isBranch(disassembler, insns[i])) {
                blockStarts.push_back(branchTargetAddress(disassembler, insns[i]));  // #2
                if (i+1 < insnCount) {
                    blockStarts.push_back(insns[i+1].address); // #3
                }
            }
        }

        // Sort block starts by increasing address.
        sort(blockStarts.begin(), blockStarts.end());

        // Create the basic blocks, splitting at the branch targets.
        BasicBlock* currentBlock = nullptr;
        for (auto i = 0, b = 0; i < insnCount; i++) {
            // Advance the branch target index to on or after this instruction.
            while (blockStarts[b] < insns[i].address) {
                b++;
                if (b == blockStarts.size()) break;
            }

            if (b != blockStarts.size() &&
                blockStarts[b] == insns[i].address)
            {
                // This instruction is a block start.
                // Make a new block for it.
                // Don't set predecessors or successors yet.
                currentBlock = &blocks.emplace_back(blocks.size());
            }

            // Add the instruction to the block.
            currentBlock->insns.push_back(&insns[i]);
        }

        // Revisit the last instruction of each block to
        //   set block predecessors and successors.
        // Also insert placeholder basic blocks representing
        //   the code executed by each call instruction
        //   and each non-call branch that leaves the vicinity.
        // Also complain about each call instruction that does *not*
        //   leave the vicinity because that is weird (fixme need to handle
        //   internal call/ret in case lldb's function boundaries are too big?)

        addEdge(entry(), blocks[2]);

        for (auto& block : blocks) {
            if (block.insns.size() == 0) continue;
            auto* insn = block.insns.back();

            // The block immediately after this one,
            // if we don't branch away forever.
            auto* fallthroughSuccessor =
                (insn+1 < insns+insnCount)
                ? blockForAddress((insn+1)->address)
                : &exit();

            if (isCall(disassembler, *insn)) {
                // Insert call placeholder block.
                if (blockForAddress(branchTargetAddress(disassembler, *insn))) {
                    unimplemented("can't CFG a call instruction "
                                  "that has a local target");
                }
                auto* calledBlock = &blocks.emplace_back(blocks.size());
                calledBlock->isCallPlaceholder = true;
                addEdge(block, *calledBlock);

                // fixme recognize calls to no-return functions
                // and remove this returning edge?
                // Or do that in a later operation.
                addEdge(*calledBlock, *fallthroughSuccessor);
            }
            else if (isBranch(disassembler, *insn)) {
                // Add edge to branch's target, or exit() if it's non-local.
                auto targetAddress = branchTargetAddress(disassembler, *insn);
                auto* target = blockForAddress(targetAddress) ?: &exit();
                addEdge(block, *target);
            }

            if (!isUnconditionalBranch(disassembler, *insn)) {
                // Last instruction may fall through.
                addEdge(block, *fallthroughSuccessor);
            }
        }
    }

    // CFG append:
    // revisit each call placeholder in case the call destination now exists
    // revisit each predecessor of the exit block in case they no longer
    //   fall through to the exit
    // split anything that the new code jumps to

    void print(void) {
        printf("\nCFG\n\n");
        auto i = 0;
        for (auto& block : blocks) {
            printf("BLOCK #%d\n", i++);

            if (block.preds.size()) {
                printf("  <==");
                for (auto* pred : block.preds) {
                    printf(" #%d", pred->index);
                }
                printf("\n");
            }

            if (block.isEntry) printf("  (ENTRY)\n");
            if (block.isExit) printf("  (EXIT)\n");
            if (block.isCallPlaceholder) printf("  (CALL)\n");

            for (auto* insn : block.insns) {
                printf("  0x%llx: %s\t%s\n",
                       insn->address, insn->mnemonic, insn->op_str);
            }

            if (block.succs.size()) {
                printf("  ==>");
                for (auto* succ : block.succs) {
                    printf(" #%d", succ->index);
                }
                printf("\n");
            }

            printf("\n");
        }
    }


    // Write CFG as an OmniGraffle file.
    // tip: `Arrange > Diagram Layout > Lay Out Entire Canvas` after opening
    void grafflize()
    {
        #define graffleheader "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>GraphDocumentVersion</key><integer>3</integer><key>ReadOnly</key><string>NO</string><key>GraphicsList</key><array>\n"
        #define grafflefooter "</array></dict></plist>\n"
        #define bbstart R"###(<dict><key>Class</key><string>ShapedGraphic</string><key>FitText</key><string>YES</string><key>Flow</key><string>Resize</string><key>Wrap</key><string>NO</string><key>shadow</key><dict><key>Draws</key><string>NO</string></dict><key>Text</key><dict><key>Text</key><string>{\rtf1\ansi\ansicpg1252\cocoartf1671\cocoasubrtf200
{\fonttbl\f0\fnil\fcharset0 Menlo-Regular;}
{\colortbl;\red255\green255\blue255;\red0\green0\blue0;}
\pard\tx2000\tx3500\tx5000\pardirnatural\partightenfactor0

\f0\fs24 \cf2)###"
        #define bbmiddle "}</string></dict><key>ID</key><integer>"
        #define bbend "</integer></dict>\n"
        #define edgestart "<dict><key>Class</key><string>LineGraphic</string><key>Tail</key><dict><key>ID</key><integer>"
        #define edgemiddle "</integer></dict><key>Head</key><dict><key>ID</key><integer>"
        #define edgeend "</integer></dict><key>Style</key><dict><key>stroke</key><dict><key>HeadArrow</key><string>FilledArrow</string><key>LineType</key><integer>1</integer></dict></dict></dict>"

        char filename[] = "/tmp/cfg-XXXXX.graffle";

        // Open file
        auto gfile = fdopen(mkstemps(filename, (int)strlen(strrchr(filename, '.'))), "w");
        if (!gfile) {
            warn("couldn't create a graffle file in /tmp/ (errno %d)", errno);
            return;
        }

        // Write header
        fprintf(gfile, graffleheader);

        for (auto& block : blocks) {
            // Write a rectangle for each basic block.
            fprintf(gfile, bbstart);
            if (block.isEntry) {
                fprintf(gfile, "\\\n ENTRY \\\n");
            }
            if (block.isExit) {
                fprintf(gfile, "\\\n EXIT \\\n");
            }
            if (block.isCallPlaceholder) {
                fprintf(gfile, "\\\n CALL \\\n");
            }

            if (block.insns.size() > 0) {
                fprintf(gfile, "\\\n");
                for (auto* insn : block.insns) {
                    fprintf(gfile, " 0x%llx:\\tab %s\\tab %s \\\n",
                            insn->address, insn->mnemonic, insn->op_str);
                }
            }
            fprintf(gfile, bbmiddle "%d" bbend, block.index);

            // Write an arrow to each of its successors.
            for (auto* succ : block.succs) {
                fprintf(gfile, edgestart "%d" edgemiddle "%d" edgeend,
                        block.index, succ->index);
            }
        }

        // Finish the file
        fprintf(gfile, grafflefooter);
        fclose(gfile);
        printf("wrote CFG image to %s\n", filename);

    }

private:
    void addEdge(BasicBlock& pred, BasicBlock& succ) {
        pred.succs.push_back(&succ);
        succ.preds.push_back(&pred);
    }
};


int main(int argc, char** argv)
{
    auto dir = dirname(argv[0]);
    char* crashapp; asprintf(&crashapp, "%s/make-core", dir);
    const char* corefile = "/cores/core-to-unscramble";

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
    auto insnbytes = (uint8_t*)malloc(byteSize);
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
    cs_insn* insns;
    auto insnCount = cs_disasm(disassembler, insnbytes, byteSize, start, 0, &insns);
    for (size_t i = 0; i < insnCount; i++) {
        printf("0x%llx: %s\t%s\n",
               insns[i].address, insns[i].mnemonic, insns[i].op_str);
    }

    // Generate the control flow graph.
    auto cfg = CFG(disassembler, insns, insnCount, function.GetDisplayName());
    cfg.print();
    cfg.grafflize();
}
