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


struct Value {
    uint64_t bits;
    uint64_t validBits;

    Value(lldb::SBFrame& frame, const char *reg) {
        // fixme can this fail?
        bits = frame.FindRegister(reg).GetValueAsUnsigned();
        validBits = ~0;
    }

    Value() {
        bits = 0;
        validBits = 0;
    }

    bool allValid() {
        return validBits == ~(uint64_t)0;
    }

    bool noneValid() {
        return validBits == 0;
    }

    void print() {
        if (allValid()) {
            printf("0x%llx", (unsigned long long)bits);
        } else if (noneValid()) {
            printf("<unknown>");
        } else {
            printf("(0x%llx & 0x%llx)", (unsigned long long)(bits & validBits),
                   (unsigned long long)validBits);
        }
    }

    bool operator == (const Value& rhs) const {
        return bits == rhs.bits  &&  validBits == rhs.validBits;
    }

    bool operator != (const Value& rhs) const {
        return !(*this == rhs);
    }

    static Value unknown() {
        return Value();
    }
};

enum X86RegisterNumber {
    RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8, R9, R10, R11, R12, R13, R14, R15, RFLAGS
};

// returns register and valid bits mask (for sub-registers)
// example: X86_REG_AH returns [RAX, 0xff00]
// https://en.wikipedia.org/wiki/X86#/media/File:Table_of_x86_Registers_svg.svg
std::tuple<X86RegisterNumber, uint64_t> X86RegisterFromCapstone(x86_reg reg) {
    switch (reg) {
    // 64-bit GPRs
    case X86_REG_RAX:    return { RAX, 0xffffffffffffffff };
    case X86_REG_RBX:    return { RBX, 0xffffffffffffffff };
    case X86_REG_RCX:    return { RCX, 0xffffffffffffffff };
    case X86_REG_RDX:    return { RDX, 0xffffffffffffffff };
    case X86_REG_RSI:    return { RSI, 0xffffffffffffffff };
    case X86_REG_RDI:    return { RDI, 0xffffffffffffffff };
    case X86_REG_RBP:    return { RBP, 0xffffffffffffffff };
    case X86_REG_RSP:    return { RSP, 0xffffffffffffffff };
    case X86_REG_R8:     return { R8,  0xffffffffffffffff };
    case X86_REG_R9:     return { R9,  0xffffffffffffffff };
    case X86_REG_R10:    return { R10, 0xffffffffffffffff };
    case X86_REG_R11:    return { R11, 0xffffffffffffffff };
    case X86_REG_R12:    return { R12, 0xffffffffffffffff };
    case X86_REG_R13:    return { R13, 0xffffffffffffffff };
    case X86_REG_R14:    return { R14, 0xffffffffffffffff };
    case X86_REG_R15:    return { R15, 0xffffffffffffffff };
    // fixme RFLAGS?

    // 32-bit GPRs
    case X86_REG_EAX:    return { RAX, 0xffffffff };
    case X86_REG_EBX:    return { RBX, 0xffffffff };
    case X86_REG_ECX:    return { RCX, 0xffffffff };
    case X86_REG_EDX:    return { RDX, 0xffffffff };
    case X86_REG_ESI:    return { RSI, 0xffffffff };
    case X86_REG_EDI:    return { RDI, 0xffffffff };
    case X86_REG_EBP:    return { RBP, 0xffffffff };
    case X86_REG_ESP:    return { RSP, 0xffffffff };
    case X86_REG_R8D:    return { R8,  0xffffffff };
    case X86_REG_R9D:    return { R9,  0xffffffff };
    case X86_REG_R10D:   return { R10, 0xffffffff };
    case X86_REG_R11D:   return { R11, 0xffffffff };
    case X86_REG_R12D:   return { R12, 0xffffffff };
    case X86_REG_R13D:   return { R13, 0xffffffff };
    case X86_REG_R14D:   return { R14, 0xffffffff };
    case X86_REG_R15D:   return { R15, 0xffffffff };
    case X86_REG_EFLAGS: return { RFLAGS, 0xffffffff };

    // 16-bit GPRs
    case X86_REG_AX:     return { RAX, 0xffff };
    case X86_REG_BX:     return { RBX, 0xffff };
    case X86_REG_CX:     return { RCX, 0xffff };
    case X86_REG_DX:     return { RDX, 0xffff };
    case X86_REG_SI:     return { RSI, 0xffff };
    case X86_REG_DI:     return { RDI, 0xffff };
    case X86_REG_BP:     return { RBP, 0xffff };
    case X86_REG_SP:     return { RSP, 0xffff };
    case X86_REG_R8W:    return { R8,  0xffff };
    case X86_REG_R9W:    return { R9,  0xffff };
    case X86_REG_R10W:   return { R10, 0xffff };
    case X86_REG_R11W:   return { R11, 0xffff };
    case X86_REG_R12W:   return { R12, 0xffff };
    case X86_REG_R13W:   return { R13, 0xffff };
    case X86_REG_R14W:   return { R14, 0xffff };
    case X86_REG_R15W:   return { R15, 0xffff };

    // LSB 8-bit GPRs
    case X86_REG_AL:     return { RAX, 0xff };
    case X86_REG_BL:     return { RBX, 0xff };
    case X86_REG_CL:     return { RCX, 0xff };
    case X86_REG_DL:     return { RDX, 0xff };
    case X86_REG_SIL:    return { RSI, 0xff };
    case X86_REG_DIL:    return { RDI, 0xff };
    case X86_REG_BPL:    return { RBP, 0xff };
    case X86_REG_SPL:    return { RSP, 0xff };
    case X86_REG_R8B:    return { R8,  0xff };
    case X86_REG_R9B:    return { R9,  0xff };
    case X86_REG_R10B:   return { R10, 0xff };
    case X86_REG_R11B:   return { R11, 0xff };
    case X86_REG_R12B:   return { R12, 0xff };
    case X86_REG_R13B:   return { R13, 0xff };
    case X86_REG_R14B:   return { R14, 0xff };
    case X86_REG_R15B:   return { R15, 0xff };

    // MSB 8-bit GPRs
    case X86_REG_AH:     return { RAX, 0xff00 };
    case X86_REG_BH:     return { RBX, 0xff00 };
    case X86_REG_CH:     return { RCX, 0xff00 };
    case X86_REG_DH:     return { RDX, 0xff00 };

    default:
        die("unhandled x86 register %d", reg);
    }
}

struct RegisterState {
    Value registers[17];

    RegisterState(lldb::SBFrame& frame) {
#define READ(r) registers[r] = Value(frame, #r)
        READ(RAX); READ(RBX); READ(RCX); READ(RDX);
        READ(RSI); READ(RDI); READ(RBP); READ(RSP);
        READ(R8);  READ(R9);  READ(R10); READ(R11);
        READ(R12); READ(R13); READ(R14); READ(R15);
        READ(RFLAGS);
#undef READ
    }

    void print() {
#define PRINT(r) do { printf(#r ": %s", (r == R8 || r == R9) ? " " : "");  \
                      registers[r].print();               \
                      printf("\n"); } while (0)

        PRINT(RAX); PRINT(RBX); PRINT(RCX); PRINT(RDX);
        PRINT(RSI); PRINT(RDI); PRINT(RBP); PRINT(RSP);
        PRINT(R8);  PRINT(R9);  PRINT(R10); PRINT(R11);
        PRINT(R12); PRINT(R13); PRINT(R14); PRINT(R15);
        PRINT(RFLAGS);
    }

    void printDeltaFrom(RegisterState& pred) {
#define MAYBE(r) do {                                                   \
                     if (registers[r] != pred.registers[r]) {           \
                         PRINT(r);                                      \
                     }                                                  \
                 } while (0)
        MAYBE(RAX); MAYBE(RBX); MAYBE(RCX); MAYBE(RDX);
        MAYBE(RSI); MAYBE(RDI); MAYBE(RBP); MAYBE(RSP);
        MAYBE(R8);  MAYBE(R9);  MAYBE(R10); MAYBE(R11);
        MAYBE(R12); MAYBE(R13); MAYBE(R14); MAYBE(R15);
        MAYBE(RFLAGS);

#undef MAYBE
#undef PRINT
    }
};

struct BasicBlock;

struct Instruction {
    cs_insn* code;
    BasicBlock& owner;

    RegisterState rewindFromState(RegisterState& state);

    RegisterState rewind_x86_mov_regToReg(RegisterState& state);

    const char * c_str() {
        static char *result;
        free(result);
        asprintf(&result, "0x%llx: %s\t%s",
                 code->address, code->mnemonic, code->op_str);
        return result;
    }
};

struct BasicBlock {
    std::vector<Instruction> insns;
    std::vector<BasicBlock*> preds;
    std::vector<BasicBlock*> succs;
    uint64_t visited;
    int index;
    bool isEntry = false;
    bool isExit = false;
    bool isCallPlaceholder = false;

    BasicBlock(int i) : index(i) { }

    void print() {
        printf("BLOCK #%d\n", index);

        if (preds.size()) {
            printf("  <==");
            for (auto* pred : preds) {
                printf(" #%d", pred->index);
            }
            printf("\n");
        }

        if (isEntry) printf("  (ENTRY)\n");
        if (isExit) printf("  (EXIT)\n");
        if (isCallPlaceholder) printf("  (CALL)\n");

        for (auto& insn : insns) {
            printf("  %s\n", insn.c_str());
        }

        if (succs.size()) {
            printf("  ==>");
            for (auto* succ : succs) {
                printf(" #%d", succ->index);
            }
            printf("\n");
        }

        printf("\n");
    }
};


struct TraceStep {
    RegisterState inputs;
    Instruction& insn;
};

struct Trace {
    // steps[0] is newest; step++ is backward in time
    std::vector<TraceStep> steps;
    RegisterState outputs;

    Trace(RegisterState outputState)
        : outputs(outputState) { }

    std::vector<TraceStep>::iterator newestStep() {
        return steps.begin();
    }
    std::vector<TraceStep>::iterator oldestStep() {
        return steps.end() - 1;
    }

    RegisterState& oldestRegisterState() {
        if (steps.size() > 0) return oldestStep()->inputs;
        else return outputs;
    }

    void prependBasicBlock(BasicBlock* bb);
    void prependInstruction(Instruction& insn);
    void prependBasicBlockBeforeInstruction(BasicBlock* bb, int index);

    void print() {
        printf("TRACE\n");
        printf("  (ENTRY)\n\n");
        auto prev = steps.rend();
        for (auto step = steps.rbegin(); step != steps.rend(); step++) {
            if (prev != steps.rend()) {
                step->inputs.printDeltaFrom(prev->inputs);
            } else {
                step->inputs.print();
            }
            prev = step;
            printf("\n  %s\n\n", step->insn.c_str());
        }
        if (prev != steps.rend()) {
            outputs.printDeltaFrom(prev->inputs);
        }
        printf("\n  (EXIT)\n\n");
        outputs.print();

    }
};


bool isBranch(csh disassembler, cs_insn* insn) {
    // fixme syscall? int? ret?
    return
        cs_insn_group(disassembler, insn, CS_GRP_JUMP) ||
        cs_insn_group(disassembler, insn, CS_GRP_CALL) ||
        cs_insn_group(disassembler, insn, CS_GRP_RET)  ||
        cs_insn_group(disassembler, insn, CS_GRP_INT)  ||
        cs_insn_group(disassembler, insn, CS_GRP_IRET) ||
        cs_insn_group(disassembler, insn, CS_GRP_CALL);
}
bool isBranch(csh disassembler, Instruction& insn) {
    return isBranch(disassembler, insn.code);
}

bool isCall(csh disassembler, Instruction& insn) {
    // fixme syscall?
    return cs_insn_group(disassembler, insn.code, CS_GRP_CALL);
}

bool branchIsRelative(csh disassembler, cs_insn* insn) {
    assert(isBranch(disassembler, insn));
    return cs_insn_group(disassembler, insn, CS_GRP_BRANCH_RELATIVE);
}
bool branchIsRelative(csh disassembler, Instruction& insn) {
    return branchIsRelative(disassembler, insn.code);
}

bool isUnconditionalBranch(csh disassembler, Instruction& insn) {
    switch (insn.code->id) {
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

uint64_t branchTargetAddress(csh disassembler, cs_insn* insn) {
    if (branchIsRelative(disassembler, insn)) {
        return X86_REL_ADDR(*insn);
    } else {
        return ~0;
    }
}
uint64_t branchTargetAddress(csh disassembler, Instruction& insn) {
    return branchTargetAddress(disassembler, insn.code);
}


Value rewind_mov_r64_to_r64(Value output) {
    return output;
}


RegisterState Instruction::rewind_x86_mov_regToReg(RegisterState& output) {
    auto& x86 = code->detail->x86;
    assert(x86.operands[0].type == X86_OP_REG);
    assert(x86.operands[1].type == X86_OP_REG);

    auto [dstReg, dstRegMask] = X86RegisterFromCapstone(x86.operands[0].reg);
    auto [srcReg, srcRegMask] = X86RegisterFromCapstone(x86.operands[1].reg);
    if (dstRegMask != ~(uint64_t)0  ||  srcRegMask != ~(uint64_t)0) {
        unimplemented("x86 mov with partial register update %s", this->c_str());
    }

    // input srcReg was dstReg output
    // dstReg input was unknown
    // fixme forward propagation (see comment in make-core.cpp)
    RegisterState input = output;
    input.registers[srcReg] = rewind_mov_r64_to_r64(output.registers[dstReg]);
    input.registers[dstReg] = Value::unknown();
    return input;
}


RegisterState Instruction::rewindFromState(RegisterState& outputState) {
    auto& x86 = code->detail->x86;

    switch (code->id) {
    case X86_INS_MOV:
        if (x86.op_count != 2) {
            die("x86 mov with operand count not equal to 2 %s", this->c_str());
        }
        if (x86.operands[0].type == X86_OP_REG  ||
            x86.operands[1].type == X86_OP_REG)
        {
            return rewind_x86_mov_regToReg(outputState);
        }

    default:
        die("can't rewind instruction %s", this->c_str());
    }
}

void Trace::prependInstruction(Instruction& insn) {
    RegisterState inputs = insn.rewindFromState(oldestRegisterState());
    steps.push_back(TraceStep{ inputs, insn });
}

void Trace::prependBasicBlock(BasicBlock* bb) {
    for (auto insn = bb->insns.rbegin(); insn != bb->insns.rend(); insn++) {
        prependInstruction(*insn);
    }
}

void Trace::prependBasicBlockBeforeInstruction(BasicBlock* bb, int index)
{
    // instruction #index is NOT executed
    while (index-- > 0) {
        prependInstruction(bb->insns[index]);
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
            for (auto& insn : block.insns) {
                if (insn.code->address == address) return &block;
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
            if (isBranch(disassembler, &insns[i])) {
                blockStarts.push_back(branchTargetAddress(disassembler, &insns[i]));  // #2
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
            currentBlock->insns.push_back(Instruction{&insns[i], *currentBlock});
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
            auto& insn = block.insns.back();

            // The block immediately after this one,
            // if we don't branch away forever.
            auto* fallthroughSuccessor =
                (insn.code+1 < insns+insnCount)
                ? blockForAddress((insn.code+1)->address)
                : &exit();

            if (isCall(disassembler, insn)) {
                // Insert call placeholder block.
                if (blockForAddress(branchTargetAddress(disassembler, insn))) {
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
            else if (isBranch(disassembler, insn)) {
                // Add edge to branch's target, or exit() if it's non-local.
                auto targetAddress = branchTargetAddress(disassembler, insn);
                auto* target = blockForAddress(targetAddress) ?: &exit();
                addEdge(block, *target);
            }

            if (!isUnconditionalBranch(disassembler, insn)) {
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
        for (auto& block : blocks) {
            block.print();
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
                for (auto& insn : block.insns) {
                    fprintf(gfile, " 0x%llx:\\tab %s\\tab %s \\\n",
                            insn.code->address, insn.code->mnemonic,
                            insn.code->op_str);
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
    // fixme this only works with debuginfo?
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

    // Don't use capstone's AT&T syntax, even though macOS does.
    // captone's option changes its internal operand numbering,
    // not just its textual output.
    // We prefer to use consistent operand numbering everywhere.
    // cs_option(disassembler, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
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

    BasicBlock* crashedBB = cfg.blockForAddress(frame.GetPC());
    int crashedInstructionIndex = 0;
    for (auto insn = crashedBB->insns.begin(); insn != crashedBB->insns.end(); insn++, crashedInstructionIndex++) {
        if (insn->code->address == frame.GetPC()) {
            break;
        }
    }

    auto regs = RegisterState(frame);

    Trace tt(regs);
    tt.prependBasicBlockBeforeInstruction(crashedBB, crashedInstructionIndex);

    tt.print();
}
