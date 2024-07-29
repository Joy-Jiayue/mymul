#ifndef _RISCV_C_MYMUL_H
#define _RISCV_C_MYMUL_H

#include "decode.h"
#include "encoding.h"  
#include "processor.h" 
#include "decode_macros.h"  
#include "insn_template.h"

reg_t rv32_c_mymul(processor_t* p, insn_t insn, reg_t pc) {
    reg_t npc = sext_xlen(pc + insn_length(MATCH_C_MYMUL));
    WRITE_RD(sext_xlen(RVC_RS1(p->get_state(), insn) * RVC_RS2(p->get_state(), insn)));
    p->trace_opcode(MATCH_C_MYMUL, insn, pc, npc);
    return npc;
}

reg_t rv64_c_mymul(processor_t* p, insn_t insn, reg_t pc) {
    reg_t npc = sext_xlen(pc + insn_length(MATCH_C_MYMUL));
    WRITE_RD(sext_xlen(RVC_RS1(p->get_state(), insn) * RVC_RS2(p->get_state(), insn)));
    p->trace_opcode(MATCH_C_MYMUL, insn, pc, npc);
    return npc;
}

#endif // _RISCV_C_MYMUL_H
