#ifndef _RISCV_DECODE_MACROS_H
#define _RISCV_DECODE_MACROS_H

#include "config.h"
#include "decode.h"
#include "encoding.h"
#include "common.h"
#include "softfloat_types.h"
#include "specialize.h"
#include "processor.h" 

// Helpful macros
#define require(cond) if (!(cond)) throw trap_illegal_instruction(insn.bits())

// 
#define sext_xlen(x) (((sreg_t)(x) << (64 - p->get_xlen())) >> (64 - p->get_xlen()))

#define DECODE_MACRO_USAGE_LOGGED 0 

#define MMU (*p->get_mmu())
#define STATE (*p->get_state())
#define FLEN (p->get_flen())
#define CHECK_REG(reg) ((void) 0)
#define READ_REG(reg) (CHECK_REG(reg), STATE.XPR[reg])
#define READ_FREG(reg) STATE.FPR[reg]
#define RD READ_REG(insn.rd())
#define RS1 READ_REG(insn.rs1())
#define RS2 READ_REG(insn.rs2())
#define RS3 READ_REG(insn.rs3())
#define WRITE_RD(value) WRITE_REG(insn.rd(), value)

/* 0 : int
 * 1 : floating
 * 2 : vector reg
 * 3 : vector hint
 * 4 : csr
 */
#define WRITE_REG(reg, value) ({ \
    reg_t wdata = (value); /* value may have side effects */ \
    if (DECODE_MACRO_USAGE_LOGGED) STATE.log_reg_write[(reg) << 4] = {wdata, 0}; \
    CHECK_REG(reg); \
    STATE.XPR.write(reg, wdata); \
  })
#define WRITE_FREG(reg, value) ({ \
    freg_t wdata = freg(value); /* value may have side effects */ \
    if (DECODE_MACRO_USAGE_LOGGED) STATE.log_reg_write[((reg) << 4) | 1] = wdata; \
    DO_WRITE_FREG(reg, wdata); \
  })
#define WRITE_VSTATUS STATE.log_reg_write[3] = {0, 0};

// RVC macros
#define WRITE_RVC_RS1S(value) WRITE_REG(insn.rvc_rs1s(), value)
#define WRITE_RVC_RS2S(value) WRITE_REG(insn.rvc_rs2s(), value)
#define WRITE_RVC_FRS2S(value) WRITE_FREG(insn.rvc_rs2s(), value)
#define RVC_RS1 READ_REG(insn.rvc_rs1())
#define RVC_RS2 READ_REG(insn.rvc_rs2())
#define RVC_RS1S READ_REG(insn.rvc_rs1s())
#define RVC_RS2S READ_REG(insn.rvc_rs2s())
#define RVC_FRS2 READ_FREG(insn.rvc_rs2())
#define RVC_FRS2S READ_FREG(insn.rvc_rs2s())
#define RVC_SP READ_REG(X_SP)

// Other macros
#define SHAMT (insn.i_imm() & 0x3F)
#define BRANCH_TARGET (pc + insn.sb_imm())
#define JUMP_TARGET (pc + insn.uj_imm())
#define RM ({ int rm = insn.rm(); \
              if (rm == 7) rm = STATE.frm->read(); \
              if (rm > 4) throw trap_illegal_instruction(insn.bits()); \
              rm; })

// Define require_extension macro
#define require_extension(ext) require(p->extension_enabled(ext))

#endif // _RISCV_DECODE_MACROS_H
