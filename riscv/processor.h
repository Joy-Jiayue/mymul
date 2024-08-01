#ifndef _RISCV_PROCESSOR_H
#define _RISCV_PROCESSOR_H

#include "decode_macros.h"
#include "insns/c_mymul.h" 
// 
#include <vector>
#include <functional>
#include <unordered_map>
#include <cinttypes>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <limits.h>
#include <stdexcept>
#include <string>
#include <algorithm>
#include <unordered_map>
#include "encoding.h" 
#include "decode.h"
#include "insn.h"
#include "insn_template.h"
#include "mmu.h"

#define XLEN 64 // 

extern reg_t my_constant;

class processor_t;
class mmu_t;
typedef reg_t (*insn_func_t)(processor_t*, insn_t, reg_t);
class simif_t;
class trap_t;
class extension_t;
class disassembler_t;

reg_t illegal_instruction(processor_t* p, insn_t insn, reg_t pc);

// Declaration of custom instruction handler
reg_t custom_mymul(processor_t* p, insn_t insn, reg_t pc);

struct insn_desc_t {
    insn_bits_t match;
    insn_bits_t mask;
    insn_func_t fast_rv32i;
    insn_func_t fast_rv64i;
    insn_func_t fast_rv32e;
    insn_func_t fast_rv64e;
    insn_func_t logged_rv32i;
    insn_func_t logged_rv64i;
    insn_func_t logged_rv32e;
    insn_func_t logged_rv64e;

    insn_func_t func(int xlen, bool rve, bool logged) const {
        if (logged) {
            if (rve) return xlen == 64 ? logged_rv64e : logged_rv32e;
            else return xlen == 64 ? logged_rv64i : logged_rv32i;
        } else {
            if (rve) return xlen == 64 ? fast_rv64e : fast_rv32e;
            else return xlen == 64 ? fast_rv64i : fast_rv32i;
        }
    }

    static const insn_desc_t illegal_instruction;
};

// regnum, data
typedef std::unordered_map<reg_t, freg_t> commit_log_reg_t;

// addr, value, size
typedef std::vector<std::tuple<reg_t, uint64_t, uint8_t>> commit_log_mem_t;

// architectural state of a RISC-V hart
struct state_t {
    void reset(processor_t* const proc, reg_t max_isa);

    reg_t pc;
    regfile_t<reg_t, NXPR, true> XPR;
    regfile_t<freg_t, NFPR, false> FPR;

    // control and status registers
    std::unordered_map<reg_t, csr_t_p> csrmap;
    reg_t prv;
    reg_t prev_prv;
    bool prv_changed;
    bool v_changed;
    bool v;
    bool prev_v;
    misa_csr_t_p misa;
    mstatus_csr_t_p mstatus;
    csr_t_p mstatush;
    csr_t_p mepc;
    csr_t_p mtval;
    csr_t_p mtvec;
    csr_t_p mcause;
    wide_counter_csr_t_p minstret;
    wide_counter_csr_t_p mcycle;
    mie_csr_t_p mie;
    mip_csr_t_p mip;
    csr_t_p medeleg;
    csr_t_p mideleg;
    csr_t_p mcounteren;
    csr_t_p mevent[N_HPMCOUNTERS];
    csr_t_p mnstatus;
    csr_t_p mnepc;
    csr_t_p scounteren;
    csr_t_p sepc;
    csr_t_p stval;
    csr_t_p stvec;
    virtualized_csr_t_p satp;
    csr_t_p scause;

    csr_t_p nonvirtual_stvec;
    csr_t_p nonvirtual_scause;
    csr_t_p nonvirtual_sepc;
    csr_t_p nonvirtual_stval;
    sstatus_proxy_csr_t_p nonvirtual_sstatus;

    csr_t_p mtval2;
    csr_t_p mtinst;
    csr_t_p hstatus;
    csr_t_p hideleg;
    csr_t_p hedeleg;
    csr_t_p hcounteren;
    csr_t_p htval;
    csr_t_p htinst;
    csr_t_p hgatp;
    hvip_csr_t_p hvip;
    sstatus_csr_t_p sstatus;
    vsstatus_csr_t_p vsstatus;
    csr_t_p vstvec;
    csr_t_p vsepc;
    csr_t_p vscause;
    csr_t_p vstval;
    csr_t_p vsatp;

    csr_t_p dpc;
    dcsr_csr_t_p dcsr;
    csr_t_p tselect;
    csr_t_p tdata2;
    csr_t_p tcontrol;
    csr_t_p scontext;
    csr_t_p mcontext;

    csr_t_p jvt;

    bool debug_mode;

    mseccfg_csr_t_p mseccfg;

    static const int max_pmp = 64;
    pmpaddr_csr_t_p pmpaddr[max_pmp];

    float_csr_t_p fflags;
    float_csr_t_p frm;

    csr_t_p menvcfg;
    csr_t_p senvcfg;
    csr_t_p henvcfg;

    csr_t_p mstateen[4];
    csr_t_p sstateen[4];
    csr_t_p hstateen[4];

    csr_t_p htimedelta;
    time_counter_csr_t_p time;
    csr_t_p time_proxy;

    csr_t_p stimecmp;
    csr_t_p vstimecmp;

    csr_t_p srmcfg;

    csr_t_p ssp;

    bool serialized;

    enum {
        STEP_NONE,
        STEP_STEPPING,
        STEP_STEPPED
    } single_step;

    commit_log_reg_t log_reg_write;
    commit_log_mem_t log_mem_read;
    commit_log_mem_t log_mem_write;
    reg_t last_inst_priv;
    int last_inst_xlen;
    int last_inst_flen;

    elp_t elp;
};

class opcode_cache_entry_t {
public:
    opcode_cache_entry_t() {
        reset();
    }

    void reset() {
        for (size_t i = 0; i < OPCODE_CACHE_SIZE; i++) {
            entries[i].reset();
        }
    }

    struct entry_t {
        entry_t() : valid(false) {}
        void reset() { valid = false; }
        insn_func_t func;
        bool valid;
    } entries[OPCODE_CACHE_SIZE];
};

class processor_t {
public:
    processor_t(const isa_parser_t *isa, simif_t* sim, uint32_t id, bool halt_on_reset);
    ~processor_t();

    void set_debug(bool value);
    void set_histogram(bool value);
    void enable_log_commits();
    bool get_log_commits_enabled() const { return log_commits_enabled; }
    void reset();
    void step(size_t n); // run for n cycles
    void put_csr(int which, reg_t val);
    uint32_t get_id() const { return id; }
    reg_t get_csr(int which, insn_t insn, bool write, bool peek = 0);
    reg_t get_csr(int which) { return get_csr(which, insn_t(0), false, true); }
    mmu_t* get_mmu() { return mmu; }
    state_t* get_state() { return &state; }
    const state_t* get_state() const { return &state; }
    extension_t* get_extension() { return extensions.empty() ? nullptr : extensions[0]; }
    disassembler_t* get_disassembler() { return disassembler; }
    void take_interrupt();
    void take_trap(trap_t& t, reg_t epc);
    bool supports_impl(uint32_t feature);
    bool extension_enabled(unsigned char ext) { return isa->extension_enabled(ext); }
    bool is_supported_isa(uint32_t feature);
    bool is_supported_xlen(uint32_t xlen);

    void register_insn(insn_desc_t desc);
    void register_extension(extension_t* x);
    void register_inst_fetch_callback(std::function<void(processor_t*, reg_t)> callback);
    void register_inst_trap_callback(std::function<void(processor_t*, reg_t, trap_t&)> callback);

    void set_privilege(reg_t val) { state.prv = val; }
    reg_t get_privilege() const { return state.prv; }
    bool get_tenable() const { return tenable; }

    void trace(uint32_t t, reg_t pc, insn_t insn);
    void trace_data(uint32_t t, reg_t addr, size_t len, uint8_t* bytes);
    void trace_opcode(uint32_t opcode, insn_t insn, reg_t pc, reg_t next_pc);
    void trace_trap(uint32_t t, trap_t& trap);
    void trace_mmu(uint32_t t, reg_t addr, size_t len, bool store, uint8_t* bytes);

private:
    const isa_parser_t* isa;
    mmu_t* mmu;
    state_t state;
    simif_t* sim;
    uint32_t id;
    bool halt_on_reset;
    bool log_commits_enabled;
    bool tenable;
    std::vector<insn_desc_t> instructions;
    std::vector<extension_t*> extensions;
    std::function<void(processor_t*, reg_t)> inst_fetch_callback;
    std::function<void(processor_t*, reg_t, trap_t&)> inst_trap_callback;
    disassembler_t* disassembler;
    opcode_cache_entry_t opcode_cache[OPCODE_CACHE_SIZE];

    void build_opcode_map();
    void parse_isa_string(const char* isa);

    reg_t illegal_instruction(insn_t insn, reg_t pc);
    reg_t custom_mymul(insn_t insn, reg_t pc);

    friend class mmu_t;
};

// Implementation of custom_mymul
reg_t custom_mymul(processor_t* p, insn_t insn, reg_t pc) {
    require_extension('C');
    WRITE_RD(sext_xlen(RVC_RS1(p->get_state(), insn) * RVC_RS2(p->get_state(), insn)));
    p->trace_opcode(MATCH_C_MYMUL, insn, pc, pc + insn_length(MATCH_C_MYMUL));
    return pc + insn_length(MATCH_C_MYMUL);
}

// Implementation of trace_opcode
void processor_t::trace_opcode(uint32_t opcode, insn_t insn, reg_t pc, reg_t next_pc) {
    // Fetch current PC value
    pc = state.pc;

    // Fetch register values
    reg_t rd = 0, rs1 = 0, rs2 = 0;
    if (insn.rd() != 0) rd = state.XPR[insn.rd()];
    if (insn.rs1() != 0) rs1 = state.XPR[insn.rs1()];
    if (insn.rs2() != 0) rs2 = state.XPR[insn.rs2()];

    // Print or log relevant information
    // Here we use printf as an example, you can change to write to a file or other logging methods
    printf("PC: 0x%016lx, opcode: 0x%08x, insn: 0x%08x\n", pc, opcode, insn.bits());
    printf("rd: x%2d=0x%016llx, rs1: x%2d=0x%016llx, rs2: x%2d=0x%016llx\n",
           insn.rd(), (unsigned long long)rd, insn.rs1(), (unsigned long long)rs1, insn.rs2(), (unsigned long long)rs2);

    // Add more debug information as needed
}

#endif // _RISCV_PROCESSOR_H
