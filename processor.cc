#include "processor.h"

reg_t my_constant = 42; 
// 
void processor_t::trace_opcode(uint32_t opcode, insn_t insn, reg_t pc, reg_t next_pc) {
    // 
    pc = state.pc;

    // 
    reg_t rd = 0, rs1 = 0, rs2 = 0;
    if (insn.rd() != 0) rd = state.XPR[insn.rd()];
    if (insn.rs1() != 0) rs1 = state.XPR[insn.rs1()];
    if (insn.rs2() != 0) rs2 = state.XPR[insn.rs2()];

    // 
    // 
    printf("PC: 0x%016lx, opcode: 0x%08x, insn: 0x%08x\n", pc, opcode, insn.bits());
    printf("rd: x%2d=0x%016llx, rs1: x%2d=0x%016llx, rs2: x%2d=0x%016llx\n",
           insn.rd(), (unsigned long long)rd, insn.rs1(), (unsigned long long)rs1, insn.rs2(), (unsigned long long)rs2);
}

reg_t custom_mymul(processor_t* p, insn_t insn, reg_t pc) {
    require_extension('C');
    WRITE_RD(sext_xlen(RVC_RS1(p->get_state(), insn) * RVC_RS2(p->get_state(), insn)));
    p->trace_opcode(MATCH_C_MYMUL, insn, pc, pc + insn_length(MATCH_C_MYMUL));
    return pc + insn_length(MATCH_C_MYMUL);
}

insn_func_t processor_t::decode_insn(insn_t insn) {
    // 
    size_t idx = insn.bits() % OPCODE_CACHE_SIZE;
    auto [hit, desc] = opcode_cache[idx].lookup(insn.bits());

    bool rve = extension_enabled('E');

    if (unlikely(!hit)) {
        // 退回到线性搜索
        auto matching = [insn_bits = insn.bits()](const insn_desc_t &d) {
            return (insn_bits & d.mask) == d.match;
        };
        auto p = std::find_if(custom_instructions.begin(),
                              custom_instructions.end(), matching);
        if (p == custom_instructions.end()) {
            p = std::find_if(instructions.begin(), instructions.end(), matching);
            assert(p != instructions.end());
        }
        desc = &*p;
        opcode_cache[idx].replace(insn.bits(), desc);
    }

    return desc->func(xlen, rve, log_commits_enabled);
}

void processor_t::register_insn(insn_desc_t desc, bool is_custom) {
    assert(desc.fast_rv32i && desc.fast_rv64i && desc.fast_rv32e && desc.fast_rv64e &&
           desc.logged_rv32i && desc.logged_rv64i && desc.logged_rv32e && desc.logged_rv64e);

    if (is_custom)
        custom_instructions.push_back(desc);
    else
        instructions.push_back(desc);
}

void processor_t::build_opcode_map() {
    for (size_t i = 0; i < OPCODE_CACHE_SIZE; i++)
        opcode_cache[i].reset();
}

void processor_t::register_extension(extension_t *x) {
    for (auto insn : x->get_instructions())
        register_custom_insn(insn);
    build_opcode_map();

    for (auto disasm_insn : x->get_disasms())
        disassembler->add_insn(disasm_insn);

    if (!custom_extensions.insert(std::make_pair(x->name(), x)).second) {
        fprintf(stderr, "extensions must have unique names (got two named \"%s\"!)\n", x->name());
        abort();
    }
    x->set_processor(this);
}

void processor_t::register_base_instructions() {
    #define DECLARE_INSN(name, match, mask) \
        insn_bits_t name##_match = (match), name##_mask = (mask); \
        isa_extension_t name##_ext = NUM_ISA_EXTENSIONS; \
        bool name##_overlapping = false;

    #include "encoding.h"
    #undef DECLARE_INSN

    #define DEFINE_INSN(name) \
        extern reg_t fast_rv32i_##name(processor_t*, insn_t, reg_t); \
        extern reg_t fast_rv64i_##name(processor_t*, insn_t, reg_t); \
        extern reg_t fast_rv32e_##name(processor_t*, insn_t, reg_t); \
        extern reg_t fast_rv64e_##name(processor_t*, insn_t, reg_t); \
        extern reg_t logged_rv32i_##name(processor_t*, insn_t, reg_t); \
        extern reg_t logged_rv64i_##name(processor_t*, insn_t, reg_t); \
        extern reg_t logged_rv32e_##name(processor_t*, insn_t, reg_t); \
        extern reg_t logged_rv64e_##name(processor_t*, insn_t, reg_t);
    #include "insn_list.h"
    #undef DEFINE_INSN

    //
    #define DECLARE_OVERLAP_INSN(name, ext) \
        name##_overlapping = true; \
        if (isa->extension_enabled(ext)) \
            register_base_insn((insn_desc_t) { \
                name##_match, \
                name##_mask, \
                fast_rv32i_##name, \
                fast_rv64i_##name, \
                fast_rv32e_##name, \
                fast_rv64e_##name, \
                logged_rv32i_##name, \
                logged_rv64i_##name, \
                logged_rv32e_##name, \
                logged_rv64e_##name});
    #include "overlap_list.h"
    #undef DECLARE_OVERLAP_INSN

    // 
    #define DEFINE_INSN(name) \
        if (!name##_overlapping) \
            register_base_insn((insn_desc_t) { \
                name##_match, \
                name##_mask, \
                fast_rv32i_##name, \
                fast_rv64i_##name, \
                fast_rv32e_##name, \
                fast_rv64e_##name, \
                logged_rv32i_##name, \
                logged_rv64i_##name, \
                logged_rv32e_##name, \
                logged_rv64e_##name});
    #include "insn_list.h"
    #undef DEFINE_INSN

    // 
    register_base_insn(insn_desc_t::illegal_instruction);

    build_opcode_map();
}
