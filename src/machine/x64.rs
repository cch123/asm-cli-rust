use keystone::*;
use std::collections::HashMap;
use unicorn::{Cpu, CpuX86};

use super::interface::Machine;

pub fn new() -> Machine<'static> {
    let engine = Keystone::new(Arch::X86, keystone::keystone_const::MODE_64)
        .expect("Could not initialize Keystone engine");

    engine
        .option(OptionType::SYNTAX, keystone::OPT_SYNTAX_INTEL)
        .expect("Could not set option to nasm syntax");
    let mut map = HashMap::new();
    init_register_map(&mut map);
    let mut cpu = CpuX86::new(unicorn::Mode::MODE_64).expect("failed to instantiate emulator");
    cpu.reg_write(unicorn::RegisterX86::RSP, 0x01300000);
    cpu.reg_write(unicorn::RegisterX86::RBP, 0x10000000);
    cpu.mem_map(0x0000, 0x20000000, unicorn::PROT_ALL);

    let sorted_x64_reg_name = vec![
        "rax", "rbx", "rcx", "rdx", "end", //
        "rsi", "rdi", "r8", "r9", "end", //
        "r10", "r11", "r12", "r13", "end", //
        "r14", "r15", "end", //
        "rip", "rbp", "rsp", "end", //
        "cs", "ss", "ds", "es", "end", //
        "fs", "gs", "end", "flags", "end", //
    ];

    return Machine {
        register_map: map,
        keystone: engine,
        emu: cpu,
        sorted_reg_names: sorted_x64_reg_name,
    };
}

fn init_register_map(m: &mut HashMap<&str, unicorn::RegisterX86>) {
    m.insert("rax", unicorn::RegisterX86::RAX);
    m.insert("rbx", unicorn::RegisterX86::RBX);
    m.insert("rcx", unicorn::RegisterX86::RCX);
    m.insert("rdx", unicorn::RegisterX86::RDX);
    m.insert("rsi", unicorn::RegisterX86::RSI);
    m.insert("rdi", unicorn::RegisterX86::RDI);
    m.insert("r8", unicorn::RegisterX86::R8);
    m.insert("r9", unicorn::RegisterX86::R9);
    m.insert("r10", unicorn::RegisterX86::R10);
    m.insert("r11", unicorn::RegisterX86::R11);
    m.insert("r12", unicorn::RegisterX86::R12);
    m.insert("r13", unicorn::RegisterX86::R13);
    m.insert("r14", unicorn::RegisterX86::R14);
    m.insert("r15", unicorn::RegisterX86::R15);

    m.insert("rip", unicorn::RegisterX86::RIP);
    m.insert("rbp", unicorn::RegisterX86::RBP);
    m.insert("rsp", unicorn::RegisterX86::RSP);
    m.insert("flags", unicorn::RegisterX86::EFLAGS);

    m.insert("cs", unicorn::RegisterX86::CS);
    m.insert("ss", unicorn::RegisterX86::SS);
    m.insert("ds", unicorn::RegisterX86::DS);
    m.insert("es", unicorn::RegisterX86::ES);
    m.insert("fs", unicorn::RegisterX86::FS);
    m.insert("gs", unicorn::RegisterX86::GS);
}
