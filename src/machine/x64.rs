use keystone::*;
use std::collections::HashMap;
use unicorn::{Cpu, CpuX86};

use super::interface::Machine;

pub fn new() -> Machine<'static> {
    let reg_map = init_register_map();
    let reg_names = sorted_reg_names();
    let cpu = unicorn_vm();
    let previous_reg_val_map = previous_reg_value_map(&cpu);

    Machine {
        register_map: reg_map,
        keystone: keystone_engine(),
        emu: cpu,
        sorted_reg_names: reg_names,
        byte_size: 8,
        previous_reg_value : previous_reg_val_map,
        sp : unicorn::RegisterX86::RSP,
    }
}

fn unicorn_vm() -> CpuX86 {
    let cpu = CpuX86::new(unicorn::Mode::MODE_64).expect("failed to instantiate emulator");
    cpu.reg_write(unicorn::RegisterX86::RSP, 0x01300000)
        .expect("failed to write to rsp");
    cpu.reg_write(unicorn::RegisterX86::RBP, 0x10000000)
        .expect("failed to write to rbp");
    cpu.mem_map(0x0000, 0x20000000, unicorn::Protection::ALL)
        .expect("failed to map memory");

    cpu
}

fn keystone_engine() -> keystone::Keystone {
    let engine = Keystone::new(Arch::X86, keystone::keystone_const::MODE_64)
        .expect("Could not initialize Keystone engine");

    engine
        .option(OptionType::SYNTAX, keystone::OPT_SYNTAX_INTEL)
        .expect("Could not set option to nasm syntax");

    engine
}

fn sorted_reg_names() -> Vec<&'static str> {
    vec![
        "rax", "rbx", "rcx", "rdx", "end", //
        "rsi", "rdi", "r8", "r9", "end", //
        "r10", "r11", "r12", "r13", "end", //
        "r14", "r15", "end", //
        "rip", "rbp", "rsp", "end", //
        "cs", "ss", "ds", "es", "end", //
        "fs", "gs", "end", "flags", "end", //
    ]
}

fn init_register_map() -> HashMap<&'static str, unicorn::RegisterX86> {
    vec![
        ("rax", unicorn::RegisterX86::RAX),
        ("rbx", unicorn::RegisterX86::RBX),
        ("rcx", unicorn::RegisterX86::RCX),
        ("rdx", unicorn::RegisterX86::RDX),
        ("rsi", unicorn::RegisterX86::RSI),
        ("rdi", unicorn::RegisterX86::RDI),
        ("r8", unicorn::RegisterX86::R8),
        ("r9", unicorn::RegisterX86::R9),
        ("r10", unicorn::RegisterX86::R10),
        ("r11", unicorn::RegisterX86::R11),
        ("r12", unicorn::RegisterX86::R12),
        ("r13", unicorn::RegisterX86::R13),
        ("r14", unicorn::RegisterX86::R14),
        ("r15", unicorn::RegisterX86::R15),
        ("rip", unicorn::RegisterX86::RIP),
        ("rbp", unicorn::RegisterX86::RBP),
        ("rsp", unicorn::RegisterX86::RSP),
        ("flags", unicorn::RegisterX86::EFLAGS),
        ("cs", unicorn::RegisterX86::CS),
        ("ss", unicorn::RegisterX86::SS),
        ("ds", unicorn::RegisterX86::DS),
        ("es", unicorn::RegisterX86::ES),
        ("fs", unicorn::RegisterX86::FS),
        ("gs", unicorn::RegisterX86::GS),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>()
}

fn previous_reg_value_map(emu : &CpuX86) -> HashMap<&'static str, u64> {
    let reg_names = sorted_reg_names();
    let register_map = init_register_map();
    reg_names.iter().filter(|&&x| x != "end").map(|&reg_name|{
        (reg_name, emu.reg_read(*register_map.get(reg_name).unwrap()).unwrap())
    }).collect::<HashMap<_,_>>()
}