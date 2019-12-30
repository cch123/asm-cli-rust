use keystone::*;
use std::collections::HashMap;
use unicorn::{Cpu, CpuX86};

use super::interface::Machine;
use maplit::hashmap;

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
        byte_size: 4,
        previous_reg_value: previous_reg_val_map,
        sp: unicorn::RegisterX86::ESP,
    }
}

fn unicorn_vm() -> CpuX86 {
    let cpu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    cpu.reg_write(unicorn::RegisterX86::ESP, 0x01300000)
        .expect("failed to write to esp");
    cpu.reg_write(unicorn::RegisterX86::EBP, 0x10000000)
        .expect("failed to write ebp");
    cpu.mem_map(0x0000, 0x20000000, unicorn::Protection::ALL)
        .expect("failed to map memory");

    cpu
}

fn keystone_engine() -> keystone::Keystone {
    let engine = Keystone::new(Arch::X86, keystone::keystone_const::MODE_32)
        .expect("Could not initialize Keystone engine");

    engine
        .option(OptionType::SYNTAX, keystone::OPT_SYNTAX_INTEL)
        .expect("Could not set option to nasm syntax");

    engine
}

fn sorted_reg_names() -> Vec<&'static str> {
    vec![
        "eax", "ebx", "ecx", "edx", "end", //
        "esi", "edi", "end", //
        "eip", "ebp", "esp", "end", //
        "flags", "end", //
        "cs", "ss", "ds", "es", "end", //
        "fs", "gs", "end", //
    ]
}

fn init_register_map() -> HashMap<&'static str, unicorn::RegisterX86> {
    hashmap! {
        "eax" => unicorn::RegisterX86::EAX,
        "ebx" => unicorn::RegisterX86::EBX,
        "ecx" => unicorn::RegisterX86::ECX,
        "edx" => unicorn::RegisterX86::EDX,
        "esi" => unicorn::RegisterX86::ESI,
        "edi" => unicorn::RegisterX86::EDI,
        "eip" => unicorn::RegisterX86::EIP,
        "ebp" => unicorn::RegisterX86::EBP,
        "esp" => unicorn::RegisterX86::ESP,
        "flags" => unicorn::RegisterX86::EFLAGS,
        "cs" => unicorn::RegisterX86::CS,
        "ss" => unicorn::RegisterX86::SS,
        "ds" => unicorn::RegisterX86::DS,
        "es" => unicorn::RegisterX86::ES,
        "fs" => unicorn::RegisterX86::FS,
        "gs" => unicorn::RegisterX86::GS,
    }
}

fn previous_reg_value_map(emu: &CpuX86) -> HashMap<&'static str, u64> {
    let reg_names = sorted_reg_names();
    let register_map = init_register_map();
    reg_names
        .iter()
        .filter(|&&x| x != "end")
        .map(|&reg_name| {
            (
                reg_name,
                emu.reg_read(*register_map.get(reg_name).unwrap()).unwrap(),
            )
        })
        .collect::<HashMap<_, _>>()
}
