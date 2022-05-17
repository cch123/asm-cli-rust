use keystone::*;
use std::collections::HashMap;

use unicorn_engine::unicorn_const::{Arch, Mode, Permission};
use unicorn_engine::RegisterX86;
use unicorn_engine::Unicorn;

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
        sp: RegisterX86::ESP,
    }
}

fn unicorn_vm() -> Unicorn<'static, ()> {
    let mut cpu = Unicorn::new(Arch::X86, Mode::MODE_32).expect("failed to instantiate emulator");
    cpu.reg_write(RegisterX86::ESP, 0x01300000)
        .expect("failed to write to esp");
    cpu.reg_write(RegisterX86::EBP, 0x10000000)
        .expect("failed to write ebp");
    cpu.mem_map(0x0000, 0x20000000, Permission::ALL)
        .expect("failed to map memory");

    cpu
}

fn keystone_engine() -> keystone::Keystone {
    let engine = Keystone::new(keystone::Arch::X86, keystone::Mode::MODE_32)
        .expect("Could not initialize Keystone engine");

    engine
        .option(OptionType::SYNTAX, keystone::OptionValue::SYNTAX_INTEL)
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

fn init_register_map() -> HashMap<&'static str, RegisterX86> {
    hashmap! {
        "eax"   => RegisterX86::EAX,
        "ebx"   => RegisterX86::EBX,
        "ecx"   => RegisterX86::ECX,
        "edx"   => RegisterX86::EDX,
        "esi"   => RegisterX86::ESI,
        "edi"   => RegisterX86::EDI,
        "eip"   => RegisterX86::EIP,
        "ebp"   => RegisterX86::EBP,
        "esp"   => RegisterX86::ESP,
        "flags" => RegisterX86::EFLAGS,
        "cs"    => RegisterX86::CS,
        "ss"    => RegisterX86::SS,
        "ds"    => RegisterX86::DS,
        "es"    => RegisterX86::ES,
        "fs"    => RegisterX86::FS,
        "gs"    => RegisterX86::GS,
    }
}

fn previous_reg_value_map(emu: &Unicorn<'static, ()>) -> HashMap<&'static str, u64> {
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
