use keystone::*;
use std::collections::HashMap;
use unicorn::{Cpu, CpuX86};

use super::interface::Machine;
pub fn new() -> Machine<'static> {
    let engine = Keystone::new(Arch::X86, keystone::keystone_const::MODE_32)
        .expect("Could not initialize Keystone engine");

    engine
        .option(OptionType::SYNTAX, keystone::OPT_SYNTAX_INTEL)
        .expect("Could not set option to nasm syntax");
    let mut map = HashMap::new();
    init_register_map(&mut map);
    let mut cpu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    cpu.reg_write(unicorn::RegisterX86::ESP, 0x01300000);
    cpu.reg_write(unicorn::RegisterX86::EBP, 0x10000000);
    cpu.mem_map(0x0000, 0x20000000, unicorn::PROT_ALL);

    let sorted_x86_reg_name = vec![
        "eax", "ebx", "ecx", "edx", "end", //
        "esi", "edi", "end", //
        "eip", "ebp", "esp", "end", //
        "flags", "end", //
        "cs", "ss", "ds", "es", "end", //
        "fs", "gs", "end", //
    ];

    return Machine {
        register_map: map,
        keystone: engine,
        emu: cpu,
        sorted_reg_names: sorted_x86_reg_name,
    };
}

fn init_register_map(m: &mut HashMap<&str, unicorn::RegisterX86>) {
    m.insert("eax", unicorn::RegisterX86::EAX);
    m.insert("ebx", unicorn::RegisterX86::EBX);
    m.insert("ecx", unicorn::RegisterX86::ECX);
    m.insert("edx", unicorn::RegisterX86::EDX);
    m.insert("esi", unicorn::RegisterX86::ESI);
    m.insert("edi", unicorn::RegisterX86::EDI);

    m.insert("eip", unicorn::RegisterX86::EIP);
    m.insert("ebp", unicorn::RegisterX86::EBP);
    m.insert("esp", unicorn::RegisterX86::ESP);
    m.insert("flags", unicorn::RegisterX86::EFLAGS);

    m.insert("cs", unicorn::RegisterX86::CS);
    m.insert("ss", unicorn::RegisterX86::SS);
    m.insert("ds", unicorn::RegisterX86::DS);
    m.insert("es", unicorn::RegisterX86::ES);
    m.insert("fs", unicorn::RegisterX86::FS);
    m.insert("gs", unicorn::RegisterX86::GS);
}
