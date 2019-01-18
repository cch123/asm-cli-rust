use std::collections::HashMap;
use keystone::*;
use unicorn::{Cpu, CpuX86};

pub struct X64Machine<'a> {
    register_map: HashMap<&'a str, unicorn::RegisterX86>,
    keystone: keystone::Keystone,
}

impl <'a>X64Machine <'a>{
    pub fn new() -> Self {
        let engine = Keystone::new(Arch::X86, keystone::keystone_const::MODE_64)
            .expect("Could not initialize Keystone engine");

        engine
            .option(OptionType::SYNTAX, keystone::OPT_SYNTAX_NASM)
            .expect("Could not set option to nasm syntax");
        let mut map = HashMap::new();
        X64Machine::init_register_map(&mut map);

        return X64Machine {
            register_map: map,
            keystone: engine,
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

    fn print_register(emu: &unicorn::CpuX86) {
        let mut map = HashMap::new();
        X64Machine::init_register_map(&mut map);

        let mut sorted_x64_reg_name = vec![
            "rax", "rbx", "rcx", "rdx", "end",
            "rsi", "rdi", "r8", "r9", "end",
            "r10", "r11", "r12", "r13", "end",
            "r14", "r15", "end",
            "rip", "rbp", "rsp", "end",
            "cs", "ss", "ds", "es", "end",
            "fs", "gs", "end", "flags", "end",
        ];

        println!("----------------- cpu context -----------------");

        for reg_name in sorted_x64_reg_name {
            if reg_name == "end" {
                println!();
                continue;
            }

            let &uc_reg = map.get(reg_name).unwrap();

            // pad reg_name to 3 bytes
            let mut reg_name = reg_name.to_string();
            while reg_name.len() < 3 {
                reg_name.push(' ');
            }

            print!("{} : {} ", reg_name, emu.reg_read(uc_reg).unwrap());
        }

        println!("----------------- stack context -----------------");
    }
}
