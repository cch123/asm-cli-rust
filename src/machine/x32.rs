use std::collections::HashMap;
use keystone::*;
use unicorn::{Cpu, CpuX86};

pub struct X86Machine<'a> {
    pub register_map: HashMap<&'a str, unicorn::RegisterX86>,
    pub keystone: keystone::Keystone,
    pub emu : unicorn::CpuX86,
}

impl <'a>X86Machine <'a>{
    pub fn new() -> Self {
        let engine = Keystone::new(Arch::X86, keystone::keystone_const::MODE_64)
            .expect("Could not initialize Keystone engine");

        engine
            .option(OptionType::SYNTAX, keystone::OPT_SYNTAX_NASM)
            .expect("Could not set option to nasm syntax");
        let mut map = HashMap::new();
        X86Machine::init_register_map(&mut map);
        let cpu = CpuX86::new(unicorn::Mode::MODE_64).expect("failed to instantiate emulator");

        return X86Machine {
            register_map: map,
            keystone: engine,
            emu: cpu,
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

    pub fn print_register(&self) {
        let sorted_x86_reg_name = vec![
            "eax", "ebx", "ecx", "edx", "end",
            "esi", "edi", "end",
            "eip", "ebp", "esp", "end",
            "eflags", "end",
            "cs", "ss", "ds", "es", "end",
            "fs", "gs", "end",
        ];

        println!("----------------- cpu context -----------------");

        for reg_name in sorted_x86_reg_name {
            if reg_name == "end" {
                println!();
                continue;
            }

            let &uc_reg = self.register_map.get(reg_name).unwrap();

            // pad reg_name to 3 bytes
            let mut reg_name = reg_name.to_string();
            while reg_name.len() < 3 {
                reg_name.push(' ');
            }

            print!("{} : {} ", reg_name, self.emu.reg_read(uc_reg).unwrap());
        }

        println!("----------------- stack context -----------------");
    }
}
