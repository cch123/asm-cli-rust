use keystone::{AsmResult,Error};
use std::collections::HashMap;
use keystone::*;
use unicorn::{Cpu, CpuX86};

pub trait Interface {
    fn print_stack(&self);
    fn print_register(&self);
    fn asm(&self, str: String, address: u64) -> Result<AsmResult, Error>;
    fn write_instruction(&self, byte_arr: Vec<u8>);
}


pub struct Machine <'a> {
    pub register_map: HashMap<&'a str, unicorn::RegisterX86>,
    pub keystone: keystone::Keystone,
    pub emu : unicorn::CpuX86,
    pub sorted_reg_names : Vec<&'a str>
}

impl <'a>Machine<'a> {
    pub fn print_register(&self) {

        println!("----------------- cpu context -----------------");

        // 不写 clone 会报 cannot move out of borrowed content
        for reg_name in self.sorted_reg_names.clone() {
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

            print!("{} : {:016x} ", reg_name, self.emu.reg_read(uc_reg).unwrap());
        }

        println!("----------------- stack context -----------------");
    }

    pub fn asm(&self, str: String, address: u64) -> Result<AsmResult, Error>{
        return self.keystone.asm(str,address);
    }

    pub fn write_instruction(&self, byte_arr: Vec<u8>) {
        let _ = self.emu.mem_write(0x0000, &byte_arr);
        let _ = self.emu.emu_start(
            0x0000,
            (0x0000 + byte_arr.len()) as u64,
            10 * unicorn::SECOND_SCALE,
            1000,
        );
    }

    pub fn print_stack(&self) {
        let start_address = 0x1300000-64;
        let mem_data = self.emu.mem_read(start_address,8*4*5).unwrap();
        // 8 个字节打印一次
        (0..mem_data.len()).step_by(32).for_each(|idx|{
            print!("{:016x} :", start_address + idx as u64);
            (0..4).for_each(|offset|{
                let mut cur = mem_data[idx+offset*8..idx+offset*8+8].to_vec();
                cur.reverse();
                print!("{} ", hex::encode(cur));
            });
            println!();
        });
    }

}
