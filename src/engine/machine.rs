use ansi_term::Colour::{Blue, Purple, Yellow};
use keystone::{AsmResult, Error};
use std::collections::HashMap;
use unicorn_engine::unicorn_const::uc_error;
use unicorn_engine::unicorn_const::SECOND_SCALE;
use unicorn_engine::Unicorn;

use super::cpu;

#[derive(Debug)]
pub enum MachineError {
    Unsupported,
    Keystone(keystone::Error),
    Unicorn(uc_error),
}

pub struct Machine<'a> {
    pub register_map: HashMap<&'a str, i32>,
    pub assembler: keystone::Keystone,
    pub emu: Unicorn<'static, ()>,
    pub sorted_reg_names: Vec<&'a str>,
    pub byte_size: usize,
    pub previous_reg_value: HashMap<&'a str, u64>,
    pub cpu: (cpu::Arch, cpu::Mode),
    pub sp: i32, // stack pointer
    pub fp: i32, // stack frame
}

impl<'a> Machine<'a> {
    pub fn new(arch: cpu::Arch, mode: cpu::Mode) -> Result<Self, MachineError> {
        let emu = Self::init_unicorn(arch, mode)?;
        let assembler = Self::init_keystone(arch, mode)?;
        let arch_meta = Self::get_arch_meta(arch, mode)?;

        let register_map = arch_meta.register_map();
        let prev_reg_value = arch_meta.dump_registers(&emu);

        Ok(Self {
            emu,
            assembler,

            register_map,
            sorted_reg_names: arch_meta.sorted_reg_names(),
            byte_size: arch_meta.int_size(),
            previous_reg_value: prev_reg_value,
            cpu: arch_meta.cpu(),

            sp: arch_meta.sp_reg(),
            fp: arch_meta.fp_reg(),
        })
    }

    pub fn new_from_arch(arch_name: &str) -> Result<Self, MachineError> {
        let arch_meta = Self::get_arch_meta_from_name(arch_name)?;
        let cpu = arch_meta.cpu();
        Self::new(cpu.0, cpu.1)
    }

    pub(crate) fn init_unicorn(
        arch: cpu::Arch,
        mode: cpu::Mode,
    ) -> Result<Unicorn<'static, ()>, MachineError> {
        Unicorn::new(arch.into(), mode.into()).map_err(MachineError::Unicorn)
    }

    pub(crate) fn init_keystone(
        arch: cpu::Arch,
        mode: cpu::Mode,
    ) -> Result<keystone::Keystone, MachineError> {
        keystone::Keystone::new(arch.into(), mode.into()).map_err(MachineError::Keystone)
    }

    pub(crate) fn get_arch_name(
        arch: cpu::Arch,
        mode: cpu::Mode,
    ) -> Result<&'static str, MachineError> {
        match arch {
            cpu::Arch::X86 => match mode {
                cpu::Mode::Mode32 => Ok("x32"),
                cpu::Mode::Mode64 => Ok("x64"),
                // _ => Err(MachineError::Unsupported),
            },
            // _ => Err(MachineError::Unsupported),
        }
    }

    pub(crate) fn get_arch_meta(
        arch: cpu::Arch,
        mode: cpu::Mode,
    ) -> Result<Box<dyn cpu::ArchMeta>, MachineError> {
        let arch_name = Self::get_arch_name(arch, mode)?;
        Self::get_arch_meta_from_name(arch_name)
    }

    pub(crate) fn get_arch_meta_from_name(
        arch_name: &str,
    ) -> Result<Box<dyn cpu::ArchMeta>, MachineError> {
        match arch_name {
            "x32" => Ok(Box::new(cpu::X32::new(cpu::Arch::X86))),
            "x64" => Ok(Box::new(cpu::X64::new(cpu::Arch::X86))),
            _ => Err(MachineError::Unsupported),
        }
    }

    pub fn set_sp(&mut self, value: u64) -> Result<(), MachineError> {
        self.emu
            .reg_write(self.sp, value)
            .map_err(MachineError::Unicorn)
    }
    pub fn set_fp(&mut self, value: u64) -> Result<(), MachineError> {
        self.emu
            .reg_write(self.fp, value)
            .map_err(MachineError::Unicorn)
    }
}

impl<'a> Machine<'a> {
    pub fn print_machine(&self) {
        println!("arch: {:?} mode: {:?}", self.cpu.0, self.cpu.1);
    }
    pub fn print_register(&mut self) {
        println!(
            "{}",
            Yellow.paint("----------------- cpu context -----------------")
        );

        let mut current_reg_val_map = HashMap::new();
        for &reg_name in &self.sorted_reg_names {
            if reg_name == "end" {
                println!();
                continue;
            }

            let &uc_reg = self.register_map.get(reg_name).unwrap();

            // pad reg_name to 3 bytes
            let mut padded_reg_name = reg_name.to_string();
            while padded_reg_name.len() < 3 {
                padded_reg_name.push(' ');
            }

            let reg_val = self.emu.reg_read(uc_reg).unwrap();
            let previous_reg_val = *self.previous_reg_value.get(reg_name).unwrap();

            let reg_val_str = match self.byte_size {
                4 => format!("0x{:08x}", reg_val),
                8 => format!("0x{:016x}", reg_val),
                _ => unreachable!(),
            };

            if previous_reg_val != reg_val {
                print!("{} : {} ", padded_reg_name, Blue.paint(reg_val_str));
            } else {
                print!("{} : {} ", padded_reg_name, reg_val_str);
            }
            current_reg_val_map.insert(reg_name, reg_val);
            if reg_name == "flags" {
                self.print_flags(reg_val);
            }
        }
        self.previous_reg_value = current_reg_val_map;
    }

    pub fn asm(&self, str: String, address: u64) -> Result<AsmResult, Error> {
        self.assembler.asm(str, address)
    }

    pub fn write_instruction(&mut self, byte_arr: Vec<u8>) {
        let address = 0x0000;
        let _ = self.emu.mem_write(address, &byte_arr);
        let _ = self.emu.emu_start(
            address,
            address + byte_arr.len() as u64,
            10 * SECOND_SCALE,
            1000,
        );
    }

    pub fn print_stack(&self) {
        println!(
            "{}",
            Purple.paint("----------------- stack context -----------------")
        );
        let cur_sp_val = self.emu.reg_read(self.sp).unwrap();

        //let start_address = (0x1300000 - 8 * self.byte_size) as u64;
        let mut start_address: u64 = 0x1300000;
        while cur_sp_val < start_address - 4 * self.byte_size as u64 {
            start_address -= 4 * self.byte_size as u64;
        }
        start_address -= 8 * self.byte_size as u64;
        let mem_data = self
            .emu
            .mem_read_as_vec(start_address, self.byte_size * 4 * 5)
            .unwrap();

        // 8 个字节打印一次
        (0..mem_data.len())
            .step_by(4 * self.byte_size)
            .for_each(|idx| {
                match self.byte_size {
                    4 => print!("{:08x} : ", start_address + idx as u64),
                    8 => print!("{:016x} : ", start_address + idx as u64),
                    _ => unreachable!(),
                }

                (0..4).for_each(|offset| {
                    let (start_pos, end_pos) = (
                        idx + offset * self.byte_size,
                        idx + offset * self.byte_size + self.byte_size,
                    );
                    let mut cur = mem_data[start_pos..end_pos].to_vec();
                    cur.reverse();
                    if (start_address + start_pos as u64) == cur_sp_val {
                        print!("{} ", Blue.paint(hex::encode(cur)));
                    } else {
                        print!("{} ", hex::encode(cur));
                    }
                });
                println!();
            });
        println!();
    }

    fn print_flags(&self, flag_val: u64) {
        let flag_names = vec!["cf", "zf", "of", "sf", "pf", "af", "df"];
        let name_to_bit = vec![
            ("cf", 0),
            ("pf", 2),
            ("af", 4),
            ("zf", 6),
            ("sf", 7),
            ("df", 10),
            ("of", 11),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();

        for flag_name in flag_names {
            let bit_pos = name_to_bit.get(flag_name).unwrap();
            let flag_val = flag_val >> (*bit_pos as u64) & 1;
            match flag_val {
                0 => print!("{}({}) ", flag_name, flag_val),
                1 => print!("{} ", Blue.paint(format!("{}({})", flag_name, flag_val))),
                _ => unreachable!(),
            }
        }
    }
}
