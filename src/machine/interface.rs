use keystone::{AsmResult, Error};
use std::collections::HashMap;
use unicorn::Cpu;

extern crate ansi_term;
use ansi_term::Colour::{Blue, Purple, Yellow};

pub struct Machine<'a> {
    pub register_map: HashMap<&'a str, unicorn::RegisterX86>,
    pub keystone: keystone::Keystone,
    pub emu: unicorn::CpuX86,
    pub sorted_reg_names: Vec<&'a str>,
    pub byte_size: usize,
    pub previous_reg_value: HashMap<&'a str, u64>,
    pub sp: unicorn::RegisterX86,
}

impl<'a> Machine<'a> {
    pub fn print_register(&mut self) {
        println!(
            "{}",
            Yellow.paint("----------------- cpu context -----------------")
        );

        let mut current_reg_val_map = HashMap::new();
        // 不写 clone 会报 cannot move out of borrowed content
        for reg_name in self.sorted_reg_names.clone() {
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
            let mut reg_val_str: String;
            match self.byte_size {
                4 => reg_val_str = format!("0x{:08x}", reg_val),
                8 => reg_val_str = format!("0x{:016x}", reg_val),
                _ => unreachable!(),
            }

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
        return self.keystone.asm(str, address);
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
        println!(
            "{}",
            Purple.paint("----------------- stack context -----------------")
        );
        let cur_sp_val = self.emu.reg_read(self.sp).unwrap();

        //let start_address = (0x1300000 - 8 * self.byte_size) as u64;
        let mut start_address = 0x1300000;
        while cur_sp_val < start_address - 4 * self.byte_size as u64 {
            start_address = start_address - 4 * self.byte_size as u64;
        }
        start_address = start_address - 8 * self.byte_size as u64;
        let mem_data = self
            .emu
            .mem_read(start_address as u64, self.byte_size * 4 * 5)
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
            let flag_val = flag_val >> (*bit_pos as u64) & 1 as u64;
            match flag_val {
                0 => print!("{}({}) ", flag_name, flag_val),
                1 => print!("{} ", Blue.paint( format!("{}({})",flag_name, flag_val) )),
                _ => unreachable!()
            }
        }
    }
}

/*
func readFlagVals(flags uint64) map[string]int {
    res := make(map[string]int)
    // cf:0 zf:0 of:0 sf:0 pf:0 af:0 df:0
    flagNames := []string{"cf", "zf", "of", "sf", "pf", "af", "df"}
    var nameToBitMap = map[string]uint{
        "cf": 0,
        "pf": 2,
        "af": 4,
        "zf": 6,
        "sf": 7,
        "df": 10,
        "of": 11,
    }
    for _, flagName := range flagNames {
        bitPos := nameToBitMap[flagName]

        res[flagName] = 0
        if flags>>bitPos&1 > 0 {
            res[flagName] = 1
        }
    }
    return res
}
*/
