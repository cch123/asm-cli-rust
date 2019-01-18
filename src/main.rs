pub mod machine;

//use keystone::*;
use unicorn::Cpu;
//use std::collections::HashMap;

use crate::machine::interface::Interface;
fn get_trait() -> impl Interface {
    let m = machine::x64::X64Machine::new();
    return m;
}

fn main() {
    //let m = get_trait();
    let m = machine::x64::X64Machine::new();
    loop {
        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(n) => {
                let result = m.keystone.asm(input.to_string(),0);
                match result {
                    Ok(r) => {
                        let _ = m.emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL);
                        let _ = m.emu.mem_write(0x1000, &r.bytes);

                        let _ = m.emu.emu_start(
                            0x1000,
                            (0x1000 + r.bytes.len()) as u64,
                            10 * unicorn::SECOND_SCALE,
                            1000,
                        );
                        m.print_register()
                    }
                    Err(e) => println!("failed to assemble, err: {:?}", e),
                }
            }
            Err(error) => println!("error when read your input: {}", error),
        }
        println!();
    }
}
