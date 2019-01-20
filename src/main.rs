extern crate rustyline;
use rustyline::error::ReadlineError;
use rustyline::Editor;

pub mod machine;

use crate::machine::interface::Machine;

fn get_machine(arch_name : String) -> Machine <'static>{
    match arch_name.to_ascii_lowercase().as_str() {
        "x86" => return  machine::x32::new(),
        "x64" => return machine::x64::new(),
        _ => return machine::x64::new(),
    }
}

fn main() {
    let mut m : Machine = get_machine("x64".to_string());

    let args = std::env::args().collect::<Vec<String>>();
    if args.len() > 1 {
        m = get_machine(args[1].clone() );
    }

    m.print_register();
    m.print_stack();

    let mut rl = Editor::<()>::new();
    loop {
        let input = rl.readline(">> ");
        match input {
            Ok(line) => {
                let result = m.asm(line.to_string(),0);
                match result {
                    Ok(r) => {
                        m.write_instruction(r.bytes);
                        m.print_register();
                        m.print_stack();
                    }
                    Err(e) => println!("failed to assemble, err: {:?}", e),
                }
            },
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break
            },
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break
            },
            Err(err) => {
                println!("Error: {:?}", err);
                break
            }
        }
    }
}

