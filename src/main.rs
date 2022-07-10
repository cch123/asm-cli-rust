use ansi_term::Colour::Red;
use rustyline::error::ReadlineError;
use rustyline::{Editor, KeyEvent, Cmd, KeyCode, Modifiers};

use std::env;

pub mod machine;

use crate::machine::interface::Machine;

fn get_machine(arch_name: String) -> Machine<'static> {
    match arch_name.to_ascii_lowercase().as_str() {
        "x86" => machine::x32::new(),
        "x64" => machine::x64::new(),
        _ => machine::x64::new(),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let arch_name = match args.get(1) {
        Some(r) => r.clone(),
        None => "x64".to_string(),
    };
    let mut m: Machine = get_machine(arch_name);

    m.print_register();
    m.print_stack();

    let mut rl = Editor::<()>::new();
    rl.bind_sequence(KeyEvent(KeyCode::Down, Modifiers::NONE), Cmd::NextHistory);
    rl.bind_sequence(KeyEvent(KeyCode::Up, Modifiers::NONE), Cmd::PreviousHistory);

    loop {
        let input = rl.readline(Red.paint(">> ").to_string().as_str());
        match input {
            Ok(line) => {
                let result = m.asm(line.to_string(), 0);
                match result {
                    Ok(r) => {
                        rl.add_history_entry(line.as_str());
                        println!(
                            "{} : {} {} : {}",
                            Red.paint("mnemonic"),
                            line.trim(),
                            Red.paint("hex"),
                            r
                        );
                        m.write_instruction(r.bytes);
                        m.print_register();
                        m.print_stack();
                    }
                    Err(e) => println!("failed to assemble, err: {:?}", e),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
}
