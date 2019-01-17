use capstone::prelude::*;

const X86_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\x14\x9e\x08\x00\x45\x31\xe4";

/// Print register names
fn reg_names<T, I>(cs: &Capstone, regs: T) -> String
    where
        T: Iterator<Item = I>,
        I: Into<RegId>,
{
    let names: Vec<String> = regs.map(|x| cs.reg_name(x.into()).unwrap()).collect();
    names.join(", ")
}

/// Print instruction group names
fn group_names<T, I>(cs: &Capstone, regs: T) -> String
    where
        T: Iterator<Item = I>,
        I: Into<InsnGroupId>,
{
    let names: Vec<String> = regs.map(|x| cs.group_name(x.into()).unwrap()).collect();
    names.join(", ")
}

fn example() -> CsResult<()> {
    let mut cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()?;

    let insns = cs.disasm_all(X86_CODE, 0x1000)?;
    println!("Found {} instructions", insns.len());
    for i in insns.iter() {
        println!("");
        println!("{}", i);

        let detail: InsnDetail = cs.insn_detail(&i)?;
        let output: &[(&str, String)] = &[
            ("read regs:", reg_names(&cs, detail.regs_read())),
            ("write regs:", reg_names(&cs, detail.regs_write())),
            ("insn groups:", group_names(&cs, detail.groups())),
        ];

        for &(ref name, ref message) in output.iter() {
            println!("    {:12} {}", name, message);
        }
    }
    Ok(())
}

fn main() {
    loop {
        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(n) => {
                println!("{} bytes read", n);
                println!("{}", input);
            }
            Err(error) => println!("error: {}", error),
        }
        println!("input your commands");
        if let Err(err) = example() {
            println!("Error: {}", err);
        }
    }
}


