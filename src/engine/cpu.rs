use std::{collections::HashMap, convert::TryFrom};

use maplit::hashmap;
use unicorn_engine::{unicorn_const, RegisterX86, Unicorn};

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    Mode32,
    Mode64,
}

#[allow(clippy::from_over_into)]
impl Into<unicorn_const::Mode> for Mode {
    fn into(self) -> unicorn_const::Mode {
        match self {
            Self::Mode32 => unicorn_const::Mode::MODE_32,
            Self::Mode64 => unicorn_const::Mode::MODE_64,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<keystone::Mode> for Mode {
    fn into(self) -> keystone::Mode {
        match self {
            Self::Mode32 => keystone::Mode::MODE_32,
            Self::Mode64 => keystone::Mode::MODE_64,
        }
    }
}

impl TryFrom<unicorn_const::Mode> for Mode {
    type Error = &'static str;
    fn try_from(value: unicorn_const::Mode) -> Result<Self, Self::Error> {
        match value {
            unicorn_const::Mode::MODE_32 => Ok(Self::Mode32),
            unicorn_const::Mode::MODE_64 => Ok(Self::Mode64),
            _ => Err("unsupported mode"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Arch {
    X86,
}

#[allow(clippy::from_over_into)]
impl Into<unicorn_const::Arch> for Arch {
    fn into(self) -> unicorn_const::Arch {
        match self {
            Self::X86 => unicorn_const::Arch::X86,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<keystone::Arch> for Arch {
    fn into(self) -> keystone::Arch {
        match self {
            Self::X86 => keystone::Arch::X86,
        }
    }
}

impl TryFrom<unicorn_const::Arch> for Arch {
    type Error = &'static str;
    fn try_from(value: unicorn_const::Arch) -> Result<Self, Self::Error> {
        match value {
            unicorn_const::Arch::X86 => Ok(Self::X86),
            _ => Err("unsupported arch"),
        }
    }
}

impl Arch {
    fn dump_registers(
        &self,
        emu: &Unicorn<'static, ()>,
        registers: HashMap<&'static str, i32>,
    ) -> HashMap<&'static str, u64> {
        registers
            .keys()
            .into_iter()
            .filter(|&&x| x != "end") // "end" is pseudo-register (to add new row)
            .map(|&reg_name| {
                (
                    reg_name,
                    emu.reg_read(*registers.get(reg_name).unwrap()).unwrap(),
                )
            })
            .collect::<HashMap<_, _>>()
    }
}

pub trait ArchMeta {
    fn cpu(&self) -> (Arch, Mode);
    fn sp_reg(&self) -> i32;
    fn fp_reg(&self) -> i32;
    fn int_size(&self) -> usize;
    fn sorted_reg_names(&self) -> Vec<&'static str>;
    fn register_map(&self) -> HashMap<&'static str, i32>;
    fn dump_registers(&self, emu: &Unicorn<'static, ()>) -> HashMap<&'static str, u64>;
}

#[derive(Clone, Copy, Debug)]
pub struct X32 {
    inner: Arch,
}
impl X32 {
    pub fn new(arch: Arch) -> Self {
        Self { inner: arch }
    }
}
impl ArchMeta for X32 {
    fn cpu(&self) -> (Arch, Mode) {
        (self.inner, Mode::Mode32)
    }

    fn sp_reg(&self) -> i32 {
        i32::from(RegisterX86::ESP)
    }
    fn fp_reg(&self) -> i32 {
        i32::from(RegisterX86::EBP)
    }

    fn int_size(&self) -> usize {
        32 / 8
    }

    fn sorted_reg_names(&self) -> Vec<&'static str> {
        vec![
            "eax", "ebx", "ecx", "edx", "end", //
            "esi", "edi", "end", //
            "eip", "ebp", "esp", "end", //
            "flags", "end", //
            "cs", "ss", "ds", "es", "end", //
            "fs", "gs", "end", //
        ]
    }

    fn register_map(&self) -> HashMap<&'static str, i32> {
        // register to trace, display, etc.
        hashmap! {
            "eax"   => i32::from(RegisterX86::EAX),
            "ebx"   => i32::from(RegisterX86::EBX),
            "ecx"   => i32::from(RegisterX86::ECX),
            "edx"   => i32::from(RegisterX86::EDX),
            "esi"   => i32::from(RegisterX86::ESI),
            "edi"   => i32::from(RegisterX86::EDI),
            "eip"   => i32::from(RegisterX86::EIP),
            "ebp"   => i32::from(RegisterX86::EBP),
            "esp"   => i32::from(RegisterX86::ESP),
            "flags" => i32::from(RegisterX86::EFLAGS),
            "cs"    => i32::from(RegisterX86::CS),
            "ss"    => i32::from(RegisterX86::SS),
            "ds"    => i32::from(RegisterX86::DS),
            "es"    => i32::from(RegisterX86::ES),
            "fs"    => i32::from(RegisterX86::FS),
            "gs"    => i32::from(RegisterX86::GS),
        }
    }

    fn dump_registers(&self, emu: &Unicorn<'static, ()>) -> HashMap<&'static str, u64> {
        self.inner.dump_registers(emu, self.register_map())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct X64 {
    inner: Arch,
}
impl X64 {
    pub fn new(arch: Arch) -> X64 {
        X64 { inner: arch }
    }
}
impl ArchMeta for X64 {
    fn cpu(&self) -> (Arch, Mode) {
        (self.inner, Mode::Mode64)
    }

    fn sp_reg(&self) -> i32 {
        i32::from(RegisterX86::RSP)
    }
    fn fp_reg(&self) -> i32 {
        i32::from(RegisterX86::RBP)
    }

    fn int_size(&self) -> usize {
        64 / 8
    }

    fn sorted_reg_names(&self) -> Vec<&'static str> {
        vec![
            "rax", "rbx", "rcx", "rdx", "end", //
            "rsi", "rdi", "r8", "r9", "end", //
            "r10", "r11", "r12", "r13", "end", //
            "r14", "r15", "end", //
            "rip", "rbp", "rsp", "end", //
            "cs", "ss", "ds", "es", "end", //
            "fs", "gs", "end", "flags", "end", //
        ]
    }

    fn register_map(&self) -> HashMap<&'static str, i32> {
        // register to trace, display, etc.
        hashmap! {
            "rax"   => i32::from(RegisterX86::RAX),
            "rbx"   => i32::from(RegisterX86::RBX),
            "rcx"   => i32::from(RegisterX86::RCX),
            "rdx"   => i32::from(RegisterX86::RDX),
            "rsi"   => i32::from(RegisterX86::RSI),
            "rdi"   => i32::from(RegisterX86::RDI),
            "r8"    => i32::from(RegisterX86::R8),
            "r9"    => i32::from(RegisterX86::R9),
            "r10"   => i32::from(RegisterX86::R10),
            "r11"   => i32::from(RegisterX86::R11),
            "r12"   => i32::from(RegisterX86::R12),
            "r13"   => i32::from(RegisterX86::R13),
            "r14"   => i32::from(RegisterX86::R14),
            "r15"   => i32::from(RegisterX86::R15),
            "rip"   => i32::from(RegisterX86::RIP),
            "rbp"   => i32::from(RegisterX86::RBP),
            "rsp"   => i32::from(RegisterX86::RSP),
            "flags" => i32::from(RegisterX86::EFLAGS),
            "cs"    => i32::from(RegisterX86::CS),
            "ss"    => i32::from(RegisterX86::SS),
            "ds"    => i32::from(RegisterX86::DS),
            "es"    => i32::from(RegisterX86::ES),
            "fs"    => i32::from(RegisterX86::FS),
            "gs"    => i32::from(RegisterX86::GS),
        }
    }

    fn dump_registers(&self, emu: &Unicorn<'static, ()>) -> HashMap<&'static str, u64> {
        self.inner.dump_registers(emu, self.register_map())
    }
}
