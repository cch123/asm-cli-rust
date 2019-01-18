use keystone::{AsmResult,Error};
pub trait Interface {
    fn print_stack(&self);
    fn print_register(&self);
    fn asm(&self, str: String, address: u64) -> Result<AsmResult, Error>;
    fn write_instruction(&self, byte_arr: Vec<u8>);
}