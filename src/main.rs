use capstone::prelude::*;
use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

fn main() -> io::Result<()> {
    // Parse command line arguments for input and output file paths
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input_file> <output_file>", args[0]);
        std::process::exit(1);
    }
    let input_path = &args[1];
    let output_path = &args[2];

    // Read the bytes from the input file
    let mut file = File::open(input_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Create a Capstone disassembler instance for 32-bit x86 code
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode32)
        .build()
        .expect("Failed to create Capstone object");

    // Disassemble the bytes into instructions
    let instructions = cs.disasm_all(&buffer, 0x1000).expect("Failed to disassemble code");

    // Create or overwrite the output file
    let mut output_file = File::create(output_path)?;

    // Write each instruction to the output file
    for i in instructions.iter() {
        let bytes = i.bytes();
        let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        writeln!(output_file, "0x{:x}:\t{}\t{}\t{}", i.address(), i.mnemonic().unwrap_or(""), i.op_str().unwrap_or(""), hex_str)?;
    }
    

    println!("Disassembly written to: {}", output_path);
    Ok(())
}