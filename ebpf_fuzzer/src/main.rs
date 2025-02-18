use clap::Parser;
use rand::Rng;
use rbpf::ebpf;
use std::fs;
use std::path::Path;

/// CLI arguments for the program
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Minimum number of instructions to generate
    #[arg(long, default_value_t = 3)]
    min_size: u32,

    /// Maximum number of instructions to generate
    #[arg(long, default_value_t = 40)]
    max_size: u32,

    /// Number of programs to generate
    #[arg(long, default_value_t = 1)]
    count: u32,

    /// Output format string (e.g. "./out/%d.bpf")
    #[arg(long, default_value = "-")]
    output: String,
}

const OPCODES: [u8; 128] = [
    // BPF_LD class
    ebpf::LD_ABS_B,
    ebpf::LD_ABS_H,
    ebpf::LD_ABS_W,
    ebpf::LD_ABS_DW,
    ebpf::LD_IND_B,
    ebpf::LD_IND_H,
    ebpf::LD_IND_W,
    ebpf::LD_IND_DW,
    ebpf::LD_DW_IMM,
    ebpf::LD_B_REG,
    ebpf::LD_H_REG,
    ebpf::LD_W_REG,
    ebpf::LD_DW_REG,

    ebpf::LD_DW_IMM,

    // BPF_LDX class
    ebpf::LD_B_REG,
    ebpf::LD_H_REG,
    ebpf::LD_W_REG,
    ebpf::LD_DW_REG,

    // BPF_ST class
    ebpf::ST_B_IMM,
    ebpf::ST_H_IMM,
    ebpf::ST_W_IMM,
    ebpf::ST_DW_IMM,

    // BPF_STX class
    ebpf::ST_B_REG,
    ebpf::ST_H_REG,
    ebpf::ST_W_REG,
    ebpf::ST_DW_REG,
    ebpf::ST_W_XADD,
    ebpf::ST_DW_XADD,

    // BPF_ALU class
    ebpf::ADD32_IMM,
    ebpf::ADD32_REG,
    ebpf::SUB32_IMM,
    ebpf::SUB32_REG,
    ebpf::MUL32_IMM,
    ebpf::MUL32_REG,
    ebpf::DIV32_IMM,
    ebpf::DIV32_REG,
    ebpf::OR32_IMM,
    ebpf::OR32_REG,
    ebpf::AND32_IMM,
    ebpf::AND32_REG,
    ebpf::LSH32_IMM,
    ebpf::LSH32_REG,
    ebpf::RSH32_IMM,
    ebpf::RSH32_REG,
    ebpf::NEG32,
    ebpf::MOD32_IMM,
    ebpf::MOD32_REG,
    ebpf::XOR32_IMM,
    ebpf::XOR32_REG,
    ebpf::MOV32_IMM,
    ebpf::MOV32_REG,
    ebpf::ARSH32_IMM,
    ebpf::ARSH32_REG,
    ebpf::LE,
    ebpf::BE,

    // BPF_ALU64 class
    ebpf::ADD64_IMM,
    ebpf::ADD64_REG,
    ebpf::SUB64_IMM,
    ebpf::SUB64_REG,
    ebpf::MUL64_IMM,
    ebpf::MUL64_REG,
    ebpf::DIV64_IMM,
    ebpf::DIV64_REG,
    ebpf::OR64_IMM,
    ebpf::OR64_REG,
    ebpf::AND64_IMM,
    ebpf::AND64_REG,
    ebpf::LSH64_IMM,
    ebpf::LSH64_REG,
    ebpf::RSH64_IMM,
    ebpf::RSH64_REG,
    ebpf::NEG64,
    ebpf::MOD64_IMM,
    ebpf::MOD64_REG,
    ebpf::XOR64_IMM,
    ebpf::XOR64_REG,
    ebpf::MOV64_IMM,
    ebpf::MOV64_REG,
    ebpf::ARSH64_IMM,
    ebpf::ARSH64_REG,

    // BPF_JMP class
    ebpf::JA,
    ebpf::JEQ_IMM,
    ebpf::JEQ_REG,
    ebpf::JGT_IMM,
    ebpf::JGT_REG,
    ebpf::JGE_IMM,
    ebpf::JGE_REG,
    ebpf::JLT_IMM,
    ebpf::JLT_REG,
    ebpf::JLE_IMM,
    ebpf::JLE_REG,
    ebpf::JSET_IMM,
    ebpf::JSET_REG,
    ebpf::JNE_IMM,
    ebpf::JNE_REG,
    ebpf::JSGT_IMM,
    ebpf::JSGT_REG,
    ebpf::JSGE_IMM,
    ebpf::JSGE_REG,
    ebpf::JSLT_IMM,
    ebpf::JSLT_REG,
    ebpf::JSLE_IMM,
    ebpf::JSLE_REG,
    ebpf::CALL,
    ebpf::TAIL_CALL,
    ebpf::EXIT,

    // BPF_JMP32 class
    ebpf::JEQ_IMM32,
    ebpf::JEQ_REG32,
    ebpf::JGT_IMM32,
    ebpf::JGT_REG32,
    ebpf::JGE_IMM32,
    ebpf::JGE_REG32,
    ebpf::JLT_IMM32,
    ebpf::JLT_REG32,
    ebpf::JLE_IMM32,
    ebpf::JLE_REG32,
    ebpf::JSET_IMM32,
    ebpf::JSET_REG32,
    ebpf::JNE_IMM32,
    ebpf::JNE_REG32,
    ebpf::JSGT_IMM32,
    ebpf::JSGT_REG32,
    ebpf::JSGE_IMM32,
    ebpf::JSGE_REG32,
    ebpf::JSLT_IMM32,
    ebpf::JSLT_REG32,
    ebpf::JSLE_IMM32,
    ebpf::JSLE_REG32
];

fn generate_program(size: u32) -> String {
    let mut rng = rand::rng();
    let mut bytes: Vec<u8> = (0..(size*8)).map(|_| rng.random()).collect();

    // Iterate and ensure opcodes are in range.
    let mut pc = 0;
    while pc < bytes.len() {
        bytes[pc] = OPCODES[rng.random_range(0..OPCODES.len())];
        pc += 8;
    }

    // Ensure last opcode is not lddw
    if bytes[bytes.len() - 8] == ebpf::LD_DW_IMM {
        let end = bytes.len() - 8;
        bytes[end] = ebpf::EXIT;
    }

    let mut output = String::new();
    
    // Disassemble with rbpf and print the asm
    output.push_str("-- asm\n");
    for insn in rbpf::disassembler::to_insn_vec(&bytes) {
        output.push_str(&format!("{}\n", insn.desc));
    }

    // Since rbpf text format differs a bit from bpf_conformance, also emit the raw bytes
    output.push_str("-- raw\n");
    // Print 64 bits per line as a single hex value
    for i in (0..bytes.len()).step_by(8) {
        let v: u64 = u64::from_le_bytes(bytes[i..i+8].try_into().unwrap());
        output.push_str(&format!("0x{:016x}\n", v));
    }
    
    // bpf_conformance expects a result or error
    output.push_str("-- result\n");
    output.push_str("0x0\n");

    output
}

fn main() {
    let args = Args::parse();
    let mut rng = rand::rng();

    for i in 0..args.count {
        let size = rng.random_range(args.min_size..args.max_size);
        let program = generate_program(size);

        if args.output == "-" {
            print!("{}", program);
        } else {
            let output_path = args.output.replace("%d", &i.to_string());
            // Create parent directory if it doesn't exist
            if let Some(parent) = Path::new(&output_path).parent() {
                fs::create_dir_all(parent).expect("Failed to create output directory");
            }
            fs::write(&output_path, program).expect("Failed to write program to file");
        }
    }
}
