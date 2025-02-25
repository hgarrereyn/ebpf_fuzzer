use clap::Parser;
use rand::{Rng, thread_rng};
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

    /// Version of the eBPF specification to use
    #[arg(long, default_value_t = 3, help = "Maximum CPU version to generate instructions for (default: 3)")]
    max_cpu_version: u8,
}

#[derive(Debug, Clone, Copy)]
struct Instruction {
    opcode: u8,
    dst: u8,
    src: u8,
    offset: u16,
    imm: u32,
}

impl Instruction {
    pub fn new(opcode: u8, dst: u8, src: u8, offset: u16, imm: u32) -> Self {
        Self { opcode, dst, src, offset, imm }
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[0] = self.opcode;
        bytes[1] = (self.dst << 4) | self.src;
        bytes[2] = (self.offset >> 8) as u8;
        bytes[3] = self.offset as u8;
        bytes[4] = (self.imm >> 24) as u8;
        bytes[5] = (self.imm >> 16) as u8;
        bytes[6] = (self.imm >> 8) as u8;
        bytes[7] = self.imm as u8;
        bytes
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Version {
    V1,
    V2,
    V3,
    V4,
}

impl Version {
    fn value(&self) -> u8 {
        match self {
            Version::V1 => 1,
            Version::V2 => 2,
            Version::V3 => 3,
            Version::V4 => 4,
        }
    }

    pub fn from_value(value: u8) -> Option<Self> {
        match value {
            1 => Some(Version::V1),
            2 => Some(Version::V2),
            3 => Some(Version::V3),
            4 => Some(Version::V4),
            _ => None,
        }
    }
}

pub struct Template {
    version: Version,
    opcode: u8,
    src: u8,
    imm: u32,
    offset: u16,
}

impl Template {
    pub const fn new(version: Version, opcode: u8, src: u8, imm: u32, offset: u16) -> Self {
        Self { version, opcode, src, imm, offset }
    }
}

pub fn needs_src(opcode: u8) -> bool {
    opcode == 0x18 || opcode == 0x85
}

pub fn needs_imm(opcode: u8) -> bool {
    opcode == 0xc3 || opcode == 0xd4 || opcode == 0xdb || opcode == 0xdc
}

pub fn needs_offset(opcode: u8) -> bool {
    opcode == 0x34 || opcode == 0x37 || opcode == 0x3c || opcode == 0x3f || opcode == 0x94 || opcode == 0x97 ||
    opcode == 0x9c || opcode == 0x9f || opcode == 0xbc || opcode == 0xbf
}

// See: https://github.com/Alan-Jowett/bpf_conformance/blob/main/src/opcode_names.h
// Packet/callx opcodes are commented out
const INSTRUCTIONS_FROM_SPEC: &[Template] = &[
    Template::new(Version::V1, 0x00, 0, 0, 0),
    Template::new(Version::V1, 0x04, 0, 0, 0),
    Template::new(Version::V1, 0x05, 0, 0, 0),
    Template::new(Version::V4, 0x06, 0, 0, 0),
    Template::new(Version::V1, 0x07, 0, 0, 0),
    Template::new(Version::V1, 0x0c, 0, 0, 0),
    Template::new(Version::V1, 0x0f, 0, 0, 0),
    Template::new(Version::V1, 0x14, 0, 0, 0),
    Template::new(Version::V1, 0x15, 0, 0, 0),
    Template::new(Version::V3, 0x16, 0, 0, 0),
    Template::new(Version::V1, 0x17, 0, 0, 0),
    Template::new(Version::V1, 0x18, 0x00, 0, 0),
    Template::new(Version::V1, 0x18, 0x01, 0, 0),
    Template::new(Version::V1, 0x18, 0x02, 0, 0),
    Template::new(Version::V1, 0x18, 0x03, 0, 0),
    Template::new(Version::V1, 0x18, 0x04, 0, 0),
    Template::new(Version::V1, 0x18, 0x05, 0, 0),
    Template::new(Version::V1, 0x18, 0x06, 0, 0),
    Template::new(Version::V1, 0x1c, 0, 0, 0),
    Template::new(Version::V1, 0x1d, 0, 0, 0),
    Template::new(Version::V3, 0x1e, 0, 0, 0),
    Template::new(Version::V1, 0x1f, 0, 0, 0),
    // Template::new(Version::V1, 0x20, 0, 0, 0),
    Template::new(Version::V1, 0x24, 0, 0, 0),
    Template::new(Version::V1, 0x25, 0, 0, 0),
    Template::new(Version::V3, 0x26, 0, 0, 0),
    Template::new(Version::V1, 0x27, 0, 0, 0),
    // Template::new(Version::V1, 0x28, 0, 0, 0),
    Template::new(Version::V1, 0x2c, 0, 0, 0),
    Template::new(Version::V1, 0x2d, 0, 0, 0),
    Template::new(Version::V3, 0x2e, 0, 0, 0),
    Template::new(Version::V1, 0x2f, 0, 0, 0),
    // Template::new(Version::V1, 0x30, 0, 0, 0),
    Template::new(Version::V1, 0x34, 0, 0, 0),
    Template::new(Version::V4, 0x34, 0, 1, 0),
    Template::new(Version::V1, 0x35, 0, 0, 0),
    Template::new(Version::V3, 0x36, 0, 0, 0),
    Template::new(Version::V1, 0x37, 0, 0, 0),
    Template::new(Version::V4, 0x37, 0, 1, 0),
    Template::new(Version::V1, 0x3c, 0, 0, 0),
    Template::new(Version::V4, 0x3c, 0, 1, 0),
    Template::new(Version::V1, 0x3d, 0, 0, 0),
    Template::new(Version::V3, 0x3e, 0, 0, 0),
    Template::new(Version::V1, 0x3f, 0, 0, 0),
    Template::new(Version::V4, 0x3f, 0, 1, 0),
    // Template::new(Version::V1, 0x40, 0, 0, 0),
    Template::new(Version::V1, 0x44, 0, 0, 0),
    Template::new(Version::V1, 0x45, 0, 0, 0),
    Template::new(Version::V3, 0x46, 0, 0, 0),
    Template::new(Version::V1, 0x47, 0, 0, 0),
    // Template::new(Version::V1, 0x48, 0, 0, 0),
    Template::new(Version::V1, 0x4c, 0, 0, 0),
    Template::new(Version::V1, 0x4d, 0, 0, 0),
    Template::new(Version::V3, 0x4e, 0, 0, 0),
    Template::new(Version::V1, 0x4f, 0, 0, 0),
    // Template::new(Version::V1, 0x50, 0, 0, 0),
    Template::new(Version::V1, 0x54, 0, 0, 0),
    Template::new(Version::V1, 0x55, 0, 0, 0),
    Template::new(Version::V3, 0x56, 0, 0, 0),
    Template::new(Version::V1, 0x57, 0, 0, 0),
    Template::new(Version::V1, 0x5c, 0, 0, 0),
    Template::new(Version::V1, 0x5d, 0, 0, 0),
    Template::new(Version::V3, 0x5e, 0, 0, 0),
    Template::new(Version::V1, 0x5f, 0, 0, 0),
    Template::new(Version::V1, 0x61, 0, 0, 0),
    Template::new(Version::V1, 0x62, 0, 0, 0),
    Template::new(Version::V1, 0x63, 0, 0, 0),
    Template::new(Version::V1, 0x64, 0, 0, 0),
    Template::new(Version::V1, 0x65, 0, 0, 0),
    Template::new(Version::V3, 0x66, 0, 0, 0),
    Template::new(Version::V1, 0x67, 0, 0, 0),
    Template::new(Version::V1, 0x69, 0, 0, 0),
    Template::new(Version::V1, 0x6a, 0, 0, 0),
    Template::new(Version::V1, 0x6b, 0, 0, 0),
    Template::new(Version::V1, 0x6c, 0, 0, 0),
    Template::new(Version::V1, 0x6d, 0, 0, 0),
    Template::new(Version::V3, 0x6e, 0, 0, 0),
    Template::new(Version::V1, 0x6f, 0, 0, 0),
    Template::new(Version::V1, 0x71, 0, 0, 0),
    Template::new(Version::V1, 0x72, 0, 0, 0),
    Template::new(Version::V1, 0x73, 0, 0, 0),
    Template::new(Version::V1, 0x74, 0, 0, 0),
    Template::new(Version::V1, 0x75, 0, 0, 0),
    Template::new(Version::V3, 0x76, 0, 0, 0),
    Template::new(Version::V1, 0x77, 0, 0, 0),
    Template::new(Version::V1, 0x79, 0, 0, 0),
    Template::new(Version::V1, 0x7a, 0, 0, 0),
    Template::new(Version::V1, 0x7b, 0, 0, 0),
    Template::new(Version::V1, 0x7c, 0, 0, 0),
    Template::new(Version::V1, 0x7d, 0, 0, 0),
    Template::new(Version::V3, 0x7e, 0, 0, 0),
    Template::new(Version::V1, 0x7f, 0, 0, 0),
    Template::new(Version::V1, 0x84, 0, 0, 0),
    Template::new(Version::V1, 0x85, 0x00, 0, 0),
    Template::new(Version::V3, 0x85, 0x01, 0, 0),
    Template::new(Version::V3, 0x85, 0x02, 0, 0),
    Template::new(Version::V1, 0x87, 0, 0, 0),
    // Template::new(Version::V1, 0x8d, 0x00, 0, 0),
    Template::new(Version::V1, 0x94, 0, 0, 0),
    Template::new(Version::V4, 0x94, 0, 1, 0),
    Template::new(Version::V1, 0x95, 0, 0, 0),
    Template::new(Version::V1, 0x97, 0, 0, 0),
    Template::new(Version::V4, 0x97, 0, 1, 0),
    Template::new(Version::V1, 0x9c, 0, 0, 0),
    Template::new(Version::V4, 0x9c, 0, 1, 0),
    Template::new(Version::V1, 0x9f, 0, 0, 0),
    Template::new(Version::V4, 0x9f, 0, 1, 0),
    Template::new(Version::V1, 0xa4, 0, 0, 0),
    Template::new(Version::V2, 0xa5, 0, 0, 0),
    Template::new(Version::V3, 0xa6, 0, 0, 0),
    Template::new(Version::V1, 0xa7, 0, 0, 0),
    Template::new(Version::V1, 0xac, 0, 0, 0),
    Template::new(Version::V2, 0xad, 0, 0, 0),
    Template::new(Version::V3, 0xae, 0, 0, 0),
    Template::new(Version::V1, 0xaf, 0, 0, 0),
    Template::new(Version::V1, 0xb4, 0, 0, 0),
    Template::new(Version::V2, 0xb5, 0, 0, 0),
    Template::new(Version::V3, 0xb6, 0, 0, 0),
    Template::new(Version::V1, 0xb7, 0, 0, 0),
    Template::new(Version::V1, 0xbc, 0, 0, 0),
    Template::new(Version::V4, 0xbc, 0, 8, 0),
    Template::new(Version::V4, 0xbc, 0, 0x10, 0),
    Template::new(Version::V2, 0xbd, 0, 0, 0),
    Template::new(Version::V3, 0xbe, 0, 0, 0),
    Template::new(Version::V1, 0xbf, 0, 0, 0),
    Template::new(Version::V4, 0xbf, 0, 8, 0),
    Template::new(Version::V4, 0xbf, 0, 0x10, 0),
    Template::new(Version::V4, 0xbf, 0, 0x20, 0),
    Template::new(Version::V3, 0xc3, 0, 0, 0),
    Template::new(Version::V3, 0xc3, 0, 1, 0),
    Template::new(Version::V3, 0xc3, 0, 0x40, 0),
    Template::new(Version::V3, 0xc3, 0, 0x41, 0),
    Template::new(Version::V3, 0xc3, 0, 0x50, 0),
    Template::new(Version::V3, 0xc3, 0, 0x51, 0),
    Template::new(Version::V3, 0xc3, 0, 0xa0, 0),
    Template::new(Version::V3, 0xc3, 0, 0xa1, 0),
    Template::new(Version::V3, 0xc3, 0, 0xe1, 0),
    Template::new(Version::V3, 0xc3, 0, 0xf1, 0),
    Template::new(Version::V1, 0xc4, 0, 0, 0),
    Template::new(Version::V2, 0xc5, 0, 0, 0),
    Template::new(Version::V3, 0xc6, 0, 0, 0),
    Template::new(Version::V1, 0xc7, 0, 0, 0),
    Template::new(Version::V1, 0xcc, 0, 0, 0),
    Template::new(Version::V2, 0xcd, 0, 0, 0),
    Template::new(Version::V3, 0xce, 0, 0, 0),
    Template::new(Version::V1, 0xcf, 0, 0, 0),
    Template::new(Version::V1, 0xd4, 0, 0x10, 0),
    Template::new(Version::V1, 0xd4, 0, 0x20, 0),
    Template::new(Version::V1, 0xd4, 0, 0x40, 0),
    Template::new(Version::V2, 0xd5, 0, 0, 0),
    Template::new(Version::V3, 0xd6, 0, 0, 0),
    Template::new(Version::V4, 0xd7, 0, 0x10, 0),
    Template::new(Version::V4, 0xd7, 0, 0x20, 0),
    Template::new(Version::V4, 0xd7, 0, 0x40, 0),
    Template::new(Version::V3, 0xdb, 0, 0, 0),
    Template::new(Version::V3, 0xdb, 0, 1, 0),
    Template::new(Version::V3, 0xdb, 0, 0x40, 0),
    Template::new(Version::V3, 0xdb, 0, 0x41, 0),
    Template::new(Version::V3, 0xdb, 0, 0x50, 0),
    Template::new(Version::V3, 0xdb, 0, 0x51, 0),
    Template::new(Version::V3, 0xdb, 0, 0x50, 0),
    Template::new(Version::V3, 0xdb, 0, 0xa0, 0),
    Template::new(Version::V3, 0xdb, 0, 0xa1, 0),
    Template::new(Version::V3, 0xdb, 0, 0xe1, 0),
    Template::new(Version::V3, 0xdb, 0, 0xf1, 0),
    Template::new(Version::V1, 0xdc, 0, 0x10, 0),
    Template::new(Version::V1, 0xdc, 0, 0x20, 0),
    Template::new(Version::V1, 0xdc, 0, 0x40, 0),
    Template::new(Version::V2, 0xdd, 0, 0, 0),
    Template::new(Version::V3, 0xde, 0, 0, 0),
];

fn get_possible_values<T: Copy>(opcode: u8, field_selector: fn(&Template) -> T) -> Vec<T> {
    INSTRUCTIONS_FROM_SPEC
        .iter()
        .filter(|t| t.opcode == opcode)
        .map(|t| field_selector(t))
        .collect()
}

fn generate_random_instruction<R: Rng>(rng: &mut R, max_version: Version) -> Instruction {
    // Filter templates by version and get possible opcodes
    let valid_templates: Vec<&Template> = INSTRUCTIONS_FROM_SPEC
        .iter()
        .filter(|t| t.version.value() <= max_version.value())
        .collect();

    // Pick a random template
    let template = valid_templates[rng.random_range(0..valid_templates.len())];
    let opcode = template.opcode;

    // Generate random values for fields
    let dst = rng.random::<u8>() & 0xF; // Only use lower 4 bits for registers
    let mut src = rng.random::<u8>() & 0xF;
    let mut offset = rng.random::<u16>();
    let mut imm = rng.random::<u32>();

    // If opcode needs specific src value, pick from templates
    if needs_src(opcode) {
        let possible_srcs = get_possible_values(opcode, |t| t.src);
        src = possible_srcs[rng.random_range(0..possible_srcs.len())];
    }

    // If opcode needs specific imm value, pick from templates
    if needs_imm(opcode) {
        let possible_imms = get_possible_values(opcode, |t| t.imm);
        imm = possible_imms[rng.random_range(0..possible_imms.len())];
    }

    // If opcode needs specific offset value, pick from templates
    if needs_offset(opcode) {
        let possible_offsets = get_possible_values(opcode, |t| t.offset);
        offset = possible_offsets[rng.random_range(0..possible_offsets.len())];
    }

    Instruction::new(opcode, dst, src, offset, imm)
}

fn generate_program(size: u32, max_cpu_version: u8) -> String {
    let mut rng = rand::rng();
    let mut bytes = Vec::with_capacity((size * 8) as usize);

    // Generate random instructions
    for _ in 0..size {
        let insn = generate_random_instruction(&mut rng, Version::from_value(max_cpu_version).unwrap());
        bytes.extend_from_slice(&insn.to_bytes());

        // If opcode is LD_DW_IMM, fill 8 bytes with random data
        if insn.opcode == 0x18 {
            bytes.extend_from_slice(&rng.random::<[u8; 8]>());
        }
    }

    let mut output = String::new();

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
        let program = generate_program(size, args.max_cpu_version);

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
