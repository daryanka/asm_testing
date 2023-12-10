use std::fmt::LowerHex;
use strum::{EnumIter, IntoEnumIterator};
use winnow::token::take_while;
use winnow::PResult;
use winnow::Parser;

#[derive(Debug, Default)]
#[allow(non_camel_case_types)]
pub enum MachineType {
  #[default]
  IMAGE_FILE_MACHINE_UNKNOWN, // The content of this field is assumed to be applicable to any machine type
  IMAGE_FILE_MACHINE_ALPHA,       // Alpha AXP, 32-bit address space
  IMAGE_FILE_MACHINE_ALPHA64,     // Alpha 64, 64-bit address space
  IMAGE_FILE_MACHINE_AM33,        // Matsushita AM33
  IMAGE_FILE_MACHINE_AMD64,       // x64
  IMAGE_FILE_MACHINE_ARM,         // ARM little endian
  IMAGE_FILE_MACHINE_ARM64,       // ARM64 little endian
  IMAGE_FILE_MACHINE_ARMNT,       // ARM Thumb-2 little endian
  IMAGE_FILE_MACHINE_AXP64,       // AXP 64 (Same as Alpha 64)
  IMAGE_FILE_MACHINE_EBC,         // EFI byte code
  IMAGE_FILE_MACHINE_I386,        // Intel 386 or later processors and compatible processors
  IMAGE_FILE_MACHINE_IA64,        // Intel Itanium processor family
  IMAGE_FILE_MACHINE_LOONGARCH32, // LoongArch 32-bit processor family
  IMAGE_FILE_MACHINE_LOONGARCH64, // LoongArch 64-bit processor family
  IMAGE_FILE_MACHINE_M32R,        // Mitsubishi M32R little endian
  IMAGE_FILE_MACHINE_MIPS16,      // MIPS16
  IMAGE_FILE_MACHINE_MIPSFPU,     // MIPS with FPU
  IMAGE_FILE_MACHINE_MIPSFPU16,   // MIPS16 with FPU
  IMAGE_FILE_MACHINE_POWERPC,     // Power PC little endian
  IMAGE_FILE_MACHINE_POWERPCFP,   // Power PC with floating point support
  IMAGE_FILE_MACHINE_R4000,       // MIPS little endian
  IMAGE_FILE_MACHINE_RISCV32,     // RISC-V 32-bit address space
  IMAGE_FILE_MACHINE_RISCV64,     // RISC-V 64-bit address space
  IMAGE_FILE_MACHINE_RISCV128,    // RISC-V 128-bit address space
  IMAGE_FILE_MACHINE_SH3,         // Hitachi SH3
  IMAGE_FILE_MACHINE_SH3DSP,      // Hitachi SH3 DSP
  IMAGE_FILE_MACHINE_SH4,         // Hitachi SH4
  IMAGE_FILE_MACHINE_SH5,         // Hitachi SH5
  IMAGE_FILE_MACHINE_THUMB,       // Thumb
  IMAGE_FILE_MACHINE_WCEMIPSV2,   // MIPS little-endian WCE v2
}

impl Into<u16> for MachineType {
  fn into(self) -> u16 {
    match self {
      MachineType::IMAGE_FILE_MACHINE_UNKNOWN => 0x0,
      MachineType::IMAGE_FILE_MACHINE_ALPHA => 0x184,
      MachineType::IMAGE_FILE_MACHINE_ALPHA64 => 0x284,
      MachineType::IMAGE_FILE_MACHINE_AM33 => 0x1d3,
      MachineType::IMAGE_FILE_MACHINE_AMD64 => 0x8664,
      MachineType::IMAGE_FILE_MACHINE_ARM => 0x1c0,
      MachineType::IMAGE_FILE_MACHINE_ARM64 => 0xaa64,
      MachineType::IMAGE_FILE_MACHINE_ARMNT => 0x1c4,
      MachineType::IMAGE_FILE_MACHINE_AXP64 => 0x284,
      MachineType::IMAGE_FILE_MACHINE_EBC => 0xebc,
      MachineType::IMAGE_FILE_MACHINE_I386 => 0x14c,
      MachineType::IMAGE_FILE_MACHINE_IA64 => 0x200,
      MachineType::IMAGE_FILE_MACHINE_LOONGARCH32 => 0x6232,
      MachineType::IMAGE_FILE_MACHINE_LOONGARCH64 => 0x6264,
      MachineType::IMAGE_FILE_MACHINE_M32R => 0x9041,
      MachineType::IMAGE_FILE_MACHINE_MIPS16 => 0x266,
      MachineType::IMAGE_FILE_MACHINE_MIPSFPU => 0x366,
      MachineType::IMAGE_FILE_MACHINE_MIPSFPU16 => 0x466,
      MachineType::IMAGE_FILE_MACHINE_POWERPC => 0x1f0,
      MachineType::IMAGE_FILE_MACHINE_POWERPCFP => 0x1f1,
      MachineType::IMAGE_FILE_MACHINE_R4000 => 0x166,
      MachineType::IMAGE_FILE_MACHINE_RISCV32 => 0x5032,
      MachineType::IMAGE_FILE_MACHINE_RISCV64 => 0x5064,
      MachineType::IMAGE_FILE_MACHINE_RISCV128 => 0x5128,
      MachineType::IMAGE_FILE_MACHINE_SH3 => 0x1a2,
      MachineType::IMAGE_FILE_MACHINE_SH3DSP => 0x1a3,
      MachineType::IMAGE_FILE_MACHINE_SH4 => 0x1a6,
      MachineType::IMAGE_FILE_MACHINE_SH5 => 0x1a8,
      MachineType::IMAGE_FILE_MACHINE_THUMB => 0x1c2,
      MachineType::IMAGE_FILE_MACHINE_WCEMIPSV2 => 0x169,
    }
  }
}

impl TryFrom<u16> for MachineType {
  type Error = ();

  fn try_from(value: u16) -> Result<Self, Self::Error> {
    match value {
      0x0 => Ok(MachineType::IMAGE_FILE_MACHINE_UNKNOWN),
      0x184 => Ok(MachineType::IMAGE_FILE_MACHINE_ALPHA),
      0x284 => Ok(MachineType::IMAGE_FILE_MACHINE_ALPHA64),
      0x1d3 => Ok(MachineType::IMAGE_FILE_MACHINE_AM33),
      0x8664 => Ok(MachineType::IMAGE_FILE_MACHINE_AMD64),
      0x1c0 => Ok(MachineType::IMAGE_FILE_MACHINE_ARM),
      0xaa64 => Ok(MachineType::IMAGE_FILE_MACHINE_ARM64),
      0x1c4 => Ok(MachineType::IMAGE_FILE_MACHINE_ARMNT),
      0x284 => Ok(MachineType::IMAGE_FILE_MACHINE_AXP64),
      0xebc => Ok(MachineType::IMAGE_FILE_MACHINE_EBC),
      0x14c => Ok(MachineType::IMAGE_FILE_MACHINE_I386),
      0x200 => Ok(MachineType::IMAGE_FILE_MACHINE_IA64),
      0x6232 => Ok(MachineType::IMAGE_FILE_MACHINE_LOONGARCH32),
      0x6264 => Ok(MachineType::IMAGE_FILE_MACHINE_LOONGARCH64),
      0x9041 => Ok(MachineType::IMAGE_FILE_MACHINE_M32R),
      0x266 => Ok(MachineType::IMAGE_FILE_MACHINE_MIPS16),
      0x366 => Ok(MachineType::IMAGE_FILE_MACHINE_MIPSFPU),
      0x466 => Ok(MachineType::IMAGE_FILE_MACHINE_MIPSFPU16),
      0x1f0 => Ok(MachineType::IMAGE_FILE_MACHINE_POWERPC),
      0x1f1 => Ok(MachineType::IMAGE_FILE_MACHINE_POWERPCFP),
      0x166 => Ok(MachineType::IMAGE_FILE_MACHINE_R4000),
      0x5032 => Ok(MachineType::IMAGE_FILE_MACHINE_RISCV32),
      0x5064 => Ok(MachineType::IMAGE_FILE_MACHINE_RISCV64),
      0x5128 => Ok(MachineType::IMAGE_FILE_MACHINE_RISCV128),
      0x1a2 => Ok(MachineType::IMAGE_FILE_MACHINE_SH3),
      0x1a3 => Ok(MachineType::IMAGE_FILE_MACHINE_SH3DSP),
      0x1a6 => Ok(MachineType::IMAGE_FILE_MACHINE_SH4),
      0x1a8 => Ok(MachineType::IMAGE_FILE_MACHINE_SH5),
      0x1c2 => Ok(MachineType::IMAGE_FILE_MACHINE_THUMB),
      0x169 => Ok(MachineType::IMAGE_FILE_MACHINE_WCEMIPSV2),
      _ => Err(()),
    }
  }
}

#[derive(Debug, Default, EnumIter, Clone)]
#[allow(non_camel_case_types)]
pub enum Characteristics {
  #[default]
  IMAGE_FILE_RELOCS_STRIPPED, // Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
  IMAGE_FILE_EXECUTABLE_IMAGE, // Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
  IMAGE_FILE_LINE_NUMS_STRIPPED, // COFF line numbers have been removed. This flag is deprecated and should be zero.
  IMAGE_FILE_LOCAL_SYMS_STRIPPED, // COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
  IMAGE_FILE_AGGRESSIVE_WS_TRIM, // Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
  IMAGE_FILE_LARGE_ADDRESS_AWARE, // Application can handle > 2-GB addresses.
  IMAGE_FILE_BYTES_REVERSED_LO, // Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
  IMAGE_FILE_32BIT_MACHINE,     // Machine is based on a 32-bit-word architecture.
  IMAGE_FILE_DEBUG_STRIPPED,    // Debugging information is removed from the image file.
  IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, // If the image is on removable media, fully load it and copy it to the swap file.
  IMAGE_FILE_NET_RUN_FROM_SWAP, // If the image is on network media, fully load it and copy it to the swap file.
  IMAGE_FILE_SYSTEM,            // The image file is a system file, not a user program.
  IMAGE_FILE_DLL, // The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
  IMAGE_FILE_UP_SYSTEM_ONLY, // The file should be run only on a uniprocessor machine.
  IMAGE_FILE_BYTES_REVERSED_HI, // Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
}

impl Characteristics {
  pub fn get_characteristics(value: u16) -> Vec<Characteristics> {
    // number is bit flag
    // get bits
    // match bits
    let mut characteristics = Vec::new();

    for char in Characteristics::iter() {
      let char = char.clone();
      let val: u16 = char.clone().into();
      if value & val != 0 {
        characteristics.push(char);
      }
    }

    characteristics
  }
}

impl Into<u16> for Characteristics {
  fn into(self) -> u16 {
    match self {
      Self::IMAGE_FILE_RELOCS_STRIPPED => 0x0001,
      Self::IMAGE_FILE_EXECUTABLE_IMAGE => 0x0002,
      Self::IMAGE_FILE_LINE_NUMS_STRIPPED => 0x0004,
      Self::IMAGE_FILE_LOCAL_SYMS_STRIPPED => 0x0008,
      Self::IMAGE_FILE_AGGRESSIVE_WS_TRIM => 0x0010,
      Self::IMAGE_FILE_LARGE_ADDRESS_AWARE => 0x0020,
      Self::IMAGE_FILE_BYTES_REVERSED_LO => 0x0040,
      Self::IMAGE_FILE_32BIT_MACHINE => 0x0080,
      Self::IMAGE_FILE_DEBUG_STRIPPED => 0x0100,
      Self::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP => 0x0200,
      Self::IMAGE_FILE_NET_RUN_FROM_SWAP => 0x0400,
      Self::IMAGE_FILE_SYSTEM => 0x0800,
      Self::IMAGE_FILE_DLL => 0x1000,
      Self::IMAGE_FILE_UP_SYSTEM_ONLY => 0x2000,
      Self::IMAGE_FILE_BYTES_REVERSED_HI => 0x4000,
    }
  }
}

pub fn format_to_hex<T: LowerHex>(data: &T) -> String {
  format!("{:02x} ", data)
}

pub fn get_ascii_string<'s>(input: &mut &'s [u8], len: usize) -> PResult<String> {
  let bytes = take_while(len, |b: u8| b.is_ascii()).parse_next(input)?;
  let string = String::from_utf8(bytes.to_vec()).unwrap();
  Ok(string)
}

pub fn get_le_u16<'s>(input: &mut &'s [u8]) -> PResult<u16> {
  let bytes = take_while(2, |_| true).parse_next(input)?;
  let num = u16::from_le_bytes([bytes[0], bytes[1]]);
  Ok(num)
}

pub fn get_le_u32<'s>(input: &mut &'s [u8]) -> PResult<u32> {
  let bytes = take_while(4, |_| true).parse_next(input)?;
  let num = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
  Ok(num)
}

pub fn get_le_u16_vec<'s>(input: &mut &'s [u8], len: usize) -> PResult<Vec<u16>> {
  let mut arr = Vec::with_capacity(len);
  for _ in 0..len {
    let bytes = take_while(2, |_| true).parse_next(input)?;
    arr.push(u16::from_le_bytes([bytes[0], bytes[1]]));
  }
  Ok(arr)
}
