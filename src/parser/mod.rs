use crate::parser::header_parse::{parse_pe_header, parse_sections_table};
use crate::parser::parse_text::parse_text_section;
use crate::parser::utils::{
  Characteristics, DLLCharacteristics, DataDirectoryTableField, MachineType,
  OptionalHeaderSubSystem,
};
use winnow::error::ParserError;
use winnow::stream::Stream;
use winnow::PResult;
use winnow::Parser;

mod header_parse;
mod parse_text;
mod utils;

#[derive(Debug)]
pub struct PEFile {
  headers: PEHeader,
  section_table: Vec<SectionEntry>,
}

#[derive(Debug, Default)]
pub struct SectionEntry {
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
  name: String, // (originally 8 bytes)
  virtual_size: u32,
  virtual_address: u32,
  size_of_raw_data: u32,
  pointer_to_raw_data: u32,
  pointer_to_relocations: u32,
  pointer_to_linenumbers: u32,
  number_of_relocations: u16,
  number_of_linenumbers: u16,
  characteristics: u32, // TODO parse this into vec of characteristics, bitfield
}

#[derive(Debug)]
pub struct PEHeader {
  dos_header: DOSHeader,
  dos_stub: Vec<u8>,
  nt_headers: NtHeaders,
}

#[derive(Debug, Default)]
pub struct NtHeaders {
  signature: String,
  file_header: FileHeader,
  optional_header: Option<OptionalHeader>,
}

#[derive(Debug)]
pub enum OptionalHeader {
  ImageOptionalHeader32(ImageOptionalHeader32),
  ImageOptionalHeader64(ImageOptionalHeader64),
  ImageOptionalHeaderRom(ImageOptionalHeaderRom),
}

impl Default for OptionalHeader {
  fn default() -> Self {
    Self::ImageOptionalHeader32(ImageOptionalHeader32::default())
  }
}

#[derive(Debug, Default)]
pub struct CommonOptionalHeaderFields {
  magic: u16,
  major_linker_version: u8,
  minor_linker_version: u8,
  size_of_code: u32, // The size of the code (text) section, or the sum of all code sections if there are multiple sections.
  size_of_initialized_data: u32, // The size of the initialized data section, or the sum of all such sections if there are multiple data sections.
  size_of_uninitialized_data: u32, // The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.
  address_of_entry_point: u32, // The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero.
  base_of_code: u32, // The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
}

#[derive(Debug, Default)]
pub struct ImageOptionalHeader32 {
  common: CommonOptionalHeaderFields,
  base_of_data: u32, // The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
  image_base: u32, // The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
  section_alignment: u32, // The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
  file_alignment: u32, // The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
  major_operating_system_version: u16, // The major version number of the required operating system.
  minor_operating_system_version: u16, // The minor version number of the required operating system.
  major_image_version: u16, // The major version number of the image.
  minor_image_version: u16, // The minor version number of the image.
  major_subsystem_version: u16, // The major version number of the subsystem.
  minor_subsystem_version: u16, // The minor version number of the subsystem.
  win32_version_value: u32, // Reserved, must be zero.
  size_of_image: u32, // The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
  size_of_headers: u32, // The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
  checksum: u32, // The image file checksum. The following files are validated at load time: all drivers, any DLL loaded at boot time, and any DLL loaded into a critical system process.
  subsystem: OptionalHeaderSubSystem, // The subsystem that is required to run this image.
  dll_characteristics: Vec<DLLCharacteristics>, // (u16) // The DLL characteristics of the image.
  size_of_stack_reserve: u32, // The number of bytes to reserve for the stack. Only the memory specified by the SizeOfStackCommit member is committed at load time; the rest is made available one page at a time until this reserve size is reached.
  size_of_stack_commit: u32,  // The number of bytes to commit for the stack.
  size_of_heap_reserve: u32, // The number of bytes to reserve for the local heap. Only the memory specified by the SizeOfHeapCommit member is committed at load time; the rest is made available one page at a time until this reserve size is reached.
  size_of_heap_commit: u32,  // The number of bytes to commit for the local heap.
  loader_flags: u32,         // Reserved, must be zero.
  number_of_rva_and_sizes: u32, // The number of directory entries in the remainder of the optional header. Each entry describes a location and size.
  data_directories: Vec<DataDirectory>,
}

#[derive(Debug, Default)]
pub struct ImageOptionalHeader64 {
  common: CommonOptionalHeaderFields,
  image_base: u64, // The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
  section_alignment: u32, // The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
  file_alignment: u32, // The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
  major_operating_system_version: u16, // The major version number of the required operating system.
  minor_operating_system_version: u16, // The minor version number of the required operating system.
  major_image_version: u16, // The major version number of the image.
  minor_image_version: u16, // The minor version number of the image.
  major_subsystem_version: u16, // The major version number of the subsystem.
  minor_subsystem_version: u16, // The minor version number of the subsystem.
  win32_version_value: u32, // Reserved, must be zero.
  size_of_image: u32, // The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
  size_of_headers: u32, // The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
  checksum: u32, // The image file checksum. The following files are validated at load time: all drivers, any DLL loaded at boot time, and any DLL loaded into a critical system process.
  subsystem: OptionalHeaderSubSystem, // The subsystem that is required to run this image.
  dll_characteristics: Vec<DLLCharacteristics>, // (u16) // The DLL characteristics of the image.
  size_of_stack_reserve: u64, // The number of bytes to reserve for the stack. Only the memory specified by the SizeOfStackCommit member is committed at load time; the rest is made available one page at a time until this reserve size is reached.
  size_of_stack_commit: u64,  // The number of bytes to commit for the stack.
  size_of_heap_reserve: u64, // The number of bytes to reserve for the local heap. Only the memory specified by the SizeOfHeapCommit member is committed at load time; the rest is made available one page at a time until this reserve size is reached.
  size_of_heap_commit: u64,  // The number of bytes to commit for the local heap.
  loader_flags: u32,         // Reserved, must be zero.
  number_of_rva_and_sizes: u32, // The number of directory entries in the remainder of the optional header. Each entry describes a location and size.
  data_directories: Vec<DataDirectory>,
}

#[derive(Debug, Default)]
pub struct DataDirectory {
  virtual_address: u32,
  size: u32,
  field: DataDirectoryTableField,
}

#[derive(Debug, Default)]
pub struct ImageOptionalHeaderRom {
  common: CommonOptionalHeaderFields,
}

#[derive(Debug, Default)]
pub struct FileHeader {
  // Same as COFF header
  machine: MachineType, // u16 originally
  number_of_sections: u16,
  time_date_stamp: u32,
  pointer_to_symbol_table: u32,
  number_of_symbols: u32,
  size_of_optional_header: u16,
  characteristics: CharacteristicsBlock, // u16 originally in COFF header
}

#[derive(Debug, Default)]
pub struct CharacteristicsBlock {
  characteristics: Vec<Characteristics>,
  value: u16,
}

#[derive(Debug, Default)]
pub struct DOSHeader {
  e_magic: String,
  e_cblp: u16,       // Bytes on last page of file
  e_cp: u16,         // Pages in file
  e_crlc: u16,       // Relocations
  e_cparhdr: u16,    // Size of header in paragraphs
  e_minalloc: u16,   // Minimum extra paragraphs needed
  e_maxalloc: u16,   // Maximum extra paragraphs needed
  e_ss: u16,         // Initial (relative) SS value
  e_sp: u16,         // Initial SP value
  e_csum: u16,       // Checksum
  e_ip: u16,         // Initial IP value
  e_cs: u16,         // Initial (relative) CS value
  e_lfarlc: u16,     // File address of relocation table
  e_ovno: u16,       // Overlay number
  e_res: [u16; 4],   // Reserved words
  e_oemid: u16,      // OEM identifier (for e_oeminfo)
  e_oeminfo: u16,    // OEM information; e_oemid specific
  e_res2: [u16; 10], // Reserved words
  e_lfanew: u32,     // File address of new exe header
}

fn parse_pe_file<'s>(input: &mut &'s [u8]) -> PResult<PEFile> {
  let start = input.checkpoint();
  let headers = parse_pe_header(input)?;
  let section_table = parse_sections_table(input, &headers)?;
  input.reset(start);
  println!("len: {}", input.len());
  // TODO
  let _ = parse_text_section(input, &section_table, &headers.nt_headers.file_header)?;

  let pe_file = PEFile {
    headers,
    section_table,
  };
  return Ok(pe_file);
}

pub fn run(bytes: Vec<u8>) {
  let mut bytes = bytes.as_slice();
  println!("original bytes: len {}", bytes.len());
  let res = parse_pe_file.parse_next(&mut bytes);

  println!("res: {:#?}", res);
  // pretty_print_bytes(bytes);
}

pub fn pretty_print_bytes(bytes: &[u8]) {
  for (index, byte) in bytes.iter().enumerate() {
    if index % 16 == 0 && index != 0 {
      println!();
    }
    print!("{:02x} ", byte);
  }
  println!();
  println!();
}
