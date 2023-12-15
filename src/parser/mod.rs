use crate::parser::header_parse::{parse_pe_header, parse_sections_table};
use crate::parser::parse_text::parse_text_section;
use crate::parser::utils::{
  Characteristics, DLLCharacteristics, DataDirectoryTableField, MachineType,
  OptionalHeaderSubSystem,
};
use iced_x86::Instruction;
use winnow::stream::Stream;
use winnow::PResult;
use winnow::Parser;

mod header_parse;
mod parse_text;
mod utils;

#[derive(Debug)]
pub struct PEFile {
  pub headers: PEHeader,
  pub section_table: Vec<SectionEntry>,
  // pub sections_data: Vec<SectionData>,
  pub text_section: SectionData,
}

#[derive(Debug, Default)]
pub struct SectionData {
  pub name: String,
  pub data: Vec<InstructionData>,
  pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct InstructionData {
  pub instr: Instruction,
  pub offset: usize,
  pub size: usize,
  pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SectionEntry {
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
  pub name: String, // (originally 8 bytes)
  pub virtual_size: u32,
  pub virtual_address: u32,
  pub size_of_raw_data: u32,
  pub pointer_to_raw_data: u32,
  pub pointer_to_relocations: u32,
  pub pointer_to_linenumbers: u32,
  pub number_of_relocations: u16,
  pub number_of_linenumbers: u16,
  pub characteristics: u32, // TODO parse this into vec of characteristics, bitfield
}

#[derive(Debug)]
pub struct PEHeader {
  pub dos_header: DOSHeader,
  pub dos_stub: Vec<u8>,
  pub nt_headers: NtHeaders,
}

#[derive(Debug, Default)]
pub struct NtHeaders {
  pub signature: String,
  pub file_header: FileHeader,
  pub optional_header: Option<OptionalHeader>,
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
  pub magic: u16,
  pub major_linker_version: u8,
  pub minor_linker_version: u8,
  pub size_of_code: u32, // The size of the code (text) section, or the sum of all code sections if there are multiple sections.
  pub size_of_initialized_data: u32, // The size of the initialized data section, or the sum of all such sections if there are multiple data sections.
  pub size_of_uninitialized_data: u32, // The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.
  pub address_of_entry_point: u32, // The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero.
  pub base_of_code: u32, // The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
}

#[derive(Debug, Default)]
pub struct ImageOptionalHeader32 {
  pub common: CommonOptionalHeaderFields,
  pub base_of_data: u32, // The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
  pub image_base: u32, // The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
  pub section_alignment: u32, // The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
  pub file_alignment: u32, // The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
  pub major_operating_system_version: u16, // The major version number of the required operating system.
  pub minor_operating_system_version: u16, // The minor version number of the required operating system.
  pub major_image_version: u16,            // The major version number of the image.
  pub minor_image_version: u16,            // The minor version number of the image.
  pub major_subsystem_version: u16,        // The major version number of the subsystem.
  pub minor_subsystem_version: u16,        // The minor version number of the subsystem.
  pub win32_version_value: u32,            // Reserved, must be zero.
  pub size_of_image: u32, // The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
  pub size_of_headers: u32, // The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
  pub checksum: u32, // The image file checksum. The following files are validated at load time: all drivers, any DLL loaded at boot time, and any DLL loaded into a critical system process.
  pub subsystem: OptionalHeaderSubSystem, // The subsystem that is required to run this image.
  pub dll_characteristics: Vec<DLLCharacteristics>, // (u16) // The DLL characteristics of the image.
  pub size_of_stack_reserve: u32, // The number of bytes to reserve for the stack. Only the memory specified by the SizeOfStackCommit member is committed at load time; the rest is made available one page at a time until this reserve size is reached.
  pub size_of_stack_commit: u32,  // The number of bytes to commit for the stack.
  pub size_of_heap_reserve: u32, // The number of bytes to reserve for the local heap. Only the memory specified by the SizeOfHeapCommit member is committed at load time; the rest is made available one page at a time until this reserve size is reached.
  pub size_of_heap_commit: u32,  // The number of bytes to commit for the local heap.
  pub loader_flags: u32,         // Reserved, must be zero.
  pub number_of_rva_and_sizes: u32, // The number of directory entries in the remainder of the optional header. Each entry describes a location and size.
  pub data_directories: Vec<DataDirectory>,
}

#[derive(Debug, Default)]
pub struct ImageOptionalHeader64 {
  pub common: CommonOptionalHeaderFields,
  pub image_base: u64, // The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
  pub section_alignment: u32, // The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
  pub file_alignment: u32, // The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
  pub major_operating_system_version: u16, // The major version number of the required operating system.
  pub minor_operating_system_version: u16, // The minor version number of the required operating system.
  pub major_image_version: u16,            // The major version number of the image.
  pub minor_image_version: u16,            // The minor version number of the image.
  pub major_subsystem_version: u16,        // The major version number of the subsystem.
  pub minor_subsystem_version: u16,        // The minor version number of the subsystem.
  pub win32_version_value: u32,            // Reserved, must be zero.
  pub size_of_image: u32, // The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
  pub size_of_headers: u32, // The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
  pub checksum: u32, // The image file checksum. The following files are validated at load time: all drivers, any DLL loaded at boot time, and any DLL loaded into a critical system process.
  pub subsystem: OptionalHeaderSubSystem, // The subsystem that is required to run this image.
  pub dll_characteristics: Vec<DLLCharacteristics>, // (u16) // The DLL characteristics of the image.
  pub size_of_stack_reserve: u64, // The number of bytes to reserve for the stack. Only the memory specified by the SizeOfStackCommit member is committed at load time; the rest is made available one page at a time until this reserve size is reached.
  pub size_of_stack_commit: u64,  // The number of bytes to commit for the stack.
  pub size_of_heap_reserve: u64, // The number of bytes to reserve for the local heap. Only the memory specified by the SizeOfHeapCommit member is committed at load time; the rest is made available one page at a time until this reserve size is reached.
  pub size_of_heap_commit: u64,  // The number of bytes to commit for the local heap.
  pub loader_flags: u32,         // Reserved, must be zero.
  pub number_of_rva_and_sizes: u32, // The number of directory entries in the remainder of the optional header. Each entry describes a location and size.
  pub data_directories: Vec<DataDirectory>,
}

#[derive(Debug, Default)]
pub struct DataDirectory {
  pub virtual_address: u32,
  pub size: u32,
  pub field: DataDirectoryTableField,
}

#[derive(Debug, Default)]
pub struct ImageOptionalHeaderRom {
  pub common: CommonOptionalHeaderFields,
}

#[derive(Debug, Default)]
pub struct FileHeader {
  // Same as COFF header
  pub machine: MachineType, // u16 originally
  pub number_of_sections: u16,
  pub time_date_stamp: u32,
  pub pointer_to_symbol_table: u32,
  pub number_of_symbols: u32,
  pub size_of_optional_header: u16,
  pub characteristics: CharacteristicsBlock, // u16 originally in COFF header
}

#[derive(Debug, Default)]
pub struct CharacteristicsBlock {
  pub characteristics: Vec<Characteristics>,
  pub value: u16,
}

#[derive(Debug, Default)]
pub struct DOSHeader {
  pub e_magic: String,
  pub e_cblp: u16,       // Bytes on last page of file
  pub e_cp: u16,         // Pages in file
  pub e_crlc: u16,       // Relocations
  pub e_cparhdr: u16,    // Size of header in paragraphs
  pub e_minalloc: u16,   // Minimum extra paragraphs needed
  pub e_maxalloc: u16,   // Maximum extra paragraphs needed
  pub e_ss: u16,         // Initial (relative) SS value
  pub e_sp: u16,         // Initial SP value
  pub e_csum: u16,       // Checksum
  pub e_ip: u16,         // Initial IP value
  pub e_cs: u16,         // Initial (relative) CS value
  pub e_lfarlc: u16,     // File address of relocation table
  pub e_ovno: u16,       // Overlay number
  pub e_res: [u16; 4],   // Reserved words
  pub e_oemid: u16,      // OEM identifier (for e_oeminfo)
  pub e_oeminfo: u16,    // OEM information; e_oemid specific
  pub e_res2: [u16; 10], // Reserved words
  pub e_lfanew: u32,     // File address of new exe header
}

fn parse_pe_file<'s>(input: &mut &'s [u8]) -> PResult<PEFile> {
  let start = input.checkpoint();
  let headers = parse_pe_header(input)?;
  let section_table = parse_sections_table(input, &headers)?;
  input.reset(start);
  let text_section = parse_text_section(input, &section_table, &headers.nt_headers.file_header)?;

  let pe_file = PEFile {
    headers,
    section_table,
    text_section,
  };

  Ok(pe_file)
}

pub fn parse_pe(bytes: Vec<u8>) -> Result<PEFile, ()> {
  let mut bytes = bytes.as_slice();
  let res = parse_pe_file.parse_next(&mut bytes).map_err(|_| ())?;
  Ok(res)
}
