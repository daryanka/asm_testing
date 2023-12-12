use crate::parser::utils::{
  get_le_u64, get_single_u8, Characteristics, DLLCharacteristics, DataDirectoryTableField,
  MachineType, OptionalHeaderSubSystem,
};
use winnow::error::ErrMode;
use winnow::error::ErrorKind;
use winnow::error::Needed;
use winnow::error::ParserError;
use winnow::stream::Stream;
use winnow::token::take_while;
use winnow::PResult;
use winnow::Parser;

use self::utils::format_to_hex;
use self::utils::get_ascii_string;
use self::utils::get_le_u16;
use self::utils::get_le_u16_vec;
use self::utils::get_le_u32;

mod utils;

#[derive(Debug)]
struct PEFile {
  headers: PEHeader,
}

#[derive(Debug)]
struct PEHeader {
  dos_header: DOSHeader,
  dos_stub: Vec<u8>,
  nt_headers: NtHeaders,
}

#[derive(Debug, Default)]
struct NtHeaders {
  signature: String,
  file_header: FileHeader,
  optional_header: Option<OptionalHeader>,
}

#[derive(Debug)]
enum OptionalHeader {
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
struct CommonOptionalHeaderFields {
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
struct ImageOptionalHeader32 {
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
struct ImageOptionalHeader64 {
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
struct DataDirectory {
  virtual_address: u32,
  size: u32,
  field: DataDirectoryTableField,
}

#[derive(Debug, Default)]
struct ImageOptionalHeaderRom {
  common: CommonOptionalHeaderFields,
}

#[derive(Debug, Default)]
struct FileHeader {
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
struct CharacteristicsBlock {
  characteristics: Vec<Characteristics>,
  value: u16,
}

#[derive(Debug, Default)]
struct DOSHeader {
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

fn parse_dos_header<'s>(input: &mut &'s [u8]) -> PResult<(DOSHeader, Vec<u8>)> {
  // get first 64 bytes
  let mut header_bytes = take_while(0..=64, |_| true).parse_next(input)?;
  if header_bytes.len() != 64 {
    return Err(ErrMode::Incomplete(Needed::new(64)));
  }

  let magic = get_ascii_string(&mut header_bytes, 2)?;
  if magic != "MZ" {
    return Err(ErrMode::from_error_kind(input, ErrorKind::Verify));
  }

  let mut dos_header = DOSHeader::default();

  dos_header.e_magic = magic;
  dos_header.e_cblp = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_cp = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_crlc = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_cparhdr = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_minalloc = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_maxalloc = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_ss = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_sp = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_csum = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_ip = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_cs = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_lfarlc = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_ovno = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_res = get_le_u16_vec(&mut header_bytes, 4)?.try_into().unwrap();
  dos_header.e_oemid = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_oeminfo = get_le_u16.parse_next(&mut header_bytes)?;
  dos_header.e_res2 = get_le_u16_vec(&mut header_bytes, 10)?.try_into().unwrap();
  dos_header.e_lfanew = get_le_u32.parse_next(&mut header_bytes)?;

  let distance_to_pe_header = dos_header.e_lfanew as usize - 64;
  let dos_stub = take_while(0..=distance_to_pe_header, |_| true).parse_next(input)?;

  Ok((dos_header, dos_stub.to_vec()))
}

fn parse_nt_header<'s>(input: &mut &'s [u8]) -> PResult<NtHeaders> {
  let mut nt_header = NtHeaders::default();

  // Signature
  nt_header.signature = get_ascii_string(input, 4)?; // should be PE\0\0, 4 bytes since its a DWORD

  // File Header
  let mut file_header = FileHeader::default();
  file_header.machine = MachineType::try_from(get_le_u16.parse_next(input)?)
    .map_err(|_| ParserError::from_error_kind(input, ErrorKind::Verify))?;
  file_header.number_of_sections = get_le_u16.parse_next(input)?;
  file_header.time_date_stamp = get_le_u32.parse_next(input)?;
  file_header.pointer_to_symbol_table = get_le_u32.parse_next(input)?;
  file_header.number_of_symbols = get_le_u32.parse_next(input)?;
  file_header.size_of_optional_header = get_le_u16.parse_next(input)?;

  let characteristics_u16 = get_le_u16.parse_next(input)?;
  file_header.characteristics.value = characteristics_u16;
  file_header.characteristics.characteristics =
    Characteristics::get_characteristics(characteristics_u16);

  nt_header.file_header = file_header;

  // Optional Header
  if nt_header.file_header.size_of_optional_header == 0 {
    return Ok(nt_header);
  }

  let mut optional_header_bytes = take_while(
    0..=nt_header.file_header.size_of_optional_header as usize,
    |_| true,
  )
  .parse_next(input)?;
  if optional_header_bytes.len() != nt_header.file_header.size_of_optional_header as usize {
    return Err(ErrMode::Incomplete(Needed::new(
      nt_header.file_header.size_of_optional_header as usize,
    )));
  }

  let magic = get_le_u16.parse_next(&mut optional_header_bytes)?;
  let mut optional_header = match magic {
    0x10b => OptionalHeader::ImageOptionalHeader32(ImageOptionalHeader32::default()),
    0x20b => OptionalHeader::ImageOptionalHeader64(ImageOptionalHeader64::default()),
    0x107 => OptionalHeader::ImageOptionalHeaderRom(ImageOptionalHeaderRom::default()),
    _ => return Err(ErrMode::from_error_kind(input, ErrorKind::Verify)),
  };

  let mut common = CommonOptionalHeaderFields::default();
  common.magic = magic;

  common.major_linker_version = get_single_u8.parse_next(&mut optional_header_bytes)?;
  common.minor_linker_version = get_single_u8.parse_next(&mut optional_header_bytes)?;
  common.size_of_code = get_le_u32.parse_next(&mut optional_header_bytes)?;
  common.size_of_initialized_data = get_le_u32.parse_next(&mut optional_header_bytes)?;
  common.size_of_uninitialized_data = get_le_u32.parse_next(&mut optional_header_bytes)?;
  common.address_of_entry_point = get_le_u32.parse_next(&mut optional_header_bytes)?;
  common.base_of_code = get_le_u32.parse_next(&mut optional_header_bytes)?;

  match &mut optional_header {
    OptionalHeader::ImageOptionalHeader32(header) => {
      header.common = common;
      header.base_of_data = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.image_base = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.section_alignment = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.file_alignment = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.major_operating_system_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.minor_operating_system_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.major_image_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.minor_image_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.major_subsystem_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.minor_subsystem_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.win32_version_value = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.size_of_image = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.size_of_headers = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.checksum = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.subsystem =
        OptionalHeaderSubSystem::try_from(get_le_u16.parse_next(&mut optional_header_bytes)?)
          .map_err(|_| ParserError::from_error_kind(input, ErrorKind::Verify))?;
      header.dll_characteristics =
        DLLCharacteristics::from_u16(get_le_u16.parse_next(&mut optional_header_bytes)?);

      // 32 bits part
      header.size_of_stack_reserve = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.size_of_stack_commit = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.size_of_heap_reserve = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.size_of_heap_commit = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.loader_flags = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.number_of_rva_and_sizes = get_le_u32.parse_next(&mut optional_header_bytes)?;

      // number of rva and sizes should always be 16 with the last row (8 bytes) being 0
      let mut data_directories = Vec::new();
      for index in 0..header.number_of_rva_and_sizes {
        let virtual_address = get_le_u32.parse_next(&mut optional_header_bytes)?;
        let size = get_le_u32.parse_next(&mut optional_header_bytes)?;
        let field = DataDirectoryTableField::try_from(index)
          .map_err(|_| ParserError::from_error_kind(input, ErrorKind::Verify))?;

        data_directories.push(DataDirectory {
          virtual_address,
          size,
          field,
        });
      }
      header.data_directories = data_directories;
    }
    OptionalHeader::ImageOptionalHeader64(header) => {
      header.common = common;
      header.image_base = get_le_u64.parse_next(&mut optional_header_bytes)?;
      header.section_alignment = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.file_alignment = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.major_operating_system_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.minor_operating_system_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.major_image_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.minor_image_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.major_subsystem_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.minor_subsystem_version = get_le_u16.parse_next(&mut optional_header_bytes)?;
      header.win32_version_value = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.size_of_image = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.size_of_headers = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.checksum = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.subsystem =
        OptionalHeaderSubSystem::try_from(get_le_u16.parse_next(&mut optional_header_bytes)?)
          .map_err(|_| ParserError::from_error_kind(input, ErrorKind::Verify))?;
      header.dll_characteristics =
        DLLCharacteristics::from_u16(get_le_u16.parse_next(&mut optional_header_bytes)?);

      // 64 bits part
      header.size_of_stack_reserve = get_le_u64.parse_next(&mut optional_header_bytes)?;
      header.size_of_stack_commit = get_le_u64.parse_next(&mut optional_header_bytes)?;
      header.size_of_heap_reserve = get_le_u64.parse_next(&mut optional_header_bytes)?;
      header.size_of_heap_commit = get_le_u64.parse_next(&mut optional_header_bytes)?;
      header.loader_flags = get_le_u32.parse_next(&mut optional_header_bytes)?;
      header.number_of_rva_and_sizes = get_le_u32.parse_next(&mut optional_header_bytes)?;

      // number of rva and sizes should always be 16 with the last row (8 bytes) being 0
      let mut data_directories = Vec::new();
      for index in 0..header.number_of_rva_and_sizes {
        let virtual_address = get_le_u32.parse_next(&mut optional_header_bytes)?;
        let size = get_le_u32.parse_next(&mut optional_header_bytes)?;
        let field = DataDirectoryTableField::try_from(index)
          .map_err(|_| ParserError::from_error_kind(input, ErrorKind::Verify))?;

        data_directories.push(DataDirectory {
          virtual_address,
          size,
          field,
        });
      }
      header.data_directories = data_directories;
    }
    OptionalHeader::ImageOptionalHeaderRom(header) => {
      header.common = common;
    }
  }

  nt_header.optional_header = Some(optional_header);

  Ok(nt_header)
}
fn parse_pe_header<'s>(input: &mut &'s [u8]) -> PResult<PEHeader> {
  let (dos_header, dos_stub) = parse_dos_header(input)?;
  let nt_header = parse_nt_header(input)?;

  Ok(PEHeader {
    dos_header: dos_header,
    dos_stub: dos_stub.to_vec(),
    nt_headers: nt_header,
  })
}

fn parse_pe_file<'s>(input: &mut &'s [u8]) -> PResult<PEFile> {
  let start = input.checkpoint();
  let headers = parse_pe_header(input)?;
  input.reset(start);

  let pe_file = PEFile { headers };
  return Ok(pe_file);
}

pub fn run(bytes: Vec<u8>) {
  let mut bytes = bytes.as_slice();
  println!("original bytes: len {}", bytes.len());
  let mut bytes = &bytes[0..500];
  let res = parse_pe_file.parse_next(&mut bytes);

  println!("res: {:#?}", res.unwrap().headers.nt_headers);
  pretty_print_bytes(bytes);
}

fn pretty_print_bytes(bytes: &[u8]) {
  for (index, byte) in bytes.iter().enumerate() {
    if index % 16 == 0 && index != 0 {
      println!();
    }
    print!("{:02x} ", byte);
  }
  println!();
  println!();
}
