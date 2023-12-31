use crate::parser::utils::{
  get_ascii_string, get_le_u16, get_le_u16_vec, get_le_u32, get_le_u64, get_single_u8,
  get_utf8_null_terminated_string, Characteristics, DLLCharacteristics, DataDirectoryTableField,
  MachineType, OptionalHeaderSubSystem,
};
use crate::parser::{
  CommonOptionalHeaderFields, DOSHeader, DataDirectory, FileHeader, ImageOptionalHeader32,
  ImageOptionalHeader64, ImageOptionalHeaderRom, NtHeaders, OptionalHeader, PEHeader, SectionEntry,
};
use winnow::error::ErrMode;
use winnow::error::ErrorKind;
use winnow::error::Needed;
use winnow::error::ParserError;
use winnow::token::take_while;
use winnow::PResult;
use winnow::Parser;

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
pub fn parse_pe_header<'s>(input: &mut &'s [u8]) -> PResult<PEHeader> {
  let (dos_header, dos_stub) = parse_dos_header(input)?;
  let nt_header = parse_nt_header(input)?;

  Ok(PEHeader {
    dos_header: dos_header,
    dos_stub: dos_stub.to_vec(),
    nt_headers: nt_header,
  })
}

pub fn parse_sections_table<'s>(
  input: &mut &'s [u8],
  pe_header: &PEHeader,
) -> PResult<Vec<SectionEntry>> {
  let mut sections = Vec::new();

  let number_of_sections = pe_header.nt_headers.file_header.number_of_sections;

  for _ in 0..number_of_sections {
    let mut section = SectionEntry::default();

    section.name = get_utf8_null_terminated_string(input, 8)?;
    section.virtual_size = get_le_u32.parse_next(input)?;
    section.virtual_address = get_le_u32.parse_next(input)?;
    section.size_of_raw_data = get_le_u32.parse_next(input)?;
    section.pointer_to_raw_data = get_le_u32.parse_next(input)?;
    section.pointer_to_relocations = get_le_u32.parse_next(input)?;
    section.pointer_to_linenumbers = get_le_u32.parse_next(input)?;
    section.number_of_relocations = get_le_u16.parse_next(input)?;
    section.number_of_linenumbers = get_le_u16.parse_next(input)?;
    section.characteristics = get_le_u32.parse_next(input)?;

    sections.push(section);
  }

  Ok(sections)
}
