use crate::parser::utils::{Characteristics, MachineType};
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
  // optional_header: Option<OptionalHeader>,
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
  pretty_print_bytes(input);
  nt_header.signature = get_ascii_string(input, 4)?; // should be PE\0\0, 4 bytes since its a DWORD
  pretty_print_bytes(input);

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

  println!("file_header: {:#?}", file_header.machine);

  nt_header.file_header = file_header;
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
