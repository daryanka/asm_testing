use crate::parser::utils::MachineType;
use crate::parser::{FileHeader, InstructionData, SectionData, SectionEntry};
use iced_x86::{Decoder, DecoderOptions};
use winnow::error::ErrMode;
use winnow::error::ErrorKind;
use winnow::error::ParserError;
use winnow::PResult;

pub fn parse_text_section<'s>(
  input: &mut &'s [u8],
  sections: &Vec<SectionEntry>,
  file_header: &FileHeader,
) -> PResult<SectionData> {
  let text_entry = sections
    .iter()
    .find(|&x| x.name == ".text")
    .ok_or(ErrMode::from_error_kind(input, ErrorKind::Fail))?;

  // go to the start of the .text section
  let size = text_entry.size_of_raw_data as usize;

  if text_entry.pointer_to_raw_data + size as u32 > input.len() as u32 {
    return Err(ErrMode::from_error_kind(input, ErrorKind::Eof));
  }

  if size == 0 {
    return Err(ErrMode::from_error_kind(input, ErrorKind::Fail));
  }

  let text_bytes = &input
    [text_entry.pointer_to_raw_data as usize..=text_entry.pointer_to_raw_data as usize + size];

  let mut decoder = Decoder::new(
    file_header.machine.bitness(),
    text_bytes,
    match file_header.machine {
      MachineType::IMAGE_FILE_MACHINE_AMD64 => DecoderOptions::AMD,
      _ => DecoderOptions::NONE,
    },
  );

  let mut instructions_data: Vec<InstructionData> = Vec::new();
  let mut total_offset = 0;

  while decoder.can_decode() {
    let instr = decoder.decode();
    let instr_len = instr.len();
    let offset = instr.ip() as usize;
    instructions_data.push(InstructionData {
      instr,
      offset,
      size: instr_len,
      bytes: text_bytes[total_offset..total_offset + instr_len].to_vec(),
    });
    total_offset += instr_len;
  }

  Ok(SectionData {
    data: instructions_data,
    name: text_entry.name.clone(),
    bytes: text_bytes.to_vec(),
  })
}
