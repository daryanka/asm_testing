use crate::parser::{FileHeader, SectionData, SectionEntry};
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
  println!(
    "text_entry.pointer_to_raw_data: {}",
    text_entry.pointer_to_raw_data
  );
  let size = text_entry.size_of_raw_data as usize;

  if text_entry.pointer_to_raw_data + size as u32 > input.len() as u32 {
    return Err(ErrMode::from_error_kind(input, ErrorKind::Eof));
  }

  if size == 0 {
    return Err(ErrMode::from_error_kind(input, ErrorKind::Fail));
  }

  let text_bytes =
    &input[text_entry.pointer_to_raw_data as usize..text_entry.pointer_to_raw_data as usize + size];

  let mut decoder = Decoder::new(
    file_header.machine.bitness(),
    text_bytes,
    DecoderOptions::NONE,
  );

  let mut data = Vec::new();

  while decoder.can_decode() {
    let instr = decoder.decode();
    data.push(instr);
  }

  Ok(SectionData {
    data,
    name: text_entry.name.clone(),
  })
}
