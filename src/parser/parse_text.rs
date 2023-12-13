use crate::parser::{pretty_print_bytes, FileHeader, SectionEntry};
use winnow::error::ErrMode;
use winnow::error::ErrorKind;
use winnow::error::Needed;
use winnow::error::ParserError;
use winnow::token::take_while;
use winnow::PResult;
use winnow::Parser;

pub fn parse_text_section<'s>(
  input: &mut &'s [u8],
  sections: &Vec<SectionEntry>,
  file_header: &FileHeader,
) -> PResult<()> {
  let text_entry = sections
    .iter()
    .find(|&x| x.name == ".text")
    .ok_or(ErrMode::from_error_kind(input, ErrorKind::Fail))?;

  // go to the start of the .text section
  println!(
    "text_entry.pointer_to_raw_data: {}",
    text_entry.pointer_to_raw_data
  );
  let text_bytes =
    &input[text_entry.pointer_to_raw_data as usize..text_entry.pointer_to_raw_data as usize + 100];

  println!("machine type {:?}", file_header.machine);
  pretty_print_bytes(text_bytes);

  Ok(())
}
