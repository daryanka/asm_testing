use std::io::BufReader;
use std::io::{Read, Write};

mod parser;
mod tui;

fn main() {
  let args = std::env::args().collect::<Vec<String>>();
  if args.len() < 2 {
    print_color(
      "Please provide a file to disassemble",
      termcolor::Color::Yellow,
    );
    return;
  }

  let bytes = open_file_and_read_bytes(&args[1]);
  let bytes = match bytes {
    Ok(bytes) => bytes,
    Err(err) => {
      print_color(&err, termcolor::Color::Red);
      return;
    }
  };

  if !is_pe_executable(&bytes) {
    print_color("File is not a PE executable", termcolor::Color::Red);
    return;
  }

  let data = parser::parse_pe(bytes);
  let pe_file = match data {
    Ok(data) => data,
    Err(_) => {
      print_color(
        "Unable to disassemble, please ensure the executable is valid",
        termcolor::Color::Red,
      );
      return;
    }
  };
  let _ = tui::draw(pe_file);
}

fn print_color(text: &str, color: termcolor::Color) {
  use termcolor::{ColorChoice, ColorSpec, StandardStream, WriteColor};
  let mut stdout = StandardStream::stdout(ColorChoice::Always);
  stdout
    .set_color(ColorSpec::new().set_fg(Some(color)))
    .unwrap();
  writeln!(&mut stdout, "{}", text).unwrap();
  stdout.reset().unwrap();
}

fn open_file_and_read_bytes(file_path: &str) -> Result<Vec<u8>, String> {
  let file = std::fs::File::open(file_path).map_err(|e| match e.kind() {
    std::io::ErrorKind::NotFound => "File not found".to_owned(),
    _ => format!("Error opening file: {}", e.kind().to_string()),
  })?;
  let mut buf = BufReader::new(file);

  let mut bytes: Vec<u8> = Vec::new();

  buf
    .read_to_end(&mut bytes)
    .map_err(|e| format!("Error reading file: {}", e.kind().to_string()))?;
  Ok(bytes)
}

// fn is_elf_executable(data: &Vec<u8>) -> bool {
//   if data.len() < 4 {
//     return false;
//   }
//   return data[0..4] == [0x7f, 0x45, 0x4c, 0x46];
// }

fn is_pe_executable(data: &Vec<u8>) -> bool {
  if data.len() < 2 {
    return false;
  }
  data[0..2] == [0x4d, 0x5a]
}
