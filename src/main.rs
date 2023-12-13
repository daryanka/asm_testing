use std::io::prelude::*;
use std::io::BufReader;
use std::io::BufWriter;

mod parser;

fn main() {
  // let file = std::fs::File::open("./disassembler_linux").unwrap();
  let file = std::fs::File::open("./disassembler_win.exe").unwrap();

  let mut buf = BufReader::new(file);

  let mut bytes: Vec<u8> = Vec::new();

  buf.read_to_end(&mut bytes).unwrap();

  if !is_pe_executable(&bytes) {
    panic!("Not a PE executable");
  }

  // Debugging
  // write_to_temp(bytes);
  let data = parser::parse_pe(bytes);
  println!("{}", std::mem::size_of_val(&data));
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
  return data[0..2] == [0x4d, 0x5a];
}
