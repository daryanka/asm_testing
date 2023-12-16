use crate::parser::{CommonOptionalHeaderFields, OptionalHeader, PEFile};
use crossterm::event::EnableMouseCapture;
use crossterm::{
  event::{self, KeyCode, KeyEventKind},
  execute,
  terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
  ExecutableCommand,
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::{prelude::*, widgets::*};
use ratatui::{
  prelude::{CrosstermBackend, Terminal},
  widgets::Paragraph,
  Frame,
};
use std::fmt::LowerHex;
use std::io::stdout;
use strum::EnumIter;

#[derive(Debug, EnumIter, Clone, PartialEq)]
enum Tab {
  Disassembly,
  Headers,
}

impl Into<String> for &Tab {
  fn into(self) -> String {
    match self {
      Tab::Disassembly => "Disassembly".to_owned(),
      Tab::Headers => "Headers".to_owned(),
    }
  }
}

struct App {
  tabs: Vec<Tab>,
  active_tab: Tab,
  data: PEFile,
  data_scroll: usize,
  header_scroll: usize,
  header_lines: Vec<Line<'static>>,
}

impl App {
  fn new(data: PEFile) -> Self {
    let mut temp = App {
      tabs: vec![Tab::Disassembly, Tab::Headers],
      active_tab: Tab::Disassembly,
      data,
      data_scroll: 0,
      header_scroll: 0,
      header_lines: vec![],
    };
    temp.generate_headers_lines();
    temp
  }

  fn generate_headers_lines(&mut self) {
    let app = &self;
    let mut lines: Vec<Line> = Vec::new();

    // DOS Headers
    lines.push(Line::from(vec!["DOS Headers".yellow()]));
    let mut dos_lines: Vec<HeaderKeyValue> = Vec::new();

    dos_lines.push(HeaderKeyValue {
      key: "Magic".to_owned(),
      value: app.data.headers.dos_header.e_magic.clone(),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Bytes On last page".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_cblp),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Relocations".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_crlc),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Size of header in paragraphs".to_owned().to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_cparhdr),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Minimum extra paragraphs needed".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_minalloc),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Maximum extra paragraphs needed".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_maxalloc),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Initial (relative) SS value".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_ss),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Initial SP value".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_sp),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Checksum".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_csum),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Initial IP value".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_ip),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Initial (relative) CS value".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_cs),
    });
    dos_lines.push(HeaderKeyValue {
      key: "File address of relocation table".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_lfarlc),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Overlay number".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_ovno),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Reserved words".to_owned(),
      value: app
        .data
        .headers
        .dos_header
        .e_res
        .to_vec()
        .iter()
        .map(|x| format!("{:#x}", x))
        .collect::<Vec<String>>()
        .join(", "),
    });
    dos_lines.push(HeaderKeyValue {
      key: "OEM identifier (for e_oeminfo)".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_oemid),
    });
    dos_lines.push(HeaderKeyValue {
      key: "OEM information; e_oemid specific".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_oeminfo),
    });
    dos_lines.push(HeaderKeyValue {
      key: "Reserved words".to_owned(),
      value: app
        .data
        .headers
        .dos_header
        .e_res2
        .to_vec()
        .iter()
        .map(|x| format!("{:#x}", x))
        .collect::<Vec<String>>()
        .join(", "),
    });
    dos_lines.push(HeaderKeyValue {
      key: "File address of new exe header".to_owned(),
      value: util_hex(&app.data.headers.dos_header.e_lfanew),
    });

    let dos_lines = dos_lines
      .iter()
      .map(|x| {
        let mut line_parts = vec![];
        line_parts.push(" ".to_owned().into());
        line_parts.push(x.key.clone().yellow());
        line_parts.push(" ".into());
        line_parts.push(x.value.clone().white());
        Line::from(line_parts)
      })
      .collect::<Vec<Line>>();

    lines.extend_from_slice(&dos_lines);

    // NT Headers
    lines.push(Line::from(vec!["  ".into()]));
    lines.push(Line::from(vec!["NT Headers".yellow()]));

    let mut nt_lines: Vec<HeaderKeyValue> = Vec::new();
    nt_lines.push(HeaderKeyValue {
      key: "Signature".to_owned(),
      value: app.data.headers.nt_headers.signature.clone(),
    });

    nt_lines.push(HeaderKeyValue {
      key: "Machine".to_owned(),
      value: app
        .data
        .headers
        .nt_headers
        .file_header
        .machine
        .clone()
        .into(),
    });
    nt_lines.push(HeaderKeyValue {
      key: "number_of_sections".to_owned(),
      value: util_hex(&app.data.headers.nt_headers.file_header.number_of_sections),
    });

    let time_date_stamp = app.data.headers.nt_headers.file_header.time_date_stamp;
    let time_date_stamp = match chrono::NaiveDateTime::from_timestamp_opt(time_date_stamp as i64, 0)
    {
      Some(x) => x.format("%Y-%m-%d %H:%M:%S").to_string(),
      None => "Not a valid timestamp".to_owned(),
    };
    nt_lines.push(HeaderKeyValue {
      key: "time_date_stamp".to_owned(),
      value: time_date_stamp,
    });
    nt_lines.push(HeaderKeyValue {
      key: "pointer_to_symbol_table".to_owned(),
      value: util_hex(
        &app
          .data
          .headers
          .nt_headers
          .file_header
          .pointer_to_symbol_table,
      ),
    });
    nt_lines.push(HeaderKeyValue {
      key: "number_of_symbols".to_owned(),
      value: util_hex(&app.data.headers.nt_headers.file_header.number_of_symbols),
    });
    nt_lines.push(HeaderKeyValue {
      key: "size_of_optional_header".to_owned(),
      value: util_hex(
        &app
          .data
          .headers
          .nt_headers
          .file_header
          .size_of_optional_header,
      ),
    });
    nt_lines.push(HeaderKeyValue {
      key: "Characteristics".to_owned(),
      value: app
        .data
        .headers
        .nt_headers
        .file_header
        .characteristics
        .characteristics
        .iter()
        .map(|x| {
          let x: &str = x.into();
          x.to_owned()
        })
        .collect::<Vec<String>>()
        .join(", "),
    });

    //  Optional Header
    let nt_optional_header_lines = match &app.data.headers.nt_headers.optional_header {
      Some(optional_headers) => match optional_headers {
        OptionalHeader::ImageOptionalHeader32(val) => {
          let mut lines = get_common_values(&val.common);
          lines.push(HeaderKeyValue::default());

          lines.push(HeaderKeyValue {
            key: "base_of_data".to_owned(),
            value: util_hex(&val.base_of_data),
          });
          lines.push(HeaderKeyValue {
            key: "image_base".to_owned(),
            value: util_hex(&val.image_base),
          });
          lines.push(HeaderKeyValue {
            key: "section_alignment".to_owned(),
            value: util_hex(&val.section_alignment),
          });
          lines.push(HeaderKeyValue {
            key: "file_alignment".to_owned(),
            value: util_hex(&val.file_alignment),
          });
          lines.push(HeaderKeyValue {
            key: "major_operating_system_version".to_owned(),
            value: util_hex(&val.major_operating_system_version),
          });
          lines.push(HeaderKeyValue {
            key: "minor_operating_system_version".to_owned(),
            value: util_hex(&val.minor_operating_system_version),
          });
          lines.push(HeaderKeyValue {
            key: "major_image_version".to_owned(),
            value: util_hex(&val.major_image_version),
          });
          lines.push(HeaderKeyValue {
            key: "minor_image_version".to_owned(),
            value: util_hex(&val.minor_image_version),
          });
          lines.push(HeaderKeyValue {
            key: "major_subsystem_version".to_owned(),
            value: util_hex(&val.major_subsystem_version),
          });
          lines.push(HeaderKeyValue {
            key: "minor_subsystem_version".to_owned(),
            value: util_hex(&val.minor_subsystem_version),
          });
          lines.push(HeaderKeyValue {
            key: "win32_version_value".to_owned(),
            value: util_hex(&val.win32_version_value),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_image".to_owned(),
            value: util_hex(&val.size_of_image),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_headers".to_owned(),
            value: util_hex(&val.size_of_headers),
          });
          lines.push(HeaderKeyValue {
            key: "checksum".to_owned(),
            value: util_hex(&val.checksum),
          });
          lines.push(HeaderKeyValue {
            key: "subsystem".to_owned(),
            value: {
              let str: &str = val.subsystem.clone().into();
              str.to_owned()
            },
          });
          lines.push(HeaderKeyValue {
            key: "dll_characteristics".to_owned(),
            value: val
              .dll_characteristics
              .iter()
              .map(|x| {
                let str: &str = x.into();
                str.to_owned()
              })
              .collect::<Vec<String>>()
              .join(", "),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_stack_reserve".to_owned(),
            value: util_hex(&val.size_of_stack_reserve),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_stack_commit".to_owned(),
            value: util_hex(&val.size_of_stack_commit),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_heap_reserve".to_owned(),
            value: util_hex(&val.size_of_heap_reserve),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_heap_commit".to_owned(),
            value: util_hex(&val.size_of_heap_commit),
          });
          lines.push(HeaderKeyValue {
            key: "loader_flags".to_owned(),
            value: util_hex(&val.loader_flags),
          });
          lines.push(HeaderKeyValue {
            key: "number_of_rva_and_sizes".to_owned(),
            value: util_hex(&val.number_of_rva_and_sizes),
          });
          lines.push(HeaderKeyValue {
            key: "data_directories".to_owned(),
            value: val
              .data_directories
              .iter()
              .map(|x| {
                let s: &str = x.field.clone().into();
                s.to_owned()
              })
              .collect::<Vec<String>>()
              .join(", "),
          });

          lines
        }
        OptionalHeader::ImageOptionalHeader64(val) => {
          let mut lines = get_common_values(&val.common);

          lines.push(HeaderKeyValue::default());

          lines.push(HeaderKeyValue {
            key: "image_base".to_owned(),
            value: util_hex(&val.image_base),
          });
          lines.push(HeaderKeyValue {
            key: "section_alignment".to_owned(),
            value: util_hex(&val.section_alignment),
          });
          lines.push(HeaderKeyValue {
            key: "file_alignment".to_owned(),
            value: util_hex(&val.file_alignment),
          });
          lines.push(HeaderKeyValue {
            key: "major_operating_system_version".to_owned(),
            value: util_hex(&val.major_operating_system_version),
          });
          lines.push(HeaderKeyValue {
            key: "minor_operating_system_version".to_owned(),
            value: util_hex(&val.minor_operating_system_version),
          });
          lines.push(HeaderKeyValue {
            key: "major_image_version".to_owned(),
            value: util_hex(&val.major_image_version),
          });
          lines.push(HeaderKeyValue {
            key: "minor_image_version".to_owned(),
            value: util_hex(&val.minor_image_version),
          });
          lines.push(HeaderKeyValue {
            key: "major_subsystem_version".to_owned(),
            value: util_hex(&val.major_subsystem_version),
          });
          lines.push(HeaderKeyValue {
            key: "minor_subsystem_version".to_owned(),
            value: util_hex(&val.minor_subsystem_version),
          });
          lines.push(HeaderKeyValue {
            key: "win32_version_value".to_owned(),
            value: util_hex(&val.win32_version_value),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_image".to_owned(),
            value: util_hex(&val.size_of_image),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_headers".to_owned(),
            value: util_hex(&val.size_of_headers),
          });
          lines.push(HeaderKeyValue {
            key: "checksum".to_owned(),
            value: util_hex(&val.checksum),
          });
          lines.push(HeaderKeyValue {
            key: "subsystem".to_owned(),
            value: {
              let str: &str = val.subsystem.clone().into();
              str.to_owned()
            },
          });
          lines.push(HeaderKeyValue {
            key: "dll_characteristics".to_owned(),
            value: val
              .dll_characteristics
              .iter()
              .map(|x| {
                let str: &str = x.into();
                str.to_owned()
              })
              .collect::<Vec<String>>()
              .join(", "),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_stack_reserve".to_owned(),
            value: util_hex(&val.size_of_stack_reserve),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_stack_commit".to_owned(),
            value: util_hex(&val.size_of_stack_commit),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_heap_reserve".to_owned(),
            value: util_hex(&val.size_of_heap_reserve),
          });
          lines.push(HeaderKeyValue {
            key: "size_of_heap_commit".to_owned(),
            value: util_hex(&val.size_of_heap_commit),
          });
          lines.push(HeaderKeyValue {
            key: "loader_flags".to_owned(),
            value: util_hex(&val.loader_flags),
          });
          lines.push(HeaderKeyValue {
            key: "number_of_rva_and_sizes".to_owned(),
            value: util_hex(&val.number_of_rva_and_sizes),
          });
          lines.push(HeaderKeyValue {
            key: "data_directories".to_owned(),
            value: val
              .data_directories
              .iter()
              .map(|x| {
                let s: &str = x.field.clone().into();
                s.to_owned()
              })
              .collect::<Vec<String>>()
              .join(", "),
          });

          lines
        }
        OptionalHeader::ImageOptionalHeaderRom(val) => get_common_values(&val.common),
      },
      _ => vec![],
    };

    nt_lines.push(HeaderKeyValue::default());
    nt_lines.push(HeaderKeyValue {
      key: "Optional Headers".to_owned(),
      value: "".to_owned(),
    });
    nt_lines.extend_from_slice(&nt_optional_header_lines);

    lines.extend_from_slice(
      &nt_lines
        .iter()
        .map(|x| {
          let mut line_parts = vec![];
          line_parts.push(" ".to_owned().into());
          line_parts.push(x.key.clone().yellow());
          line_parts.push(" ".into());
          line_parts.push(x.value.clone().white());
          Line::from(line_parts)
        })
        .collect::<Vec<Line>>(),
    );

    self.header_lines = lines;
  }

  fn next_tab(&mut self) {
    self.active_tab = self
      .tabs
      .iter()
      .cycle()
      .skip_while(|t| **t != self.active_tab)
      .nth(1)
      .unwrap()
      .clone();
  }

  fn scroll_down(&mut self) {
    match self.active_tab {
      Tab::Disassembly => {
        if self.data_scroll < self.data.text_section.data.len() {
          self.data_scroll += 1;
        }
      }
      Tab::Headers => {
        self.header_scroll += 1;
      }
    }
  }

  fn scroll_up(&mut self) {
    match self.active_tab {
      Tab::Disassembly => {
        if self.data_scroll > 0 {
          self.data_scroll -= 1;
        }
      }
      Tab::Headers => {
        if self.header_scroll > 0 {
          self.header_scroll -= 1;
        }
      }
    }
  }
}

pub fn draw(file_data: PEFile) -> anyhow::Result<()> {
  let mut app = App::new(file_data);
  execute!(stdout(), EnterAlternateScreen, EnableMouseCapture)?;
  enable_raw_mode()?;
  let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
  terminal.clear()?;

  loop {
    terminal.draw(|frame| {
      ui(frame, &mut app);
    })?;

    // 30 fps = 33ms, can use 16ms for 60fps
    if event::poll(std::time::Duration::from_millis(33))? {
      let event = event::read()?;
      if let event::Event::Mouse(event) = event {
        if event.kind == event::MouseEventKind::ScrollDown {
          app.scroll_down();
        }
        if event.kind == event::MouseEventKind::ScrollUp {
          app.scroll_up();
        }
      }

      if let event::Event::Key(key) = event {
        // break on ctrl+c or q
        if key.kind == KeyEventKind::Press
          && (key.modifiers == event::KeyModifiers::CONTROL && key.code == KeyCode::Char('c'))
          || key.code == KeyCode::Char('q')
        {
          break;
        }

        // on tab, change the active tab
        if key.kind == KeyEventKind::Press && key.code == KeyCode::Tab {
          app.next_tab();
        }

        // on up/down arrow keys
        if key.kind == KeyEventKind::Press && key.code == KeyCode::Up {
          app.scroll_up();
        }
        if key.kind == KeyEventKind::Press && key.code == KeyCode::Down {
          app.scroll_down();
        }

        // move on scroll wheel
      }
    }
  }

  stdout().execute(LeaveAlternateScreen)?;
  disable_raw_mode()?;
  Ok(())
}

fn ui(f: &mut Frame, app: &mut App) {
  let size = f.size();
  let chunks = Layout::default()
    .direction(Direction::Vertical)
    .constraints([
      Constraint::Length(3),
      Constraint::Min(0),
      Constraint::Length(3),
    ])
    .split(size);

  let block = Block::default().black().black();
  f.render_widget(block, size);
  let titles = app
    .tabs
    .iter()
    .map(|t| {
      let str: String = t.into();
      Line::from(vec![str.to_owned().yellow()])
    })
    .collect();

  let tabs = Tabs::new(titles)
    .block(Block::default().borders(Borders::ALL).title(" Tabs "))
    .select(app.tabs.iter().position(|t| t == &app.active_tab).unwrap())
    .style(Style::default().white().on_black())
    .highlight_style(Style::default().bold().white().on_dark_gray());
  f.render_widget(tabs, chunks[0]);

  match app.active_tab {
    Tab::Disassembly => render_disassembly(f, app, chunks[1]),
    Tab::Headers => render_headers(f, app, chunks[1]),
  };

  let mut default_help = vec![];
  default_help.extend_from_slice(&helper_text("q".to_owned(), "Quit".to_owned()));
  default_help.push(" | ".yellow());
  default_help.extend_from_slice(&helper_text("tab".to_owned(), "Switch tabs".to_owned()));
  default_help.push(" | ".yellow());
  default_help.extend_from_slice(&helper_text("up/down".to_owned(), "Scroll".to_owned()));

  let help = Paragraph::new(Line::from(default_help))
    .block(
      Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White))
        .padding(Padding::new(1, 0, 0, 0)),
    )
    .white();

  f.render_widget(help, chunks[2]);
}

fn helper_text(key: String, text: String) -> Vec<Span<'static>> {
  vec!["<".white(), key.yellow(), "> ".white(), text.white()]
}

fn render_disassembly(f: &mut Frame, app: &mut App, section_size: Rect) {
  let top = app.data.text_section.data.get(app.data_scroll).unwrap();
  let split = Layout::default()
    .direction(Direction::Horizontal)
    .constraints([Constraint::Min(0), Constraint::Length(27)])
    .split(section_size);

  // TODO add search bar
  // let left_split = Layout::default()
  //   .direction(Direction::Vertical)
  //   .constraints([Constraint::Length(3), Constraint::Min(0)])
  //   .split(split[0]);

  let left_height = split[0].height;
  let left_lines = app
    .data
    .text_section
    .data
    .iter()
    .enumerate()
    .filter_map(|(i, l)| {
      if i < app.data_scroll {
        return None;
      }
      if i > app.data_scroll + left_height as usize {
        return None;
      }
      let real_index = i - app.data_scroll;
      let mut line_parts = vec![];
      if real_index == 0 {
        line_parts.push(format!("{:#8x}", l.offset).green().on_gray());
      } else {
        line_parts.push(format!("{:#8x}", l.offset).green());
      }
      line_parts.push("  ".to_owned().into());
      line_parts.push(l.instr.to_string().yellow());
      Some(Line::from(line_parts))
    })
    .collect::<Vec<Line>>();

  // Hex
  let right_height = split[1].height;
  let right_lines = app
    .data
    .text_section
    .bytes
    .iter()
    .enumerate()
    .filter_map(|(i, b)| {
      if i < top.offset {
        return None;
      }
      if i > top.offset + (right_height * 8) as usize {
        return None;
      }
      if i >= top.offset && i < top.offset + top.size {
        return Some(format!("{:02x}", b).blue().on_gray());
      }
      Some(format!("{:02x}", b).green())
    })
    .collect::<Vec<Span>>()
    .chunks(8)
    .map(|c| {
      // add spaces between each byte
      let c = c.to_vec();
      let mut new_c = Vec::with_capacity(16);
      for (i, b) in c.iter().enumerate() {
        new_c.push(b.clone());
        if i != 7 {
          new_c.push(" ".to_owned().into());
        }
      }
      Line::from(new_c)
    })
    .collect::<Vec<Line>>();

  // group by 8
  // right_spans.chunks()

  let right = Paragraph::new(right_lines)
    .block(
      Block::default()
        .title(" Hex ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White))
        .padding(Padding::new(1, 0, 0, 0)),
    )
    .white();

  let left = Paragraph::new(left_lines)
    .block(
      Block::default()
        .title(" .text ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White))
        .padding(Padding::new(1, 0, 0, 0)),
    )
    .white();

  f.render_widget(left, split[0]);
  f.render_widget(right, split[1]);
}

#[derive(Debug, Clone, Default)]
struct HeaderKeyValue {
  key: String,
  value: String,
}

fn util_hex<T: LowerHex>(value: &T) -> String {
  format!("{:#x}", value)
}

fn get_common_values(data: &CommonOptionalHeaderFields) -> Vec<HeaderKeyValue> {
  let mut common_lines: Vec<HeaderKeyValue> = Vec::new();

  common_lines.push(HeaderKeyValue {
    key: "Magic".to_owned(),
    value: util_hex(&data.magic),
  });

  common_lines.push(HeaderKeyValue {
    key: "major_linker_version".to_owned(),
    value: util_hex(&data.major_linker_version),
  });
  common_lines.push(HeaderKeyValue {
    key: "minor_linker_version".to_owned(),
    value: util_hex(&data.minor_linker_version),
  });
  common_lines.push(HeaderKeyValue {
    key: "size_of_code".to_owned(),
    value: util_hex(&data.size_of_code),
  });
  common_lines.push(HeaderKeyValue {
    key: "size_of_initialized_data".to_owned(),
    value: util_hex(&data.size_of_initialized_data),
  });
  common_lines.push(HeaderKeyValue {
    key: "size_of_uninitialized_data".to_owned(),
    value: util_hex(&data.size_of_uninitialized_data),
  });
  common_lines.push(HeaderKeyValue {
    key: "address_of_entry_point".to_owned(),
    value: util_hex(&data.address_of_entry_point),
  });
  common_lines.push(HeaderKeyValue {
    key: "base_of_code".to_owned(),
    value: util_hex(&data.base_of_code),
  });

  common_lines
}

fn render_headers(f: &mut Frame, app: &mut App, size: Rect) {
  let p = Paragraph::new(app.header_lines.clone())
    .scroll((app.header_scroll as u16, 0))
    .block(
      Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White))
        .padding(Padding::new(1, 0, 0, 0)),
    )
    .white()
    .wrap(Wrap { trim: false });

  f.render_widget(p, size);
}
