use crate::parser::PEFile;
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
}

impl App {
  fn new(data: PEFile) -> Self {
    Self {
      tabs: vec![Tab::Disassembly, Tab::Headers],
      active_tab: Tab::Disassembly,
      data,
      data_scroll: 0,
      header_scroll: 0,
    }
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
    if self.data_scroll < self.data.text_section.data.len() {
      self.data_scroll += 1;
    }
  }

  fn scroll_up(&mut self) {
    if self.data_scroll > 0 {
      self.data_scroll -= 1;
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

    // 60 fps
    if event::poll(std::time::Duration::from_millis(16))? {
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

        if app.active_tab == Tab::Disassembly {
          // on up/down arrow keys, scroll the disassembly
          if key.kind == KeyEventKind::Press && key.code == KeyCode::Up {
            app.scroll_up();
          }
          if key.kind == KeyEventKind::Press && key.code == KeyCode::Down {
            app.scroll_down();
          }
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

  // help section
  let default_help = vec![
    "Press q to exit".white(),
    " | ".yellow(),
    "Press tab to switch tabs".white(),
    " | ".yellow(),
    "Press up/down arrow keys or scroll wheel to scroll".white(),
  ];

  let help = Paragraph::new(Line::from(default_help))
    .block(
      Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White)),
    )
    .white();

  f.render_widget(help, chunks[2]);
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

fn render_headers(f: &mut Frame, app: &mut App, size: Rect) {
  let mut text = String::new();

  for _ in 0..1000 {
    text.push_str("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec eget odio eu ");
  }

  let p = Paragraph::new(text)
    .scroll((1, 0))
    .block(
      Block::default()
        .title(" .text ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White))
        .padding(Padding::new(1, 0, 0, 0)),
    )
    .white()
    .wrap(Wrap { trim: true });

  f.render_widget(p, size);
}
