//! Interactive flight deck (ratatui): sparklines, telemetry matrix, strategy
//! hotkeys, graceful termination.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Sparkline};

use crate::config::StrategyKind;
use crate::controller::ControlMsg;
use crate::telemetry::{Snapshot, Telemetry, Trend};

/// Drives the fullscreen TUI until quit/drain.
pub async fn run_tui(
    telemetry: Arc<Telemetry>,
    control: tokio::sync::mpsc::UnboundedSender<ControlMsg>,
    stop: watch::Receiver<bool>,
) {
    let mut stdout = std::io::stdout();
    let _ = crossterm::terminal::enable_raw_mode();
    let _ = crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::cursor::Hide
    );
    let backend = CrosstermBackend::new(std::io::stdout());
    let Ok(mut terminal) = Terminal::new(backend) else {
        restore();
        return;
    };

    let shutdown = stop.clone();
    loop {
        // Drain pending input (non-blocking-ish short poll).
        if crossterm::event::poll(Duration::from_millis(50)).unwrap_or(false) {
            while crossterm::event::poll(Duration::from_millis(1)).unwrap_or(false) {
                match crossterm::event::read() {
                    Ok(crossterm::event::Event::Key(k)) => {
                        if k.kind == crossterm::event::KeyEventKind::Press {
                            match k.code {
                                crossterm::event::KeyCode::Char('q' | 'Q') => {
                                    let _ = control.send(ControlMsg::Quit);
                                }
                                crossterm::event::KeyCode::Char('k' | 'K') => {
                                    let _ =
                                        control.send(ControlMsg::SetStrategy(StrategyKind::Knee));
                                }
                                crossterm::event::KeyCode::Char('b' | 'B') => {
                                    let _ = control
                                        .send(ControlMsg::SetStrategy(StrategyKind::Brownout));
                                }
                                crossterm::event::KeyCode::Char('p' | 'P') => {
                                    let _ =
                                        control.send(ControlMsg::SetStrategy(StrategyKind::Pulse));
                                }
                                crossterm::event::KeyCode::Char('e' | 'E') => {
                                    let _ = control.send(ControlMsg::ToggleEntropy);
                                }
                                crossterm::event::KeyCode::Char('+')
                                | crossterm::event::KeyCode::Down => {
                                    let _ = control.send(ControlMsg::AdjustRate(100.0));
                                }
                                crossterm::event::KeyCode::Char('-')
                                | crossterm::event::KeyCode::Up => {
                                    let _ = control.send(ControlMsg::AdjustRate(-100.0));
                                }
                                crossterm::event::KeyCode::Char('c')
                                    if k.modifiers
                                        .contains(crossterm::event::KeyModifiers::CONTROL) =>
                                {
                                    let _ = control.send(ControlMsg::Quit);
                                }
                                _ => {}
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {}
                }
            }
        }

        let snap = telemetry.snapshot();
        let _ = terminal.draw(|f| render(f, &snap));

        if *shutdown.borrow() {
            break;
        }
    }
    restore();
}

fn restore() {
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::cursor::Show
    );
}

fn render(f: &mut ratatui::Frame, snap: &Snapshot) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(4), // throughput
            Constraint::Length(6), // p99 sparkline
            Constraint::Length(5), // telemetry matrix
            Constraint::Length(4), // strategy
            Constraint::Min(0),
        ])
        .split(f.area());

    let secs = format!(
        "{:02}:{:02}:{:02}",
        snap.elapsed_s as u64 / 3600,
        (snap.elapsed_s as u64 % 3600) / 60,
        snap.elapsed_s as u64 % 60
    );
    let trend_label = match snap.trend {
        Trend::Stable => "STABLE",
        Trend::Degrading => "DEGRADING",
        Trend::Idle => "idle",
    };
    let trend_color = match snap.trend {
        Trend::Stable => Color::Green,
        Trend::Degrading => Color::Red,
        Trend::Idle => Color::DarkGray,
    };
    let header = Line::from(vec![
        Span::styled(
            format!(" DISPATCHED: {} ", snap.dispatched),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            format!(
                " | STATUS: {} ",
                if snap.running { "RUNNING" } else { "BEGIN" }
            ),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(
            format!(" | RUNTIME: {} ", secs),
            Style::default().fg(Color::White),
        ),
        Span::styled(
            format!(" | dLat/dt: {:.3} ({}) ", snap.dlat_rel, trend_label),
            Style::default().fg(trend_color),
        ),
    ]);
    f.render_widget(
        Paragraph::new(header).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        outer[0],
    );

    let tput = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[1]);
    let tgt_label = format!(
        "RPS target {:.0}  actual {:.0}",
        snap.target_rate, snap.actual_rps
    );
    let tgt_ratio = if snap.target_rate > 0.0 {
        (snap.actual_rps / snap.target_rate).clamp(0.0, 1.0)
    } else {
        0.0
    };
    f.render_widget(
        Gauge::default()
            .ratio(tgt_ratio)
            .label(tgt_label)
            .gauge_style(Style::default().fg(Color::Blue)),
        tput[0],
    );
    let err_label = format!(
        "errors {:.1}%  in-flight {}",
        snap.err_pct_window, snap.in_flight
    );
    let err_ratio = (snap.err_pct_window / 100.0).clamp(0.0, 1.0);
    f.render_widget(
        Gauge::default()
            .ratio(err_ratio)
            .label(err_label)
            .gauge_style(Style::default().fg(Color::Red)),
        tput[1],
    );

    // p99 sparkline over the retained ~24s history.
    let p99s: Vec<u64> = snap
        .history
        .iter()
        .map(|h| h.p99_ns / 1_000)
        .chain(std::iter::once(snap.p99_ns / 1_000))
        .collect();
    f.render_widget(
        Sparkline::default()
            .block(
                Block::default()
                    .title("p99 latency (µs)")
                    .borders(Borders::ALL),
            )
            .data(&p99s)
            .style(Style::default().fg(Color::Magenta)),
        outer[2],
    );

    let st = snap
        .statuses
        .iter()
        .take(6)
        .map(|(c, n, p)| format!("{c}: {n} ({p:.1}%)"))
        .collect::<Vec<_>>()
        .join("  |  ");
    let errs = snap
        .errors
        .iter()
        .take(6)
        .map(|(k, n)| format!("{k}: {n}"))
        .collect::<Vec<_>>()
        .join("  |  ");
    let matrix = Paragraph::new(vec![
        Line::from(format!(
            "p50 {:>9.2}ms   p90 {:>9.2}ms   p95 {:>9.2}ms   p99 {:>9.2}ms",
            snap.p50_ns as f64 / 1e6,
            snap.p90_ns as f64 / 1e6,
            snap.p95_ns as f64 / 1e6,
            snap.p99_ns as f64 / 1e6
        )),
        Line::from(if st.is_empty() {
            "(no responses yet)".to_string()
        } else {
            st
        }),
        Line::from(if errs.is_empty() {
            format!(
                "transport errors: none   scheduler lag p99 {:.2}ms",
                snap.scheduler_lag_p99_ns as f64 / 1e6
            )
        } else {
            errs
        }),
    ])
    .block(
        Block::default()
            .title("telemetry matrix")
            .borders(Borders::ALL),
    );
    f.render_widget(matrix, outer[3]);

    let strategy = Paragraph::new(vec![
        Line::from(format!("ACTIVE STRATEGY: [ {} ]", snap.strategy)),
        Line::styled(
            "HOTKEYS: [K] Knee   [B] Brownout   [P] Pulse   [E] Entropy   [+/-] rate   [Q] graceful drain",
            Style::default().add_modifier(Modifier::ITALIC),
        ),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(strategy, outer[4]);
}
