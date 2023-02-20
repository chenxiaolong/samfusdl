mod format;

use format::{BinarySize, ClockDuration, HumanDuration};

use std::{
    collections::VecDeque,
    io::Write,
    time::{Duration, Instant},
};

use crossterm::{
    cursor::{Hide, MoveToColumn, Show},
    QueueableCommand,
    Result,
    style::{Print, Stylize},
    terminal::{self, Clear, ClearType},
    tty::IsTty,
};

/// Type that receives progress values and buffers them to compute the average
/// progress progression speed over the specified period of time.
#[derive(Debug)]
pub struct ProgressSpeed {
    /// Period of time to accumulate records.
    duration: Duration,
    /// Buffer containing progress records over the specified period of time.
    buf: VecDeque<(Instant, u64)>,
}

impl ProgressSpeed {
    pub fn new(duration: Duration) -> Self {
        Self {
            duration,
            buf: VecDeque::new(),
        }
    }

    /// Clear all recorded values.
    pub fn reset(&mut self) {
        self.buf.clear();
    }

    /// Record progress value to be used for the speed calculation.
    pub fn record_value(&mut self, value: u64) {
        let now = Instant::now();
        self.buf.push_back((now, value));

        // Only keep enough records to represent self.duration amount of time
        let end = self.buf
            .iter()
            .position(|x| now - x.0 < self.duration)
            .and_then(|x| x.checked_sub(1));
        if let Some(v) = end {
            self.buf.drain(0..v);
        }
    }

    /// Get progress speed as the number of progress units per second.
    pub fn units_per_sec(&self) -> f64 {
        if let (Some(f), Some(b)) = (self.buf.front(), self.buf.back()) {
            if f != b {
                return (b.1 - f.1) as f64 / (b.0 - f.0).as_secs_f64();
            }
        }

        0.0
    }
}

/// Progress bar for showing progress in bytes. The elapsed time, current
/// progress, current percentage, (moving) average speed, and ETA are displayed.
/// The rendering FPS is also configurable.
pub struct ProgressBar<T: Write + IsTty> {
    /// Maximum value
    len: u64,
    /// Current value
    pos: u64,
    /// Output terminal
    term: T,
    /// Output mode
    mode: ProgressDrawMode,
    /// (Maximum) frames per second for rendering
    fps: f64,
    /// Time of last draw
    last_draw: Instant,
    /// Timestamp of when the progress bar started
    started: Instant,
    /// Speed calculator
    speed: ProgressSpeed,
}

/// How the progress bar should be drawn
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressDrawMode {
    /// Draw to the terminal. The same line is overwritten with the new progress
    /// during each rendering frame. This mode is useful when the terminal is
    /// interactive. The default rendering frame rate in this mode is 15 fps.
    Interactive,
    /// Draw to the terminal. A new line is appended with the new progress
    /// during each rendering frame. This mode is useful when the terminal is
    /// not interactive or output is being redirected to a file. The default
    /// rendering frame rate in this mode is 0.2 fps.
    Append,
    /// Do not draw to the terminal.
    None,
}

impl ProgressDrawMode {
    fn default_fps(self) -> f64 {
        match self {
            Self::Interactive => 15.0,
            Self::Append => 0.2,
            Self::None => 0.0,
        }
    }
}

impl<T: Write + IsTty> ProgressBar<T> {
    /// Construct a new progress bar. By default, every update is rendered
    /// immediately. Call `set_fps` to reduce the rendering rate.
    pub fn new(term: T, len: u64) -> Self {
        let mode = if term.is_tty() {
            ProgressDrawMode::Interactive
        } else {
            ProgressDrawMode::Append
        };
        let now = Instant::now();

        Self {
            len,
            pos: 0,
            term,
            mode,
            fps: mode.default_fps(),
            last_draw: now,
            started: now,
            speed: ProgressSpeed::new(Duration::from_secs(10)),
        }
    }

    /// Get the current draw mode.
    pub fn mode(&self) -> ProgressDrawMode {
        self.mode
    }

    /// Set the draw mode. It the mode is set to [`None`], then the function
    /// will automatically pick [`Interactive`] or [`Append`] depending on if
    /// the terminal is interactive. This will reset the output fps to the
    /// default for the draw mode.
    pub fn set_mode(&mut self, mode: Option<ProgressDrawMode>) {
        self.mode = match mode {
            Some(m) => m,
            None => if self.term.is_tty() {
                ProgressDrawMode::Interactive
            } else {
                ProgressDrawMode::Append
            }
        };
        self.fps = self.mode.default_fps();
    }

    pub fn fps(&self) -> f64 {
        self.fps
    }

    /// Set maximum rendering frequency in frames per second.
    pub fn set_fps(&mut self, fps: f64) {
        self.fps = fps;
    }

    /// Get the maximum value of the progress bar.
    pub fn length(&self) -> u64 {
        self.len
    }

    /// Set the maximum value of the progress bar. This performs an immediate
    /// redraw.
    pub fn set_length(&mut self, len: u64) -> Result<()> {
        self.len = len;
        self.draw(true)
    }

    /// Get the current value of the progress bar.
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// Set the current value of the progress bar. This performs an immediate
    /// redraw.
    pub fn set_position(&mut self, pos: u64) -> Result<()> {
        self.pos = pos;
        self.speed.record_value(self.pos);
        self.draw(true)
    }

    /// Advances the current position of the progress bar by the specified
    /// amount. This performs a redraw, subject to the output rate limiting.
    pub fn advance(&mut self, delta: u64) -> Result<()> {
        self.pos = self.pos.saturating_add(delta);
        self.speed.record_value(self.pos);
        self.draw(false)
    }

    /// Print a line to the progress bar's terminal without clobbering the
    /// progress bar itself.
    pub fn println<I: Into<String>>(&mut self, msg: I) -> Result<()> {
        if self.mode != ProgressDrawMode::None {
            if self.mode == ProgressDrawMode::Interactive {
                self.term
                    .queue(Clear(ClearType::CurrentLine))?
                    .queue(MoveToColumn(0))?;
            }

            self.term
                .queue(Print(msg.into()))?
                .queue(Print('\n'))?;

            if self.mode == ProgressDrawMode::Interactive {
                self.draw(true)?;
            }
        }
        Ok(())
    }

    /// Draw the final frame and clear the progress bar from the terminal.
    /// The progress bar will reappear if the progress bar state changes again.
    /// This is automatically called when the progress bar is dropped.
    pub fn finish(&mut self) -> Result<()> {
        match self.mode {
            ProgressDrawMode::Interactive => {
                self.term
                    .queue(Clear(ClearType::CurrentLine))?
                    .queue(MoveToColumn(0))?
                    .queue(Show)?
                    .flush()?;
            }
            ProgressDrawMode::Append => self.draw(true)?,
            ProgressDrawMode::None => {}
        }
        Ok(())
    }

    /// If the output mode is interactive, print a newline to the terminal
    /// causing the current progress bar state to be kept on-screen on the
    /// previous line. Further progress bar state changes will appear on the
    /// last line as usual.
    pub fn keep(&mut self) -> Result<()> {
        if self.mode == ProgressDrawMode::Interactive {
            self.term
                .queue(Print('\n'))?
                .flush()?;
        }
        Ok(())
    }

    /// Reset the progress bar, including the elapsed time, the ETA, and the
    /// current position. This performs an immediate redraw.
    pub fn reset(&mut self) -> Result<()> {
        self.pos = 0;
        self.started = Instant::now();
        self.speed.reset();
        self.draw(true)
    }

    /// Draw the progress bar. This is normally done by setting the position or
    /// the length. If `force` is true, then the draw will always occur.
    /// Otherwise, the rendering is subject to the rate limit of the progress
    /// bar.
    pub fn draw(&mut self, force: bool) -> Result<()> {
        if !force && self.fps > 0.0 {
            let frame_dur = Duration::from_secs_f64(1.0 / self.fps);
            if self.last_draw != self.started && self.last_draw.elapsed() < frame_dur {
                return Ok(());
            }
        }

        if self.mode == ProgressDrawMode::None {
            return Ok(());
        }

        let elapsed = Duration::from_secs(self.started.elapsed().as_secs());
        let eta = Duration::from_secs(self.eta().as_secs());
        let ratio = (self.pos as f64 / self.len as f64).clamp(0.0, 1.0);

        let mut result = format!(
            "[{elapsed}] {bar_placeholder}{percent:.0}% {pos}/{len} ({speed}/s, {eta})",
            elapsed = ClockDuration(elapsed),
            bar_placeholder = if self.mode == ProgressDrawMode::Interactive {
                "\x00"
            } else {
                ""
            },
            percent = ratio * 100.0,
            pos = BinarySize(self.pos),
            len = BinarySize(self.len),
            speed = BinarySize(self.speed()),
            eta = HumanDuration(eta),
        );

        if self.mode == ProgressDrawMode::Interactive {
            let term_width = terminal::size().unwrap_or((80, 24)).0 as usize;
            // result.len() includes the placeholder (+1), which works because
            // there is a space after the bar.
            let bar_width = term_width.saturating_sub(result.len());
            let bar_consumed = (ratio * bar_width as f64).round() as usize;
            let bar_remaining = bar_width.saturating_sub(bar_consumed);

            if bar_width != 0 {
                result = result.replace('\x00', &format!(
                    "{}{} ",
                    "#".repeat(bar_consumed).cyan(),
                    "-".repeat(bar_remaining).blue(),
                ));
            }

            self.term
                .queue(Hide)?
                .queue(Clear(ClearType::CurrentLine))?
                .queue(MoveToColumn(0))?;
        } else {
            result.push('\n');
        };

        self.term
            .queue(Print(result))?
            .flush()?;

        self.last_draw = Instant::now();

        Ok(())
    }

    /// Compute the expected ETA over a 10 second window.
    fn eta(&self) -> Duration {
        let s = self.speed.units_per_sec();
        if s > 0.0 {
            Duration::from_secs_f64((self.len.saturating_sub(self.pos)) as f64 / s)
        } else {
            Duration::new(0, 0)
        }
    }

    /// Compute the progress speed as progress units per second over a 10 second
    /// window.
    fn speed(&self) -> u64 {
        self.speed.units_per_sec() as u64
    }
}

impl<T: Write + IsTty> Drop for ProgressBar<T> {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Error, ErrorKind},
        rc::Rc,
        str,
        sync::Mutex,
    };

    use super::*;

    struct TestTerm {
        buf: Rc<Mutex<String>>,
        tty: bool,
    }

    impl TestTerm {
        fn new(tty: bool) -> Self {
            Self {
                buf: Rc::new(Mutex::new(String::new())),
                tty,
            }
        }
    }

    impl Write for TestTerm {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let s = str::from_utf8(buf)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
            self.buf.lock().unwrap().push_str(s);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl IsTty for TestTerm {
        fn is_tty(&self) -> bool {
            self.tty
        }
    }

    impl IsTty for &mut TestTerm {
        fn is_tty(&self) -> bool {
            self.tty
        }
    }

    #[test]
    fn test_non_output_components() {
        let mut term = TestTerm::new(false);
        let buf = term.buf.clone();
        let mut bar = ProgressBar::new(&mut term, 10);

        bar.set_mode(Some(ProgressDrawMode::None));
        assert_eq!(bar.mode(), ProgressDrawMode::None);

        assert_eq!(bar.fps(), 0.0);
        bar.set_fps(1.0);
        assert_eq!(bar.fps(), 1.0);

        assert_eq!(bar.position(), 0);
        bar.set_position(5).unwrap();
        assert_eq!(bar.position(), 5);

        assert_eq!(bar.length(), 10);
        bar.set_length(15).unwrap();
        assert_eq!(bar.length(), 15);

        bar.println("hello").unwrap();

        drop(bar);

        assert_eq!(*buf.lock().unwrap(), "");
    }

    #[test]
    fn test_non_tty() {
        let mut term = TestTerm::new(false);
        let buf = term.buf.clone();
        let mut bar = ProgressBar::new(&mut term, 10);

        assert_eq!(bar.mode(), ProgressDrawMode::Append);
        assert_eq!(bar.fps(), 0.2);
        assert_eq!(bar.position(), 0);
        assert_eq!(bar.length(), 10);

        bar.set_fps(0.0);
        assert_eq!(*buf.lock().unwrap(), "");

        bar.advance(1).unwrap();
        assert_eq!(bar.position(), 1);
        {
            let mut output = buf.lock().unwrap();
            let pieces: Vec<&str> = output.split(' ').collect();
            assert_eq!(pieces[1], "10%");
            assert_eq!(pieces[2], "1B/10B");
            output.clear();
        }

        bar.set_position(10).unwrap();
        assert_eq!(bar.position(), 10);
        {
            let mut output = buf.lock().unwrap();
            let pieces: Vec<&str> = output.split(' ').collect();
            assert_eq!(pieces[1], "100%");
            assert_eq!(pieces[2], "10B/10B");
            output.clear();
        }

        bar.keep().unwrap();
        assert_eq!(buf.lock().unwrap().len(), 0);

        bar.println("hello").unwrap();
        {
            let mut output = buf.lock().unwrap();
            assert_eq!(*output, "hello\n");
            output.clear();
        }

        bar.reset().unwrap();
        {
            let mut output = buf.lock().unwrap();
            let pieces: Vec<&str> = output.split(' ').collect();
            assert_eq!(pieces[1], "0%");
            assert_eq!(pieces[2], "0B/10B");
            output.clear();
        }

        drop(bar);
    }

    #[test]
    fn test_tty() {
        let mut term = TestTerm::new(true);
        let buf = term.buf.clone();
        let mut bar = ProgressBar::new(&mut term, 10);

        assert_eq!(bar.mode(), ProgressDrawMode::Interactive);
        assert_eq!(bar.fps(), 15.0);
        assert_eq!(bar.position(), 0);
        assert_eq!(bar.length(), 10);

        bar.set_fps(0.0);
        assert_eq!(*buf.lock().unwrap(), "");

        bar.advance(1).unwrap();
        assert_eq!(bar.position(), 1);
        {
            let mut output = buf.lock().unwrap();
            let pieces: Vec<&str> = output.split(' ').collect();
            assert!(pieces[1].starts_with("\u{1b}"));
            assert_eq!(pieces[2], "10%");
            assert_eq!(pieces[3], "1B/10B");
            output.clear();
        }

        bar.set_position(10).unwrap();
        assert_eq!(bar.position(), 10);
        {
            let mut output = buf.lock().unwrap();
            let pieces: Vec<&str> = output.split(' ').collect();
            assert!(pieces[1].starts_with("\u{1b}"));
            assert_eq!(pieces[2], "100%");
            assert_eq!(pieces[3], "10B/10B");
            output.clear();
        }

        bar.keep().unwrap();
        {
            let mut output = buf.lock().unwrap();
            assert_eq!(output.bytes().last().unwrap(), b'\n');
            output.clear();
        }

        bar.println("hello").unwrap();
        {
            let mut output = buf.lock().unwrap();
            let lines: Vec<&str> = output.lines().collect();
            assert!(lines[0].ends_with("hello"));
            let pieces: Vec<&str> = lines[1].split(' ').collect();
            assert!(pieces[1].starts_with("\u{1b}"));
            assert_eq!(pieces[2], "100%");
            assert_eq!(pieces[3], "10B/10B");
            output.clear();
        }

        bar.reset().unwrap();
        {
            let mut output = buf.lock().unwrap();
            let pieces: Vec<&str> = output.split(' ').collect();
            assert!(pieces[1].starts_with("\u{1b}"));
            assert_eq!(pieces[2], "0%");
            assert_eq!(pieces[3], "0B/10B");
            output.clear();
        }

        drop(bar);
    }
}
