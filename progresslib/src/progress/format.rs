use std::{
    fmt,
    time::Duration,
};

use number_prefix::NumberPrefix;

/// Type to represent a file size in base 2 units.
#[derive(Debug)]
pub struct BinarySize(pub u64);

impl fmt::Display for BinarySize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match NumberPrefix::binary(self.0 as f64) {
            NumberPrefix::Standalone(number) => {
                write!(f, "{number:.0}B")
            }
            NumberPrefix::Prefixed(prefix, number) => {
                write!(f, "{number:.2}{prefix}B")
            }
        }
    }
}

const SECS_PER_MINUTE: u64 = 60;
const SECS_PER_HOUR: u64 = 60 * SECS_PER_MINUTE;
const SECS_PER_DAY: u64 = 24 * SECS_PER_HOUR;
const SECS_PER_YEAR: u64 = (365.25 * SECS_PER_DAY as f64) as u64;
const SECS_PER_MONTH: u64 = SECS_PER_YEAR / 12;

/// Type to represent a duration in human readable form.
#[derive(Debug)]
pub struct HumanDuration(pub Duration);

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        let nanos = u64::from(self.0.subsec_nanos());

        if secs == 0 && nanos == 0 {
            return if f.alternate() {
                f.write_str("0 seconds")
            } else {
                f.write_str("0s")
            };
        }

        let years = secs / SECS_PER_YEAR;
        let remain = secs % SECS_PER_YEAR;

        let months = remain / SECS_PER_MONTH;
        let remain = remain % SECS_PER_MONTH;

        let days = remain / SECS_PER_DAY;
        let remain = remain % SECS_PER_DAY;

        let hours = remain / SECS_PER_HOUR;
        let remain = remain % SECS_PER_HOUR;

        let minutes = remain / SECS_PER_MINUTE;
        let remain = remain % SECS_PER_MINUTE;

        let secs = remain;

        let millis = nanos / 1_000_000;
        let micros = nanos / 1_000 % 1_000;
        let nanos = nanos % 1_000;

        let mut first = true;

        for (value, full, abbrev) in &[
            (years, "year", "y"),
            (months, "month", "M"),
            (days, "day", "d"),
            (hours, "hour", "h"),
            (minutes, "minute", "m"),
            (secs, "second", "s"),
            (millis, "millisecond", "ms"),
            (micros, "microsecond", "us"),
            (nanos, "nanosecond", "ns"),
        ] {
            if *value > 0 {
                if first {
                    first = false;
                } else {
                    f.write_str(" ")?;
                }

                write!(f, "{value}")?;

                if f.alternate() {
                    write!(f, " {}{}", full, if *value > 1 { "s" } else { "" })?;
                } else {
                    f.write_str(abbrev)?;
                }
            }
        }

        Ok(())
    }
}

/// Type to represent a duration in a clock-like form.
#[derive(Debug)]
pub struct ClockDuration(pub Duration);

impl fmt::Display for ClockDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        let nanos = u64::from(self.0.subsec_nanos());

        let hours = secs / SECS_PER_HOUR;
        let remain = secs % SECS_PER_HOUR;

        let minutes = remain / SECS_PER_MINUTE;
        let remain = remain % SECS_PER_MINUTE;

        let secs = remain;

        write!(f, "{hours:02}:{minutes:02}:{secs:02}")?;

        if nanos > 0 || f.alternate() {
            write!(f, ".{nanos:09}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_size() {
        assert_eq!(BinarySize(0).to_string(), "0B");
        assert_eq!(BinarySize(1023).to_string(), "1023B");
        assert_eq!(BinarySize(1024).to_string(), "1.00KiB");
        assert_eq!(BinarySize(1536).to_string(), "1.50KiB");
        assert_eq!(BinarySize(1024 * 1024).to_string(), "1.00MiB");
        assert_eq!(BinarySize(1024 * 1024 * 1024).to_string(), "1.00GiB");
        assert_eq!(BinarySize(1024 * 1024 * 1024 * 1024).to_string(), "1.00TiB");
        assert_eq!(BinarySize(1024 * 1024 * 1024 * 1024 * 1024).to_string(), "1.00PiB");
        assert_eq!(BinarySize(1024 * 1024 * 1024 * 1024 * 1024 * 1024).to_string(), "1.00EiB");
    }

    #[test]
    fn test_human_duration() {
        // (secs, nanos, short, long)
        let test_cases = [
            (0, 0, "0s",
                "0 seconds"),
            (0, 1, "1ns",
                "1 nanosecond"),
            (0, 1_001, "1us 1ns",
                "1 microsecond 1 nanosecond"),
            (0, 1_001_001, "1ms 1us 1ns",
                "1 millisecond 1 microsecond 1 nanosecond"),
            (1, 1_001_001, "1s 1ms 1us 1ns",
                "1 second 1 millisecond 1 microsecond 1 nanosecond"),
            (61, 1_001_001, "1m 1s 1ms 1us 1ns",
                "1 minute 1 second 1 millisecond 1 microsecond 1 nanosecond"),
            (3661, 1_001_001, "1h 1m 1s 1ms 1us 1ns",
                "1 hour 1 minute 1 second 1 millisecond 1 microsecond 1 nanosecond"),
            (90061, 1_001_001, "1d 1h 1m 1s 1ms 1us 1ns",
                "1 day 1 hour 1 minute 1 second 1 millisecond 1 microsecond 1 nanosecond"),
            (2719861, 1_001_001, "1M 1d 1h 1m 1s 1ms 1us 1ns",
                "1 month 1 day 1 hour 1 minute 1 second 1 millisecond 1 microsecond 1 nanosecond"),
            (34277461, 1_001_001, "1y 1M 1d 1h 1m 1s 1ms 1us 1ns",
                "1 year 1 month 1 day 1 hour 1 minute 1 second 1 millisecond 1 microsecond 1 nanosecond"),
            (68554922, 2_002_002, "2y 2M 2d 2h 2m 2s 2ms 2us 2ns",
                "2 years 2 months 2 days 2 hours 2 minutes 2 seconds 2 milliseconds 2 microseconds 2 nanoseconds"),
        ];

        for &(secs, nanos, short, long) in test_cases.iter() {
            let d = HumanDuration(Duration::new(secs, nanos));
            assert_eq!(format!("{d}"), short);
            assert_eq!(format!("{d:#}"), long);
        }
    }

    #[test]
    fn test_clock_duration() {
        // (secs, nanos, short, long)
        let test_cases = [
            (0, 0, "00:00:00", "00:00:00.000000000"),
            (0, 1, "00:00:00.000000001", "00:00:00.000000001"),
            (0, 1_001, "00:00:00.000001001", "00:00:00.000001001"),
            (0, 1_001_001, "00:00:00.001001001", "00:00:00.001001001"),
            (1, 1_001_001, "00:00:01.001001001", "00:00:01.001001001"),
            (61, 1_001_001, "00:01:01.001001001", "00:01:01.001001001"),
            (3661, 1_001_001, "01:01:01.001001001", "01:01:01.001001001"),
            (u64::MAX, 999_999_999, "5124095576030431:00:15.999999999",
                "5124095576030431:00:15.999999999"),
        ];

        for &(secs, nanos, short, long) in test_cases.iter() {
            let d = ClockDuration(Duration::new(secs, nanos));
            assert_eq!(format!("{d}"), short);
            assert_eq!(format!("{d:#}"), long);
        }
    }
}
