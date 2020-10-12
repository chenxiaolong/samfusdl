use std::{
    cmp,
    ops::Range,
};

pub fn split_range(
    range: Range<u64>,
    n: u64,
    min_chunk_size: Option<u64>
) -> Vec<Range<u64>> {
    debug_assert!(n > 0 && min_chunk_size != Some(0));

    let size = range.end - range.start;
    let chunk_size = cmp::max(min_chunk_size.unwrap_or(1), size / n);
    let n = cmp::min(n, size / chunk_size);
    let remainder = size - n * chunk_size;

    (0..n).map(|i| {
        let extra = if i == n - 1 { remainder } else { 0 };
        Range {
            start: range.start + i * chunk_size,
            end: range.start + (i + 1) * chunk_size + extra,
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_range() {
        // Empty range should not be split into anything
        assert_eq!(split_range(0..0, 1, None), &[]);
        assert_eq!(split_range(1..1, 2, None), &[]);

        // Even splits (or close enough given integer division)
        assert_eq!(split_range(0..5, 1, None), &[0..5]);
        assert_eq!(split_range(0..5, 2, None), &[0..2, 2..5]);
        assert_eq!(split_range(0..5, 3, None), &[0..1, 1..2, 2..5]);
        assert_eq!(split_range(0..5, 4, None), &[0..1, 1..2, 2..3, 3..5]);
        assert_eq!(split_range(0..5, 5, None), &[0..1, 1..2, 2..3, 3..4, 4..5]);
        assert_eq!(split_range(0..5, 6, None), &[0..1, 1..2, 2..3, 3..4, 4..5]);

        // Minimum chunk size
        assert_eq!(split_range(0..10, 1, Some(3)), &[0..10]);
        assert_eq!(split_range(0..10, 2, Some(3)), &[0..5, 5..10]);
        assert_eq!(split_range(0..10, 3, Some(3)), &[0..3, 3..6, 6..10]);
        assert_eq!(split_range(0..10, 4, Some(3)), &[0..3, 3..6, 6..10]);
        assert_eq!(split_range(0..10, 5, Some(3)), &[0..3, 3..6, 6..10]);
        assert_eq!(split_range(0..10, 6, Some(3)), &[0..3, 3..6, 6..10]);
        assert_eq!(split_range(0..10, 7, Some(3)), &[0..3, 3..6, 6..10]);
        assert_eq!(split_range(0..10, 8, Some(3)), &[0..3, 3..6, 6..10]);
        assert_eq!(split_range(0..10, 9, Some(3)), &[0..3, 3..6, 6..10]);
        assert_eq!(split_range(0..10, 10, Some(3)), &[0..3, 3..6, 6..10]);
        assert_eq!(split_range(0..10, 11, Some(3)), &[0..3, 3..6, 6..10]);

        // Non-zero starting point
        assert_eq!(split_range(1000..2000, 2, None), &[1000..1500, 1500..2000]);
    }
}