use std::{
    fmt,
    str::FromStr,
};

use thiserror::Error;

/// A type representing the `<pda>/<csc>/<phone>/<data>` version string used by
/// the FUS protocol (eg. in the `DEVICE_FW_VERSION` field)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FwVersion {
    /// Primary firmware version (`DEVICE_PDA_CODE1_VERSION`)
    pub pda: String,
    /// Carrier services version (`DEVICE_CSC_CODE2_VERSION`)
    pub csc: String,
    /// [Unknown] `phone` version (`DEVICE_PHONE_FONT_VERSION`)
    pub phone: String,
    /// [Unknown] `data` version (`DEVICE_CONTENTS_DATA_VERSION`)
    pub data: String,
}

impl FwVersion {
    pub fn new(pda: &str, csc: &str, phone: Option<&str>, data: Option<&str>)
            -> Self {
        Self {
            pda: pda.to_owned(),
            csc: csc.to_owned(),
            phone: match phone {
                Some(s) => s.to_owned(),
                None => pda.to_owned(),
            },
            data: match data {
                Some(s) => s.to_owned(),
                None => pda.to_owned(),
            },
        }
    }
}

impl fmt::Display for FwVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}/{}", self.pda, self.csc, self.phone, self.data)
    }
}

impl FromStr for FwVersion {
    type Err = ParseFwVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pieces: Vec<&str> = s.split('/').collect();

        if pieces.len() < 2 {
            return Err(ParseFwVersionError::TooFewFields);
        } else if pieces.len() > 4 {
            return Err(ParseFwVersionError::TooManyFields);
        }

        fn none_if_empty(s: &str) -> Option<&str> {
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }

        Ok(Self::new(
            pieces[0],
            pieces[1],
            pieces.get(2).and_then(|s| none_if_empty(s)),
            pieces.get(3).and_then(|s| none_if_empty(s)),
        ))
    }
}

#[derive(Debug, Error)]
pub enum ParseFwVersionError {
    #[error("Too few fields (<2) in version string")]
    TooFewFields,
    #[error("Too many fields (>4) in version string")]
    TooManyFields,
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_display() {
        let version = FwVersion::new("a", "b", None, None);
        assert_eq!(version.to_string(), "a/b/a/a");

        let version = FwVersion::new("a", "b", Some("c"), None);
        assert_eq!(version.to_string(), "a/b/c/a");

        let version = FwVersion::new("a", "b", None, Some("d"));
        assert_eq!(version.to_string(), "a/b/a/d");

        let version = FwVersion::new("a", "b", Some("c"), Some("d"));
        assert_eq!(version.to_string(), "a/b/c/d");
    }

    #[test]
    fn test_parse() {
        let result: Result<FwVersion, _> = "a/b".parse();
        assert_matches!(result, Ok(x) if x == FwVersion::new("a", "b", None, None));

        let result: Result<FwVersion, _> = "a/b/c".parse();
        assert_matches!(result, Ok(x) if x == FwVersion::new("a", "b", Some("c"), None));

        let result: Result<FwVersion, _> = "a/b/c/d".parse();
        assert_matches!(result, Ok(x) if x == FwVersion::new("a", "b", Some("c"), Some("d")));

        let result: Result<FwVersion, _> = "a".parse();
        assert_matches!(result, Err(ParseFwVersionError::TooFewFields));

        let result: Result<FwVersion, _> = "a/b/c/d/e".parse();
        assert_matches!(result, Err(ParseFwVersionError::TooManyFields));
    }
}
