/// Hardcoded fixed key used to AES-256 encrypt/decrypt several types of data
pub const FIXED_KEY: &[u8] = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

/// Suffix appended to "flexible keys", which are keys derived from the fixed
/// key based key an array of byte indexes
pub const FLEXIBLE_KEY_SUFFIX: &[u8] = b"XXXXXXXXXXXXXXXX";
