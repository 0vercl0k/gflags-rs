// Axel '0vercl0k' Souchet - May 25 2023
use crate::error::{GflagsError, Result};

/// Returns a dword from an hex string.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(hexstring_to_dword("0x1337"), 0x1337u32);
/// assert_eq!(hexstring_to_dword("1337"), 0x1337u32);
/// ```
pub fn hexstring_to_dword(s: &str) -> Result<u32> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(stripped, 16)
        .map_err(|err| GflagsError::FailedHexConversion(err, s.to_string()))
}
