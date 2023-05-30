// Axel '0vercl0k' Souchet - May 28 2023
use std::num::ParseIntError;
use thiserror::Error;
use windows::core;

pub type Result<T> = std::result::Result<T, GflagsError>;

/// Error type used by the library.
#[derive(Error, Debug)]
pub enum GflagsError {
    // /// Failed to open the IFEO directory.
    // #[error("Failed to open IFEO key: {0}")]
    // FailedOpenIFEO(core::Error),
    /// Failed to enumerate through key names.
    #[error("Failed to enumerate key names of {1}: {0}")]
    FailedEnumKeyNames(core::Error, String),
    /// Failed to enumerate through value names.
    #[error("Failed to enumerate key values of {1}: {0}")]
    FailedEnumValueNames(core::Error, String),
    #[error("Failed to close key {1}: {0}")]
    FailedCloseKey(core::Error, String),
    #[error("Failed to delete key {1}: {0}")]
    FailedDeleteKey(core::Error, String),
    /// Failed to read a DWORD off a key.
    #[error("Failed to read DWORD {1}: {0}")]
    FailedReadDword(core::Error, String),
    /// Failed to write DWORD value.
    #[error("Failed to write DWORD {1} ({2}): {0}")]
    FailedWriteDword(core::Error, String, u32),
    /// Failed to read a string value.
    #[error("Failed to read string {1}: {0}")]
    FailedReadString(core::Error, String),
    /// Failed to write a string value.
    #[error("Failed to write string {1} ({2}): {0}")]
    FailedWriteString(core::Error, String, String),
    /// Failed to create a sub key.
    #[error("Failed to create sub key {1}: {0}")]
    FailedCreateSubKey(core::Error, String),
    /// Failed to open a sub key.
    #[error("Failed to open sub key {1}: {0}")]
    FailedOpenSubKey(core::Error, String),
    /// Failed to remove a key.
    #[error("Failed to remove key {1}: {0}")]
    FailedRemoveKey(core::Error, String),
    /// Failed to remove a value.
    #[error("Failed to remove value {1}: {0}")]
    FailedRemoveValue(core::Error, String),
    /// Failed to convert a hex string to a dword.
    #[error("Failed to convert hexstring {1}: {0}")]
    FailedHexConversion(ParseIntError, String),
}
