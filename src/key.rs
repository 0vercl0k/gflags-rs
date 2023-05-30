// Axel '0vercl0k' Souchet - May 25 2023
//! XXX
use crate::error::{GflagsError, Result};
use crate::utils;
use std::ffi::CString;
use std::str;
use windows::core::PCSTR;
use windows::Win32::Foundation::*;
use windows::Win32::System::Registry::*;

/// A `Key` is used to read and walk through the Windows registry using the native Win32 APIs.
#[derive(Debug)]
pub struct Key {
    path: String,
    handle: HKEY,
}

/// A trait to make it easier to go from `CString` to `PCSTR` which is used by the Win32 APIs.
trait ToPCSTR {
    fn to_pcstr(&self) -> PCSTR;
}

impl ToPCSTR for CString {
    fn to_pcstr(&self) -> PCSTR {
        PCSTR::from_raw(self.as_ptr().cast())
    }
}

impl Key {
    /// Opens a registry key with read access.
    pub fn open(key: HKEY, path: &str) -> Result<Self> {
        Self::open_with_rights(key, path, KEY_READ)
    }

    /// Opens a registry key with arbitrary `rights`.
    pub fn open_with_rights(key: HKEY, path: &str, rights: REG_SAM_FLAGS) -> Result<Self> {
        // Open a handle to the key w/ as much access as we can READ_ACCESS; if we encounter an access denied later, we'll try to promote our handle w/ KEY_WRITE rights.
        let mut handle = HKEY::default();
        let cstr = CString::new(path).expect("NULL character found in CString");
        let status = unsafe { RegOpenKeyExA(key, cstr.to_pcstr(), 0, rights, &mut handle) };

        // Make sure the call was a success.
        status
            .ok()
            .map_err(|err| GflagsError::FailedOpenSubKey(err, path.to_string()))?;

        // Rollin'.
        Ok(Self {
            path: path.to_string(),
            handle,
        })
    }

    /// Creates or opens a registry key with read access.
    pub fn new(key: HKEY, path: &str) -> Result<Self> {
        let mut handle = HKEY::default();
        let cstr = CString::new(path).expect("NULL character found in CString");
        let status = unsafe { RegCreateKeyA(key, cstr.to_pcstr(), &mut handle) };

        // Make sure the call was a success.
        status
            .ok()
            .map_err(|err| GflagsError::FailedCreateSubKey(err, path.to_string()))?;

        // Rollin'.
        Ok(Self {
            path: path.to_string(),
            handle,
        })
    }

    /// Opens a sub key with read access.
    pub fn open_subkey(&self, path: &str) -> Result<Key> {
        Key::open_with_rights(self.handle, path, KEY_READ)
    }

    /// Opens a sub key with read/write accesses.
    pub fn open_subkey_rw(&self, path: &str) -> Result<Key> {
        Key::open_with_rights(self.handle, path, KEY_READ | KEY_WRITE)
    }

    /// Creates or opens a sub key.
    pub fn create_subkey(&self, path: &str) -> Result<Key> {
        Key::new(self.handle, path)
    }

    /// Returns an iterator that walks through the key names.
    pub fn iter_key_names(&self) -> KeyIterator {
        KeyIterator::new(self, KeyIteratorKind::KeyName)
    }

    /// Returns an iterator that walks through the value names.
    pub fn iter_value_names(&self) -> KeyIterator {
        KeyIterator::new(self, KeyIteratorKind::ValueName)
    }

    /// Reads a zero terminated string assuming it is stored as a SZ.
    pub fn read_string(&self, value_name: &str) -> Result<String> {
        let cstr = CString::new(value_name).expect("NULL character found in CString");
        let mut buffer = [0u8; 128];
        let mut buffer_len = buffer.len() as u32;
        let status = unsafe {
            RegGetValueA(
                self.handle,
                None,
                cstr.to_pcstr(),
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut buffer_len as _),
            )
        };

        // Ensure things went well!
        status
            .ok()
            .map_err(|err| GflagsError::FailedReadString(err, value_name.to_string()))?;

        // Ensure the buffer has at least a character and a null byte.
        if buffer_len == 1 {
            panic!("RegGetValueA returned a buffer of size 1\n");
        }

        // Calculate the size w/o the ending null character.
        let buffer_len = (buffer_len - 1) as usize;
        Ok(str::from_utf8(&buffer[..buffer_len])
            .expect("Non UTF8 characters found in the registry")
            .to_string())
    }

    /// Reads a value assuming it is stored as a DWORD.
    pub fn read_dword(&self, value_name: &str) -> Result<u32> {
        let cstr = CString::new(value_name).expect("NULL character found in CString");
        let mut buffer = [0u8; 4];
        let mut buffer_len = buffer.len() as u32;
        let status = unsafe {
            RegGetValueA(
                self.handle,
                None,
                cstr.to_pcstr(),
                RRF_RT_REG_DWORD,
                None,
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut buffer_len as _),
            )
        };

        match status {
            // Woot!
            NO_ERROR => Ok(u32::from_le_bytes(buffer)),
            // Try to read the value as a string instead as I've seen
            // MSFT's gflags.exe writing the configuration values as a
            // string like "0x1337".
            ERROR_UNSUPPORTED_TYPE => {
                let hexstring = self.read_string(value_name)?;
                Ok(utils::hexstring_to_dword(&hexstring)?)
            }
            _ => Err(GflagsError::FailedReadDword(
                status.into(),
                value_name.to_string(),
            )),
        }
    }

    /// Writes a DWORD value.
    pub fn write_dword(&self, value_name: &str, value: u32) -> Result<()> {
        let cstr = CString::new(value_name).expect("NULL character found in CString");
        let status = unsafe {
            RegSetValueExA(
                self.handle,
                cstr.to_pcstr(),
                0,
                REG_DWORD,
                Some(&value.to_le_bytes()),
            )
        };

        // Ensure things went well.
        status
            .ok()
            .map_err(|err| GflagsError::FailedWriteDword(err, value_name.to_string(), value))
    }

    /// Writes a zero terminated string.
    pub fn write_string(&self, value_name: &str, value: &str) -> Result<()> {
        let value_name_cstr = CString::new(value_name).expect("NULL character found in CString");
        let status = unsafe {
            RegSetValueExA(
                self.handle,
                value_name_cstr.to_pcstr(),
                0,
                REG_SZ,
                Some(value.as_bytes()),
            )
        };

        // Ensure things went well.
        status.ok().map_err(|err| {
            GflagsError::FailedWriteString(err, value_name.to_string(), value.to_string())
        })
    }

    /// Removes a value.
    pub fn remove_value(&self, value_name: &str) -> Result<()> {
        let cstr = CString::new(value_name).expect("NULL character found in CString");
        let status = unsafe { RegDeleteKeyValueA(self.handle, None, cstr.to_pcstr()) };

        // Ensure things went well.
        status
            .ok()
            .map_err(|err| GflagsError::FailedRemoveValue(err, value_name.to_string()))
    }

    /// Removes the key.
    pub fn remove(self) -> Result<()> {
        let cstr = CString::new("").unwrap();
        let status = unsafe { RegDeleteKeyExA(self.handle, cstr.to_pcstr(), KEY_WOW64_64KEY.0, 0) };

        // Ensure things went well.
        status
            .ok()
            .map_err(|err| GflagsError::FailedDeleteKey(err, self.path.clone()))
    }
}

/// Don't leak handles!
impl Drop for Key {
    fn drop(&mut self) {
        let status = unsafe { RegCloseKey(self.handle) };
        if let Err(err) = status.ok() {
            panic!("Closing registry key failed w/ {err}");
        }
    }
}

/// Pick if we are iterating over value names or key names.
enum KeyIteratorKind {
    ValueName,
    KeyName,
}

/// Iterator that calls either `RegEnumKeyExA` or `RegEnumValueA` until hitting `ERROR_NO_MORE_ITEMS`.
pub struct KeyIterator<'k> {
    key: &'k Key,
    idx: Option<u32>,
    kind: KeyIteratorKind,
}

impl<'k> KeyIterator<'k> {
    /// Build an iterator over key or value names.
    fn new(key: &'k Key, kind: KeyIteratorKind) -> Self {
        Self {
            key,
            idx: Some(0),
            kind,
        }
    }
}

impl Iterator for KeyIterator<'_> {
    type Item = Result<String>;
    /// Walk the registry until there's no item left.
    fn next(&mut self) -> Option<Self::Item> {
        // If we have no index it means that the iterator has been exhausted already.
        let idx = self.idx?;

        // Prepare a temporary buffer to call `RegEnumKeyExA`.
        let mut buffer = [0u8; 256];
        let mut buffer_len = buffer.len() as u32;
        let status = unsafe {
            match self.kind {
                KeyIteratorKind::KeyName => RegEnumKeyExA(
                    self.key.handle,
                    idx,
                    windows::core::PSTR(buffer.as_mut_ptr()),
                    &mut buffer_len,
                    None,
                    windows::core::PSTR::null(),
                    None,
                    None,
                ),
                KeyIteratorKind::ValueName => RegEnumValueA(
                    self.key.handle,
                    idx,
                    windows::core::PSTR(buffer.as_mut_ptr()),
                    &mut buffer_len,
                    None,
                    None,
                    None,
                    None,
                ),
            }
        };

        // Assume everything went fine and bump the index.
        self.idx = Some(idx + 1);

        match status {
            // If it is a success, great nothing to do!
            NO_ERROR => {}
            // If we're done with this iterator, turn the index into None.
            ERROR_NO_MORE_ITEMS => {
                self.idx.take();
                return None;
            }
            // If we encounter any other error, let's stop here.
            _ =>
            // XXX:
            {
                return Some(Err(GflagsError::FailedEnumKeyNames(
                    status.into(),
                    self.key.path.clone(),
                )))
            }
        };

        // Calculate the size of the final buffer.
        let buffer_len = buffer_len as usize;

        // Create the final string off the temporary buffer.
        let final_string_ref = str::from_utf8(&buffer[..buffer_len])
            .expect("Non UTF8 characters found in the registry");

        Some(Ok(final_string_ref.to_string()))
    }
}
