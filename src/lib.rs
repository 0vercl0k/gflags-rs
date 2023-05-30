// Axel '0vercl0k' Souchet - May 25 2023
//! `Gflags` is a toy project that I have used to learn Rust; it basically allows you to interact with Windows' Global Flags (PageHeap, Debugger, etc.).
mod error;
mod key;
mod utils;

pub use error::{GflagsError, Result};
use key::Key;
use std::str;
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

/// IFEO path.
const IFEO_PATH: &str =
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
const GLOBAL_FLAG_KEY_NAME: &str = "GlobalFlag";
const PAGE_HEAP_FLAGS_KEY_NAME: &str = "PageHeapFlag";
const DEBUGGER_KEY_NAME: &str = "Debugger";

/// https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-flag-table?source=recommendations
const FLG_HEAP_PAGE_ALLOCS: u32 = 0x02_00_00_00_u32;

/// Various configuration of PageHeap we care about.
pub mod page_heap_kind {
    // Writes fill patterns at the end of each allocation
    // and checks the patterns when freed.
    pub const STANDARD: u32 = 0;
    // The above but also adds a guard page at the end of allocations.
    pub const FULL: u32 = 1;
    // Grabs stack traces on allocation and free.
    pub const WITH_TRACES: u32 = 2;
}

/// Get a handle to the IFEO directory which is where PageHeap/GlobalFlag settings are stored in.
pub struct Gflags {
    key: Key,
}

impl Gflags {
    /// Create a `Gflags` instance.
    pub fn new() -> Result<Self> {
        let key = Key::open(HKEY_LOCAL_MACHINE, IFEO_PATH)?;
        Ok(Self { key })
    }

    /// Returns a list of every processes that turns on PageHeap.
    pub fn list_pageheap(&self) -> Result<Vec<String>> {
        // Walk through the children key names.
        let mut names = Vec::new();
        for subkey_name in self.key.iter_key_names() {
            let subkey_name = subkey_name?;

            // Open the subkey to walk the value names.
            let subkey = match self.key.open_subkey(&subkey_name) {
                Err(err) => {
                    println!("Failed to open {subkey_name}: '{err}', skipping");
                    continue;
                }
                Ok(key) => key,
            };

            // Check if the key has the two values needed to turn on PageHeap.
            let global_flags = match subkey.read_dword(GLOBAL_FLAG_KEY_NAME) {
                Err(GflagsError::FailedReadDword(err, _))
                    if err.code().0 as u32 == 0x80_07_00_02 =>
                {
                    continue;
                }
                v => v,
            }?;

            // Do we have a hit?
            if (global_flags & FLG_HEAP_PAGE_ALLOCS) != 0 {
                names.push(subkey_name);
            }
        }

        Ok(names)
    }

    /// Turns on PageHeap for `name`.
    pub fn add_pageheap(&self, name: &str) -> Result<bool> {
        self.add_pageheap_with_kind(name, page_heap_kind::FULL | page_heap_kind::WITH_TRACES)
    }

    /// Turns on PageHeap for `name` with a `kind`.
    pub fn add_pageheap_with_kind(&self, name: &str, kind: u32) -> Result<bool> {
        // Creates or opens the registry key for the process.
        let subkey = self.key.create_subkey(name)?;

        // Reads the GlobalFlag to figure out if PageHeap is turned on.
        let global_flags = subkey.read_dword(GLOBAL_FLAG_KEY_NAME).unwrap_or(0);
        let pageheap_on = (global_flags & FLG_HEAP_PAGE_ALLOCS) == 0;
        let mut added_pageheap = false;
        if !pageheap_on {
            // If it's not turned on, then turn it on!
            let new_global_flags = global_flags | FLG_HEAP_PAGE_ALLOCS;
            subkey.write_dword(GLOBAL_FLAG_KEY_NAME, new_global_flags)?;

            added_pageheap = true;
        }

        // Now it's time to configure PageHeap.
        let pageheap_flags = subkey.read_dword(PAGE_HEAP_FLAGS_KEY_NAME).unwrap_or(0);
        if pageheap_flags == kind {
            return Ok(added_pageheap);
        }

        // Turn on the bits we want.
        let new_pageheap_flags = pageheap_flags | kind;
        subkey.write_dword(PAGE_HEAP_FLAGS_KEY_NAME, new_pageheap_flags)?;

        Ok(true)
    }

    /// Turns off PageHeap for `name`.
    pub fn remove_pageheap(&self, name: &str) -> Result<bool> {
        // Open the subkey and handle gracefully the case where it doesn't exist.
        let subkey = match self.key.open_subkey_rw(name) {
            // PageHeap was not enabled in the first place, so we're done here!
            Err(GflagsError::FailedOpenSubKey(err, _)) if err.code().0 as u32 == 0x80_07_00_02 => {
                return Ok(false)
            }
            v => v?,
        };

        // Try to read the GlobalFlag value. If it exists, then great. If it doesn't
        // then it's useful to let the rest of the function execute to potentially clean
        // up the key if it's empty.
        let global_flags = match subkey.read_dword(GLOBAL_FLAG_KEY_NAME) {
            // There's no GlobalFlag.
            Err(GflagsError::FailedReadDword(err, _)) if err.code().0 as u32 == 0x80_07_00_02 => {
                None
            }
            v => Some(v?),
        };

        // Let's track if we actually removed pageheap.
        let mut have_removed_pageheap = false;

        // If we did read flags, let's check if PageHeap is even on.
        let has_pageheap_enabled = (global_flags.unwrap_or(0) & FLG_HEAP_PAGE_ALLOCS) != 0;

        // Also check if this is the only set bit.
        let only_pageheap_enabled = global_flags.unwrap_or(0) == FLG_HEAP_PAGE_ALLOCS;

        // Untangle this mess..
        match (has_pageheap_enabled, only_pageheap_enabled) {
            (true, true) => {
                // PageHeap is enabled and this is the only bit turned on,
                // so we can just remove the value entirely.
                subkey.remove_value(GLOBAL_FLAG_KEY_NAME)?;

                // We did remove pageheap!
                have_removed_pageheap = true;
            }
            (true, false) => {
                // PageHeap is enabled but other bits are set, so let's
                // just strip the PageHeap bit.
                let new_global_flags = global_flags.unwrap() & (!FLG_HEAP_PAGE_ALLOCS);
                subkey.write_dword(GLOBAL_FLAG_KEY_NAME, new_global_flags)?;

                // We did remove pageheap!
                have_removed_pageheap = true;
            }
            _ => {}
        };

        // Grab the names of the values.
        let value_names = subkey.iter_value_names().collect::<Result<Vec<_>>>()?;

        // If there's one named 'PageHeapFlag', then remove it
        let has_pageheap_flags = value_names.iter().any(|v| v == PAGE_HEAP_FLAGS_KEY_NAME);
        if has_pageheap_flags {
            subkey.remove_value(PAGE_HEAP_FLAGS_KEY_NAME)?;
        }

        // To be able to remove the key, we need two things:
        // 1) to have no sub key and 2) have no values remaining.
        let subkey_names = subkey.iter_key_names().collect::<Result<Vec<_>>>()?;
        let can_clean_key = subkey_names.is_empty() && value_names.is_empty();
        if can_clean_key {
            subkey.remove()?;
        }

        Ok(have_removed_pageheap)
    }

    /// Returns a list of every processes that starts with a Debugger attached.
    pub fn list_debugger(&self) -> Result<Vec<(String, String)>> {
        // Walk through the children key names.
        let mut names = Vec::new();
        for subkey_name in self.key.iter_key_names() {
            let subkey_name = subkey_name?;

            // Open the subkey to walk the value names.
            let subkey = self.key.open_subkey(&subkey_name)?;

            // Try to read the debugger value.
            let debugger = match subkey.read_string(DEBUGGER_KEY_NAME) {
                // The only error we are fine swallowing is if the key doesn't exist.
                Err(GflagsError::FailedReadString(err, _))
                    if err.code().0 as u32 == 0x80_07_00_02 =>
                {
                    continue
                }
                v => v,
            }?;

            names.push((subkey_name, debugger));
        }

        Ok(names)
    }

    /// Adds a Debugger for `name`.
    pub fn add_debugger(&self, name: &str, dbg: &str) -> Result<(bool, String)> {
        // Creates or opens the registry key for the process.
        let subkey = self.key.create_subkey(name)?;

        // Tries to reads the Debugger value.
        if let Ok(dbg) = subkey.read_string(DEBUGGER_KEY_NAME) {
            return Ok((false, dbg));
        }

        // Turn on the bits we want.
        subkey.write_string(DEBUGGER_KEY_NAME, dbg)?;

        Ok((true, dbg.to_string()))
    }
}
