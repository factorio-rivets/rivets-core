#![feature(once_cell_try)]

use abi_stable::sabi_extern_fn;
use abi_stable::std_types::RBoxError;
use abi_stable::std_types::RResult;
use abi_stable::std_types::RStr;
use abi_stable::StableAbi;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

use pdb::FallibleIterator;
use pdb::PDB;

#[repr(C)]
#[derive(StableAbi)]
pub struct RivetsHook {
    hook: unsafe extern "C" fn(u64) -> RResult<(), RBoxError>,
}

#[repr(C)]
#[derive(StableAbi)]
pub struct RivetsLib {
    pub inject: unsafe extern "C" fn(RStr, RivetsHook) -> RResult<(), RBoxError>,
}

trait AsPcstr {
    fn as_pcstr(&self) -> PCSTR;
}

impl AsPcstr for CStr {
    fn as_pcstr(&self) -> PCSTR {
        PCSTR(self.as_ptr().cast())
    }
}

static PDB_CACHE: OnceLock<PDBCache> = OnceLock::new();

struct PDBCache {
    symbol_addresses: HashMap<String, u32>,
    base_address: u64,
}

impl PDBCache {
    /// Creates a new `PDBCache` instance.
    ///
    /// # Arguments
    /// * `pdb_path` - The path to the PDB file.
    /// * `module_name` - The name of the module to get the base address of.
    ///
    /// # Safety
    /// This function is unsafe because it uses the Windows API.
    /// Do not call this function in a threaded context.
    unsafe fn new(pdb_path: &Path, module_name: &str) -> Result<Self> {
        let file = File::open(pdb_path)?;
        let mut pdb = PDB::open(file)?;
        let base_address = Self::get_dll_base_address(module_name)?;

        let mut symbol_addresses = HashMap::new();
        let symbol_table = pdb.global_symbols()?;
        let address_map = pdb.address_map()?;

        symbol_table
            .iter()
            .for_each(|symbol| match symbol.parse() {
                Ok(pdb::SymbolData::Public(data)) if data.function => {
                    let rva = data.offset.to_rva(&address_map).unwrap_or_default();
                    symbol_addresses.insert(data.name.to_string().into(), rva.0);
                    Ok(())
                }
                Err(e) => Err(e),
                _ => Ok(()),
            })?;

        Ok(Self {
            symbol_addresses,
            base_address,
        })
    }

    unsafe fn get(factorio_path: &Path) -> Result<&'static Self> {
        PDB_CACHE.get_or_try_init(|| Self::new(&factorio_path.join("factorio.pdb"), "factorio.exe"))
    }

    fn get_function_address(&self, function_name: &str) -> Option<u64> {
        self.symbol_addresses
            .get(function_name)
            .copied()
            .map(|x| self.base_address + u64::from(x))
    }

    unsafe fn get_dll_base_address(module_name: &str) -> Result<u64> {
        let result = GetModuleHandleA(CString::new(module_name)?.as_pcstr());
        match result {
            Ok(handle) => Ok(handle.0 as u64),
            Err(err) => bail!(err),
        }
    }
}

fn string_to_rresult<T>(string: String) -> RResult<T, RBoxError> {
    #[derive(Debug)]
    struct Error {
        message: String,
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{}", &self.message)
        }
    }

    impl std::error::Error for Error {
        fn description(&self) -> &str {
            &self.message
        }
    }

    Err(RBoxError::new(Error { message: string })).into()
}

/// Injects a detour into a Factorio compiled function.
///
/// # Arguments
/// * `factorio_path` - The path to the Factorio binary directory.
/// * `function_name` - The name of the function to inject the detour into.
/// * `hook` - The detour function to inject.
///
/// # Safety
/// This function is unsafe because it uses the Windows API.
/// Do not call this function in a threaded context.
#[sabi_extern_fn]
#[must_use]
pub unsafe extern "C" fn inject(function_name: RStr, hook: RivetsHook) -> RResult<(), RBoxError> { // todo: remove pub
    let factorio_path = std::path::Path::new("C:/Users/zacha/Documents/factorio/bin");

    let addr = match PDBCache::get(factorio_path) {
        Ok(addr) => addr,
        Err(e) => return string_to_rresult(e.to_string()),
    };

    let Some(address) = addr.get_function_address(function_name.as_str()) else {
        return string_to_rresult(format!("Failed to find {function_name} address"));
    };
    println!("{function_name} address: {address:#x}");

    (hook.hook)(address)
}

// todo: could this be replaced by abi_stable to make it cross platform?
// todo: realistically, this should return a RRResult<(), RBoxError> however I was lazy.
// currently it returns Option<String> where the String repersenets an error message
dll_syringe::payload_procedure! {
    fn main(read_path: PathBuf, write_path: PathBuf) -> Option<String> {
        println!("Rivets initialized!");
        None
    }
}