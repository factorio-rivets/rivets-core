#![feature(once_cell_try)]

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::path::Path;
use std::sync::OnceLock;
use anyhow:: {bail, Result};
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

use pdb::FallibleIterator;
use pdb::PDB;
use rivets::detour;
use rivets::Opaque;
use rivets::AsPcstr;

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
        PDB_CACHE.get_or_try_init(|| {
            Self::new(&factorio_path.join("factorio.pdb"), "factorio.exe")
        })
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
unsafe fn inject(function_name: &str, hook: unsafe fn(u64) -> Result<(), rivets::retour::Error>) -> Result<()> {
    let factorio_path = std::path::Path::new("C:/Users/zacha/Documents/factorio/bin");

    let Some(address) = PDBCache::get(factorio_path)?.get_function_address(function_name) else {
        bail!("Failed to find {function_name} address");
    };
    println!("{function_name} address: {address:#x}");

    unsafe { Ok(hook(address)?) }
}

#[detour(?valid@LuaSurface@@UEBA_NXZ)]
fn valid(this: Opaque) -> bool {
    println!("Hello from LuaSurface::valid!");
    unsafe { back(this) }
}

rivets::_finalize!();