use abi_stable::std_types::RVec;
use anyhow::{bail, Result, Context};
use libloading::Library;
use mod_util::mod_list::ModList;
use mod_util::mod_loader::ModError;
use pdb::FallibleIterator;
use pdb::PDB;
use rivets::RivetsHook;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::path::{Path, PathBuf};
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

trait AsPcstr {
    fn as_pcstr(&self) -> PCSTR;
}

impl AsPcstr for CStr {
    fn as_pcstr(&self) -> PCSTR {
        PCSTR(self.as_ptr().cast())
    }
}

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
    unsafe fn new(pdb_path: impl AsRef<Path>, module_name: &str) -> Result<Self> {
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

    /// Injects a detour into a Factorio compiled function.
    ///
    /// # Arguments
    /// * `factorio_path` - The path to the Factorio binary directory.
    /// * `function_name` - The name of the function to inject the detour into.
    /// * `hook` - The detour function to inject.
    /// 
    /// # Safety
    /// todo!
    unsafe fn inject(&self, hook: &RivetsHook) -> Result<()> {
        let Some(address) = self.get_function_address(hook.mangled_name.as_str())
        else {
            bail!("Failed to find address for the following mangled function inside the PDB: {}", hook.mangled_name);
        };

        (hook.hook)(address)
            .into_result()
            .map_err(std::convert::Into::into)
    }
}

fn extract_all_mods_libs(
    read_data: impl AsRef<Path>,
    write_data: impl AsRef<Path>,
) -> Result<Vec<(String, PathBuf)>> {
    #[cfg(target_os = "linux")]
    static DYNAMIC_LIBRARY_SUFFIX: &str = ".so";
    #[cfg(target_os = "linux")]
    static RIVETS_LIB: &str = "rivets.so";
    #[cfg(target_os = "windows")]
    static DYNAMIC_LIBRARY_SUFFIX: &str = ".dll";
    #[cfg(target_os = "windows")]
    static RIVETS_LIB: &str = "rivets.dll";

    let mut result = vec![];
    let mut mod_list = ModList::generate_custom(&read_data, &write_data)?;
    mod_list.load()?;

    let (all_active_mods, mod_load_order) = mod_list.active_with_order();
    for mod_name in mod_load_order {
        if mod_name == "rivets" {
            continue;
        }

        let current_mod = all_active_mods
            .get(&mod_name)
            .expect("The list of active mods contains all mods in the load order");

        let lib = match current_mod.get_file(RIVETS_LIB) {
            Err(ModError::PathDoesNotExist(_)) => continue,
            Err(ModError::ZipError(e))
                if e.to_string() == "specified file not found in archive" =>
            {
                continue
            }
            Ok(lib) => lib,
            Err(e) => return Err(e.into()),
        };

        std::fs::create_dir_all(write_data.as_ref().join("temp/rivets"))?;

        let extracted_lib_name = format!("{mod_name}{DYNAMIC_LIBRARY_SUFFIX}");
        let lib_path = write_data
            .as_ref()
            .join("temp/rivets")
            .join(extracted_lib_name);
        std::fs::write(&lib_path, lib)?;

        result.push((mod_name, lib_path));
    }

    Ok(result)
}

// todo: this is duplicate code. move to rivets rs
fn get_bin_folder() -> Result<PathBuf> {
    std::env::current_exe()?
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("Failed to get binary folder"))
}

unsafe fn main(read_path: PathBuf, write_path: PathBuf) -> Result<()> {
    let pdb_path = get_bin_folder()?.join("factorio.pdb");
    let pdb_cache = PDBCache::new(pdb_path, "factorio.exe")?;

    for (mod_name, dll_so_file) in extract_all_mods_libs(read_path, write_path)? {
        let dll_so_file = Library::new(dll_so_file)?;

        let err_msg = format!("Failed to get rivets_finalize ABI function for mod {mod_name}. Did you forget to call rivets::finalize!()?");
        let get_hooks: libloading::Symbol<extern "C" fn() -> RVec<rivets::RivetsHook>> =
            dll_so_file.get(b"rivets_finalize\0").context(err_msg)?;

        for hook in get_hooks() {
            pdb_cache.inject(&hook)?;
        }
    }
    Ok(())
}

// todo: could this be replaced by abi_stable to make it cross platform?
// todo: realistically, this should return a RRResult<(), RBoxError> however I was lazy.
// currently it returns Option<String> where the String repersents an error message
dll_syringe::payload_procedure! {
    fn rivetslib_setup(read_path: PathBuf, write_path: PathBuf) -> Option<String> {
        match unsafe { main(read_path, write_path) } {
            Ok(()) => None,
            Err(e) => Some(e.to_string()),
        }
    }
}
