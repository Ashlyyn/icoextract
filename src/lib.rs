#![feature(slice_ptr_get)]

use core::panic;
use std::cmp::Reverse;
use std::ffi::{CStr};
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;
use std::path::PathBuf;
use std::ptr::{read_unaligned, slice_from_raw_parts};
use std::slice::from_raw_parts;

use libc::{c_char};
use num_traits::FromPrimitive;

mod pe;

const DOS_HEADER_MAGIC: u16 = 0x5A4D;
const NT_HEADER_SIGNATURE: u32 = 0x0004550;

#[derive(Clone, Default, Debug)]
pub struct IconBuffer {
    icon: Vec<u8>
}

impl IconBuffer {
    pub fn new() -> Self {
        Self {
            icon: Vec::new()
        }
    }

    pub fn from_vec(icon: Vec<u8>) -> Self {
        Self {
            icon
        }
    }

    pub fn unwrap(self) -> Vec<u8> {
        self.icon
    }

    pub fn to_file(self, path: PathBuf) -> std::io::Result<File> {
        let mut file = match std::fs::File::create(path) {
            Ok(f) => f,
            Err(e) => return Err(e)
        };

        match file.write_all(&self.icon) {
            Ok(_) => Ok(file),
            Err(e) => Err(e)
        }
    }
}

pub struct IconExtractor {
    bytes: Vec<u8>,
}

impl IconExtractor {
    pub fn from_path(path: PathBuf) -> Self {
        Self::from_file(File::open(path).unwrap())
    }

    pub fn from_file(mut file: File) -> Self {
        let mut vec: Vec<u8> = Vec::new();
        file.read(&mut vec).unwrap();
        Self::from_slice(&vec)
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }

    pub fn extract(self) -> Vec<IconBuffer> {
        println!("parsing DOS header...");
        let dos_header = Self::get_dos_header(&self.bytes).expect("failed to retrieve DOS header.");
        let e_magic = dos_header.e_magic;
        let e_lfanew = dos_header.e_lfanew;
        println!("DOS header found and signature validated (e_magic={:#06X}, e_lfanew={:#010X}).", e_magic, e_lfanew);

        println!("attempting to locate NT header.");
        let nt_header = Self::get_nt_header(&dos_header,&self.bytes).expect("failed to retrieve NT header");
        let signature = nt_header.signature;
        println!("NT header found (signature={:#010X}).", signature);

        if nt_header.optional_header_size == 0 {
            panic!("executable has no optional header (optional_header_size == 0).");
        }

        let nt_optional_header = Self::get_nt_optional_header(&dos_header, &self.bytes).expect("failed to retrieve NT optional header");
        
        match nt_optional_header {
            pe::nt::OptionalHeader::H32(h) => {
                let magic = h.magic;
                println!("NT optional header found (magic={:#06X}, 32-bit).", magic);
            },
            pe::nt::OptionalHeader::H64(h) => {
                let magic = h.magic;
                println!("NT optional header found (magic={:#06X}, 64-bit).", magic);
            },
        }   

        let sections = Self::get_section_table(&dos_header, &nt_header, &self.bytes);
        println!("Located section table (num_sections={:?}).", sections.len());

        for (i, s) in sections.iter().enumerate() {
            unsafe {
                println!("Found section {:?} ({:?}).", CStr::from_ptr(s.name.as_ptr() as *const c_char), i);
            }
        }

        let (resource_directory_root, rsrc_section_header) = Self::get_resource_directory_root(&nt_optional_header, &sections, &self.bytes).expect("failed to acquire resource section.");
        let resource_section_bytes = unsafe {
            &*core::ptr::slice_from_raw_parts(self.bytes.as_ptr().offset(rsrc_section_header.raw_data_offset as isize), rsrc_section_header.raw_data_size as usize)
        };
        let resource_directory_entries_bytes = unsafe { 
            &*core::ptr::slice_from_raw_parts(
                resource_section_bytes.as_ptr().add(size_of::<pe::nt::ResourceDirectoryRaw>()), 
                resource_directory_root.num_id_entries as usize * size_of::<pe::nt::ResourceDataEntryRaw>() + 
                resource_directory_root.num_named_entries as usize * size_of::<pe::nt::ResourceDataEntryRaw>())
        };  

        let resource_directory_root_entries = Self::get_resource_directory_entries(&resource_directory_root, resource_section_bytes, resource_directory_entries_bytes);
        let icons_resource_directory_root_entry = resource_directory_root_entries.iter().find(|e| match e.data_type {
            pe::nt::ResourceDirectoryEntryDataType::Id(3, _) => true,
            _ => false
        }).unwrap();

        let icons_resource_directory_ptr = match icons_resource_directory_root_entry.data_type {
            pe::nt::ResourceDirectoryEntryDataType::Id(3, offset) => match offset {
                pe::nt::ResourceDirectoryEntryOffsetType::Leaf(_) => panic!("icons resource directory is a leaf"),
                pe::nt::ResourceDirectoryEntryOffsetType::Stem(offset) => {
                    unsafe { resource_section_bytes.as_ptr().add(offset as usize) }
                }
            },
            _ => panic!("where the fuck i am")
        };

        let icons_resource_directory: pe::nt::ResourceDirectory = unsafe { (*(icons_resource_directory_ptr as *const pe::nt::ResourceDirectoryRaw)).into() };
        let icons_resource_data_entries_bytes = unsafe { &*slice_from_raw_parts(icons_resource_directory_ptr.add(size_of::<pe::nt::ResourceDirectoryRaw>()), 
            (icons_resource_directory.num_id_entries as usize * size_of::<pe::nt::ResourceDirectoryEntryRaw>()) as usize + 
            (icons_resource_directory.num_named_entries as usize * size_of::<pe::nt::ResourceDirectoryEntryRaw>()) as usize) };

        let r = Self::get_resource_data_entries(&rsrc_section_header,&icons_resource_directory, resource_section_bytes, icons_resource_data_entries_bytes);
        let mut icons: Vec<IconBuffer> = Vec::new();
        for d in r { 
            unsafe { icons.push(IconBuffer::from_vec(from_raw_parts(self.bytes.as_ptr().offset(d.offset as isize), d.size as usize).to_vec())) };
        }

        icons
    }

    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes
        }
    }

    fn get_dos_header(v: &[u8]) -> Result<pe::dos::Header, &'static str> {
        let dos_header_bytes = &v[0..std::mem::size_of::<pe::dos::Header>()];
        let dos_header: pe::dos::Header = unsafe { std::ptr::read_unaligned(dos_header_bytes.as_ptr() as *const _) };
        match dos_header.e_magic {
            DOS_HEADER_MAGIC => Ok(dos_header),
            _ => Err("invalid magic value for DOS header (probably not MZ/PE executable)")
        }
    }
    
    fn get_nt_header(dos_header: &pe::dos::Header, v: &[u8]) -> Result<pe::nt::Header, &'static str> {
        let nt_header_offset = dos_header.e_lfanew as usize;
        let nt_header_bytes = &v[nt_header_offset..nt_header_offset + std::mem::size_of::<pe::nt::Header>()];
        let nt_header: pe::nt::Header = unsafe { std::ptr::read_unaligned(nt_header_bytes.as_ptr() as *const _) };
    
        match nt_header.signature {
            NT_HEADER_SIGNATURE => Ok(nt_header),
            _ => Err("invalid magic value for NT header (probably not PE executable)")
        }
    }
    
    fn get_nt_optional_header(dos_header: &pe::dos::Header, v: &[u8]) -> Result<pe::nt::OptionalHeader, &'static str> {
        let nt_optional_header_offset = dos_header.e_lfanew as usize + size_of::<pe::nt::Header>() as usize;
        let nt_optional_header_bytes = &v[nt_optional_header_offset..nt_optional_header_offset + std::mem::size_of::<pe::nt::OptionalHeader>()];
        let magic_raw: u16 = unsafe { std::ptr::read_unaligned(nt_optional_header_bytes.as_ptr() as *const _) };
        let magic: pe::nt::OptionalHeaderMagic = match FromPrimitive::from_u16(magic_raw) {
            Some(m) => m,
            None => return Err("invalid NT optional header magic")
        };
    
        match magic {
            pe::nt::OptionalHeaderMagic::M32 => {
                let h32: pe::nt::OptionalHeader32 = unsafe { std::ptr::read_unaligned(nt_optional_header_bytes.as_ptr() as *const _) };
                Ok(pe::nt::OptionalHeader::H32(h32))
            },
            pe::nt::OptionalHeaderMagic::M64 => {
                let h64: pe::nt::OptionalHeader64 = unsafe { std::ptr::read_unaligned(nt_optional_header_bytes.as_ptr() as *const _) };
                Ok(pe::nt::OptionalHeader::H64(h64))
            },
            _ => panic!("where the fuck i am") // other cases should've been handled above
        }
    }
    
    fn get_section_table(dos_header: &pe::dos::Header, nt_header: &pe::nt::Header, v: &[u8]) -> Vec<pe::nt::SectionHeaderRaw> {
        let e_lfanew = dos_header.e_lfanew as usize;
        let nt_header_size = size_of::<pe::nt::Header>() as usize;
        let nt_optional_header_size = nt_header.optional_header_size as usize;
        let section_table_offset = e_lfanew + nt_header_size + nt_optional_header_size;
        let num_sections = nt_header.num_sections;
        let section_table_bytes = &v[section_table_offset..section_table_offset + size_of::<pe::nt::SectionHeaderRaw>() * num_sections as usize];
        let mut sections: Vec<pe::nt::SectionHeaderRaw> = Vec::new();
    
        unsafe {
            for i in 0..num_sections {
                sections.push(*(section_table_bytes.as_ptr() as *const pe::nt::SectionHeaderRaw).offset(i as isize));
            }
        }
    
        sections
    }
    
    
    fn get_resource_section_rva(nt_optional_header: &pe::nt::OptionalHeader) -> usize {
        let rsrc_data_dir: pe::nt::DataDirectory = match nt_optional_header {
            pe::nt::OptionalHeader::H32(h) => h.data_directory[2],
            pe::nt::OptionalHeader::H64(h) => h.data_directory[2],
        };
    
        rsrc_data_dir.vaddr as usize
    }
    
    
    fn get_resource_section_header(nt_optional_header: &pe::nt::OptionalHeader, section_table: &Vec<pe::nt::SectionHeaderRaw>) -> Option<pe::nt::SectionHeaderRaw> {
        let resource_section_rva = Self::get_resource_section_rva(nt_optional_header);
        for a in section_table {
            if a.virtual_address as usize == resource_section_rva {
                return Some(*a)
            }
        }
        None
    }
    
    fn get_resource_directory_root(nt_optional_header: &pe::nt::OptionalHeader, section_table: &Vec<pe::nt::SectionHeaderRaw>, v: &[u8]) -> Result<(pe::nt::ResourceDirectory, pe::nt::SectionHeader), &'static str> {
        let rsrc_section_header_raw = match Self::get_resource_section_header(nt_optional_header, section_table) {
            Some(h) => h,
            None => return Err("failed to find resource section header.")
        };
        let rsrc_section_header: pe::nt::SectionHeader = rsrc_section_header_raw.into();
        println!("Found resource section (section={:?})", rsrc_section_header.name);
        
        let resource_section_offset = rsrc_section_header.raw_data_offset as usize;
        let resource_section_size = rsrc_section_header.raw_data_size as usize;
        let resource_section_bytes = &v[resource_section_offset..resource_section_offset + resource_section_size];
        let resource_section_raw: pe::nt::ResourceDirectoryRaw = unsafe { read_unaligned(resource_section_bytes.as_ptr() as *const _) };
        Ok((resource_section_raw.into(), rsrc_section_header))
    }
    
    fn get_resource_directory_entries(resource_directory: &pe::nt::ResourceDirectory, resource_section_bytes: &[u8], resource_directory_entries_bytes: &[u8]) -> Vec<pe::nt::ResourceDirectoryEntry> {
        let mut v: Vec<pe::nt::ResourceDirectoryEntry> = Vec::new();
    
        for i in 0..(resource_directory.num_named_entries as usize) {
            unsafe {
                let raw = read_unaligned(
                    (resource_directory_entries_bytes.as_ptr() as *const pe::nt::ResourceDirectoryEntryRaw).add(i)
                );
                let len: usize = *(resource_section_bytes.as_ptr().offset(raw.offset as isize & !(1 << 31) as isize) as *const u32) as usize;
                let strbuf: &[u8] = from_raw_parts(resource_section_bytes.as_ptr().offset(raw.offset as isize & ((!(1 << 31)) as isize + size_of::<u32>() as isize)) as *const u8, len * 2);
                let string: pe::nt::ResourceDirectoryString = pe::nt::ResourceDirectoryString::from_utf16(strbuf.to_vec()).unwrap();
                v.push(pe::nt::ResourceDirectoryEntry::new((i + 1) as u16, pe::nt::ResourceDirectoryEntryDataType::Named(string, raw.offset.into())));
            };  
        }
    
        for i in 0..(resource_directory.num_id_entries as usize) {
            unsafe {
                let raw = read_unaligned(
                    (resource_directory_entries_bytes.as_ptr() as *const pe::nt::ResourceDirectoryEntryRaw).offset(i as isize + resource_directory.num_named_entries as isize)
                );
                v.push(pe::nt::ResourceDirectoryEntry::new((i + 1) as u16, pe::nt::ResourceDirectoryEntryDataType::Id(raw.id, raw.offset.into())));
            };
        }
    
        v
    }
    
    #[allow(clippy::cast_slice_different_sizes)]
    fn get_resource_data_entries(resource_section_header: &pe::nt::SectionHeader, root_directory: &pe::nt::ResourceDirectory, resource_section_bytes: &[u8], resource_directory_entries_bytes: &[u8]) -> Vec<pe::nt::ResourceDataEntry> {
        let v = Self::get_resource_directory_entries(root_directory, resource_section_bytes, resource_directory_entries_bytes);
        let mut r: Vec<pe::nt::ResourceDataEntry> = Vec::new();
        for e in v {
            match e.data_type {
                pe::nt::ResourceDirectoryEntryDataType::Id(_, t) => match t {
                    pe::nt::ResourceDirectoryEntryOffsetType::Leaf(offset) => unsafe {
                        let p = resource_section_bytes.as_ptr().offset(offset as isize) as *const pe::nt::ResourceDataEntryRaw;
                        r.push(pe::nt::ResourceDataEntry::from_raw(resource_section_header, *p));
                    },
                    pe::nt::ResourceDirectoryEntryOffsetType::Stem(offset) => {
                        let p = unsafe {
                            resource_section_bytes.as_ptr().offset(offset as isize) as *const pe::nt::ResourceDirectoryRaw
                        };
                        let raw = unsafe { *p };
                        let dir: pe::nt::ResourceDirectory = raw.into();
                        let resource_directory_entries_bytes = unsafe {
                            &*(core::ptr::slice_from_raw_parts((p as *const u8).add(size_of::<pe::nt::ResourceDirectoryRaw>()) as *const pe::nt::ResourceDirectoryEntryRaw, dir.num_id_entries as usize + dir.num_named_entries as usize) as *const [u8])
                        };
                        r.append(&mut Self::get_resource_data_entries(resource_section_header, &dir, resource_section_bytes, resource_directory_entries_bytes));
                    }
                },
                pe::nt::ResourceDirectoryEntryDataType::Named(_, t) => match t {
                    pe::nt::ResourceDirectoryEntryOffsetType::Leaf(offset) => unsafe {
                        let p = resource_section_bytes.as_ptr().offset(offset as isize) as *const pe::nt::ResourceDataEntryRaw;
                        r.push(pe::nt::ResourceDataEntry::from_raw(resource_section_header, *p));
                    },
                    pe::nt::ResourceDirectoryEntryOffsetType::Stem(offset) => {
                        let raw = unsafe { *(resource_section_bytes.as_ptr().offset(offset as isize) as *const pe::nt::ResourceDirectoryRaw) };
                        let dir: pe::nt::ResourceDirectory = raw.into();
                        r.append(&mut Self::get_resource_data_entries(resource_section_header, &dir, resource_section_bytes, resource_directory_entries_bytes));
                    }
                },
            }
        }
        
        r.sort_by_key(|w| Reverse(*w));
        r
    }
}