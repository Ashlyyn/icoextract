use std::{ptr::{slice_from_raw_parts, addr_of}, ffi::{CStr, c_char}};

use num_derive::{FromPrimitive, ToPrimitive};
use utf16string::{WString, LittleEndian};

#[repr(u16)]
#[allow(dead_code)]
pub enum MachineType {
    I386 = 0x014C,
    IA64 = 0x0200,
    AMD64 = 0x8664,
}

#[repr(u16)]
#[allow(dead_code)]
pub enum Characteristics {
    RelocsStripped = 0x0001,
    ExecutableImage = 0x0002,
    LineNumsStripped = 0x0004,
    LocalSymsStripped = 0x0008,
    AggresiveWsTrim = 0x0010,
    LargeAddressAware = 0x0020,
    BytesReversedLo = 0x0080,
    Is32BitMachine = 0x0100,
    DebugStripped = 0x0200,
    RemovableRunFromSwap = 0x0400,
    NetRunFromSwap = 0x0800,
    SystemFile = 0x1000,
    Dll = 0x2000,
    UniprocessorSystemOnly = 0x4000,
    BytesReversedHi = 0x8000,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Header {
    pub signature: u32,
    machine: u16,
    pub num_sections: u16,
    time_date_stamp: u32,
    symbol_table_offset: u32,
    num_symbols: u32,
    pub optional_header_size: u16,
    characteristics: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct DataDirectory {
    pub vaddr: u32,
    size: u32,
}

#[repr(u16)]
#[derive(Copy, Clone, FromPrimitive, ToPrimitive)]
pub enum OptionalHeaderMagic {
    M32 = 0x010B,
    M64 = 0x020B,
    Rom = 0x0107,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct OptionalHeader32 {
    pub magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    code_size: u32,
    initialized_data_size: u32,
    uninitialized_data_size: u32,
    entry_point_offset: u32,
    code_base: u32,
    data_base: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    image_size: u32,
    headers_size: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    stack_reserve_size: u32,
    stack_commit_size: u32,
    heap_reserve_size: u32,
    heap_commit_size: u32,
    loader_flags: u32,
    num_rva_and_sizes: u32,
    pub data_directory: [DataDirectory; 16],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct OptionalHeader64 {
    pub magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    code_size: u32,
    initialized_data_size: u32,
    uninitialized_data_size: u32,
    entry_point_offset: u32,
    code_base: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    image_size: u32,
    headers_size: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    stack_reserve_size: u64,
    stack_commit_size: u64,
    heap_reserve_size: u64,
    heap_commit_size: u64,
    loader_flags: u32,
    num_rva_and_sizes: u32,
    pub data_directory: [DataDirectory; 16],
}

#[derive(Clone, Copy)]
pub enum OptionalHeader {
    H32(OptionalHeader32),
    H64(OptionalHeader64),
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct SectionHeaderRaw {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_offset: u32,
    pub relocations_offset: u32,
    pub line_numbers_offset: u32,
    pub num_relocations: u16,
    pub num_line_numbers: u16,
    pub characteristics: u32,
}

#[derive(Clone)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: usize,
    pub virtual_address: usize,
    pub raw_data_size: usize,
    pub raw_data_offset: usize,
    pub relocations_offset: usize,
    pub line_numbers_offset: usize,
    pub num_relocations: u16,
    pub num_line_numbers: u16,
    pub characteristics: u32,
}

impl From<SectionHeaderRaw> for SectionHeader {
    fn from(raw: SectionHeaderRaw) -> Self {
        let name = unsafe { CStr::from_ptr(raw.name.as_ptr() as *const c_char).to_str().unwrap().to_owned() };
        Self {
            name,
            virtual_size: raw.virtual_size as usize,
            virtual_address: raw.virtual_address as usize,
            raw_data_size: raw.raw_data_size as usize,
            raw_data_offset: raw.raw_data_offset as usize,
            relocations_offset: raw.relocations_offset as usize,
            line_numbers_offset: raw.line_numbers_offset as usize,
            num_relocations: raw.num_relocations.into(),
            num_line_numbers: raw.num_line_numbers.into(),
            characteristics: raw.characteristics.into()
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct ResourceDirectoryEntryRaw {
    pub id: u32,
    pub offset: i32,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ResourceDirectoryEntryOffsetType {
    Stem(i32),
    Leaf(i32)
}

impl From<i32> for ResourceDirectoryEntryOffsetType {
    fn from(i: i32) -> Self {
        if i & (1 << 31) != 0 {
            ResourceDirectoryEntryOffsetType::Stem(i & !(1 << 31))
        } else {
            ResourceDirectoryEntryOffsetType::Leaf(i)
        }
    }
}

pub struct ResourceDirectoryEntry {
    pub entry: u16,
    pub data_type: ResourceDirectoryEntryDataType
}

impl ResourceDirectoryEntry {
    pub fn new(entry: u16, data_type: ResourceDirectoryEntryDataType) -> Self {
        Self {
            entry,
            data_type
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ResourceDirectoryEntryDataType {
    Id(u32, ResourceDirectoryEntryOffsetType),
    Named(WString<LittleEndian>, ResourceDirectoryEntryOffsetType)
}

#[repr(C, packed)]
pub struct ResourceDirectoryStringRaw {
    pub len: u16,
    pub bytes: [u16]
}

#[allow(dead_code)]
pub type ResourceDirectoryString = WString<LittleEndian>;

impl From<&ResourceDirectoryStringRaw> for ResourceDirectoryString {
    fn from(raw: &ResourceDirectoryStringRaw) -> Self {
        let p = addr_of!(raw.bytes) as *const u8;
        let len = raw.len as usize * 2;
        let bytes = unsafe { &*slice_from_raw_parts(p, len) };
        WString::from_utf16(bytes.to_vec()).unwrap()
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct ResourceDataEntryRaw {
    pub rva: u32,
    pub size: u32,
    pub codepage: u32,
    rsv: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceDataEntry {
    pub offset: usize,
    pub size: usize,
    pub codepage: u32,
}

impl ResourceDataEntry {
    pub fn from_raw(section_header: &SectionHeader, raw: ResourceDataEntryRaw) -> Self {
        Self {
            offset: raw.rva as usize - section_header.virtual_address + section_header.raw_data_offset,
            size: raw.size as usize,
            codepage: raw.codepage
        }
    }
}

impl PartialOrd for ResourceDataEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.size.cmp(&other.size))
    }
}

impl Ord for ResourceDataEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.size.cmp(&other.size)
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct ResourceDirectoryRaw {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub num_named_entries: u16,
    pub num_id_entries: u16,
}

#[derive(Debug)]
pub struct ResourceDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub num_named_entries: u16,
    pub num_id_entries: u16
}

impl From<ResourceDirectoryRaw> for ResourceDirectory {
    fn from(raw: ResourceDirectoryRaw) -> Self {
        Self {
            characteristics: raw.characteristics,
            time_date_stamp: raw.time_date_stamp,
            major_version: raw.major_version,
            minor_version: raw.minor_version,
            num_named_entries: raw.num_named_entries,
            num_id_entries: raw.num_id_entries
        }
    }
}

impl ResourceDirectory {
    #[allow(dead_code)]
    pub fn new(characteristics: u32, time_date_stamp: u32, major_version: u16, minor_version: u16, num_named_entries: u16, num_id_entries: u16) -> Self {
        Self {
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            num_named_entries,
            num_id_entries
        }
    }
}