/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.15   Soo Han, Kin        added : stopwatch
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_WINNT__
#define __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_WINNT__

#include <hotplace/sdk/base.hpp>

using namespace hotplace;

#pragma pack(push, 1)

#define UNALIGNED

#if defined BIG_ENDIAN
#define IMAGE_DOS_SIGNATURE                 0x5A4D              // MZ
#define IMAGE_OS2_SIGNATURE                 0x454E              // NE
#define IMAGE_OS2_SIGNATURE_LE              0x454C              // LE
#define IMAGE_VXD_SIGNATURE                 0x454C              // LE
#define IMAGE_NT_SIGNATURE                  0x00004550          // PE00
#elif defined LITTLE_ENDIAN
#define IMAGE_DOS_SIGNATURE                 0x4D5A              // MZ
#define IMAGE_OS2_SIGNATURE                 0x4E45              // NE
#define IMAGE_OS2_SIGNATURE_LE              0x4C45              // LE
#define IMAGE_NT_SIGNATURE                  0x50450000          // PE00
#endif

typedef struct _IMAGE_DOS_HEADER {  // DOS .EXE header
    uint16 e_magic;                 // Magic number
    uint16 e_cblp;                  // Bytes on last page of file
    uint16 e_cp;                    // Pages in file
    uint16 e_crlc;                  // Relocations
    uint16 e_cparhdr;               // Size of header in paragraphs
    uint16 e_minalloc;              // Minimum extra paragraphs needed
    uint16 e_maxalloc;              // Maximum extra paragraphs needed
    uint16 e_ss;                    // Initial (relative) SS value
    uint16 e_sp;                    // Initial SP value
    uint16 e_csum;                  // Checksum
    uint16 e_ip;                    // Initial IP value
    uint16 e_cs;                    // Initial (relative) CS value
    uint16 e_lfarlc;                // File address of relocation table
    uint16 e_ovno;                  // Overlay number
    uint16 e_res[4];                // Reserved words
    uint16 e_oemid;                 // OEM identifier (for e_oeminfo)
    uint16 e_oeminfo;               // OEM information; e_oemid specific
    uint16 e_res2[10];              // Reserved words
    uint32 e_lfanew;                // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_OS2_HEADER {  // OS/2 .EXE header
    uint16 ne_magic;                // Magic number
    char ne_ver;                    // Version number
    char ne_rev;                    // Revision number
    uint16 ne_enttab;               // Offset of Entry Table
    uint16 ne_cbenttab;             // Number of bytes in Entry Table
    uint32 ne_crc;                  // Checksum of whole file
    uint16 ne_flags;                // Flag word
    uint16 ne_autodata;             // Automatic data segment number
    uint16 ne_heap;                 // Initial heap allocation
    uint16 ne_stack;                // Initial stack allocation
    uint32 ne_csip;                 // Initial CS:IP setting
    uint32 ne_sssp;                 // Initial SS:SP setting
    uint16 ne_cseg;                 // Count of file segments
    uint16 ne_cmod;                 // Entries in Module Reference Table
    uint16 ne_cbnrestab;            // Size of non-resident name table
    uint16 ne_segtab;               // Offset of Segment Table
    uint16 ne_rsrctab;              // Offset of Resource Table
    uint16 ne_restab;               // Offset of resident name table
    uint16 ne_modtab;               // Offset of Module Reference Table
    uint16 ne_imptab;               // Offset of Imported Names Table
    uint32 ne_nrestab;              // Offset of Non-resident Names Table
    uint16 ne_cmovent;              // Count of movable entries
    uint16 ne_align;                // Segment alignment shift count
    uint16 ne_cres;                 // Count of resource segments
    byte_t ne_exetyp;               // Target Operating system
    byte_t ne_flagsothers;          // Other .EXE flags
    uint16 ne_pretthunks;           // offset to return thunks
    uint16 ne_psegrefbytes;         // offset to segment ref. bytes
    uint16 ne_swaparea;             // Minimum code swap area size
    uint16 ne_expver;               // Expected Windows version number
} IMAGE_OS2_HEADER, *PIMAGE_OS2_HEADER;

typedef struct _IMAGE_VXD_HEADER {  // Windows VXD header
    uint16 e32_magic;               // Magic number
    byte_t e32_border;              // The byte ordering for the VXD
    byte_t e32_worder;              // The word ordering for the VXD
    uint32 e32_level;               // The EXE format level for now = 0
    uint16 e32_cpu;                 // The CPU type
    uint16 e32_os;                  // The OS type
    uint32 e32_ver;                 // Module version
    uint32 e32_mflags;              // Module flags
    uint32 e32_mpages;              // Module # pages
    uint32 e32_startobj;            // Object # for instruction pointer
    uint32 e32_eip;                 // Extended instruction pointer
    uint32 e32_stackobj;            // Object # for stack pointer
    uint32 e32_esp;                 // Extended stack pointer
    uint32 e32_pagesize;            // VXD page size
    uint32 e32_lastpagesize;        // Last page size in VXD
    uint32 e32_fixupsize;           // Fixup section size
    uint32 e32_fixupsum;            // Fixup section checksum
    uint32 e32_ldrsize;             // Loader section size
    uint32 e32_ldrsum;              // Loader section checksum
    uint32 e32_objtab;              // Object table offset
    uint32 e32_objcnt;              // Number of objects in module
    uint32 e32_objmap;              // Object page map offset
    uint32 e32_itermap;             // Object iterated data map offset
    uint32 e32_rsrctab;             // Offset of Resource Table
    uint32 e32_rsrccnt;             // Number of resource entries
    uint32 e32_restab;              // Offset of resident name table
    uint32 e32_enttab;              // Offset of Entry Table
    uint32 e32_dirtab;              // Offset of Module Directive Table
    uint32 e32_dircnt;              // Number of module directives
    uint32 e32_fpagetab;            // Offset of Fixup Page Table
    uint32 e32_frectab;             // Offset of Fixup Record Table
    uint32 e32_impmod;              // Offset of Import Module Name Table
    uint32 e32_impmodcnt;           // Number of entries in Import Module Name Table
    uint32 e32_impproc;             // Offset of Import Procedure Name Table
    uint32 e32_pagesum;             // Offset of Per-Page Checksum Table
    uint32 e32_datapage;            // Offset of Enumerated Data Pages
    uint32 e32_preload;             // Number of preload pages
    uint32 e32_nrestab;             // Offset of Non-resident Names Table
    uint32 e32_cbnrestab;           // Size of Non-resident Name Table
    uint32 e32_nressum;             // Non-resident Name Table Checksum
    uint32 e32_autodata;            // Object # for automatic data object
    uint32 e32_debuginfo;           // Offset of the debugging information
    uint32 e32_debuglen;            // The length of the debugging info. in bytes
    uint32 e32_instpreload;         // Number of instance pages in preload section of VXD file
    uint32 e32_instdemand;          // Number of instance pages in demand load section of VXD file
    uint32 e32_heapsize;            // Size of heap - for 16-bit apps
    byte_t e32_res3[12];            // Reserved words
    uint32 e32_winresoff;
    uint32 e32_winreslen;
    uint16 e32_devid;                   // Device ID for VxD
    uint16 e32_ddkver;                  // DDK version for VxD
} IMAGE_VXD_HEADER, *PIMAGE_VXD_HEADER;

//
// File header format.
//

typedef struct _IMAGE_FILE_HEADER {
    uint16 Machine;
    uint16 NumberOfSections;
    uint32 TimeDateStamp;
    uint32 PointerToSymbolTable;
    uint32 NumberOfSymbols;
    uint16 SizeOfOptionalHeader;
    uint16 Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER             20

#define IMAGE_FILE_RELOCS_STRIPPED           0x0001     // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002     // File is executable  (i.e. no unresolved externel references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004     // Line nunbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008     // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010     // Agressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020     // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080     // Bytes of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE             0x0100     // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200     // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400     // If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800     // If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                    0x1000     // System File.
#define IMAGE_FILE_DLL                       0x2000     // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000     // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000     // Bytes of machine word are reversed.

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_I386              0x014c     // Intel 386.
#define IMAGE_FILE_MACHINE_R3000             0x0162     // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000             0x0166     // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000            0x0168     // MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169     // MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA             0x0184     // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3               0x01a2     // SH3 little-endian
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4     // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH4               0x01a6     // SH4 little-endian
#define IMAGE_FILE_MACHINE_SH5               0x01a8     // SH5
#define IMAGE_FILE_MACHINE_ARM               0x01c0     // ARM Little-Endian
#define IMAGE_FILE_MACHINE_THUMB             0x01c2
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0     // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200     // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266     // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284     // ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366     // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466     // MIPS
#define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520     // Infineon
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC     // EFI Byte Code
#define IMAGE_FILE_MACHINE_AMD64             0x8664     // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041     // M32R little-endian
#define IMAGE_FILE_MACHINE_CEE               0xC0EE

//
// Directory format.
//

typedef struct _IMAGE_DATA_DIRECTORY {
    uint32 VirtualAddress;
    uint32 Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

//
// Optional header format.
//

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    uint16 Magic;
    byte_t MajorLinkerVersion;
    byte_t MinorLinkerVersion;
    uint32 SizeOfCode;
    uint32 SizeOfInitializedData;
    uint32 SizeOfUninitializedData;
    uint32 AddressOfEntryPoint;
    uint32 BaseOfCode;
    uint32 BaseOfData;

    //
    // NT additional fields.
    //

    uint32 ImageBase;
    uint32 SectionAlignment;
    uint32 FileAlignment;
    uint16 MajorOperatingSystemVersion;
    uint16 MinorOperatingSystemVersion;
    uint16 MajorImageVersion;
    uint16 MinorImageVersion;
    uint16 MajorSubsystemVersion;
    uint16 MinorSubsystemVersion;
    uint32 Win32VersionValue;
    uint32 SizeOfImage;
    uint32 SizeOfHeaders;
    uint32 CheckSum;
    uint16 Subsystem;
    uint16 DllCharacteristics;
    uint32 SizeOfStackReserve;
    uint32 SizeOfStackCommit;
    uint32 SizeOfHeapReserve;
    uint32 SizeOfHeapCommit;
    uint32 LoaderFlags;
    uint32 NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
    uint16 Magic;
    byte_t MajorLinkerVersion;
    byte_t MinorLinkerVersion;
    uint32 SizeOfCode;
    uint32 SizeOfInitializedData;
    uint32 SizeOfUninitializedData;
    uint32 AddressOfEntryPoint;
    uint32 BaseOfCode;
    uint32 BaseOfData;
    uint32 BaseOfBss;
    uint32 GprMask;
    uint32 CprMask[4];
    uint32 GpValue;
} IMAGE_ROM_OPTIONAL_HEADER, *PIMAGE_ROM_OPTIONAL_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    uint16 Magic;
    byte_t MajorLinkerVersion;
    byte_t MinorLinkerVersion;
    uint32 SizeOfCode;
    uint32 SizeOfInitializedData;
    uint32 SizeOfUninitializedData;
    uint32 AddressOfEntryPoint;
    uint32 BaseOfCode;
    uint64 ImageBase;
    uint32 SectionAlignment;
    uint32 FileAlignment;
    uint16 MajorOperatingSystemVersion;
    uint16 MinorOperatingSystemVersion;
    uint16 MajorImageVersion;
    uint16 MinorImageVersion;
    uint16 MajorSubsystemVersion;
    uint16 MinorSubsystemVersion;
    uint32 Win32VersionValue;
    uint32 SizeOfImage;
    uint32 SizeOfHeaders;
    uint32 CheckSum;
    uint16 Subsystem;
    uint16 DllCharacteristics;
    uint64 SizeOfStackReserve;
    uint64 SizeOfStackCommit;
    uint64 SizeOfHeapReserve;
    uint64 SizeOfHeapCommit;
    uint32 LoaderFlags;
    uint32 NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107

#ifdef _WIN64
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC         IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC         IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif

typedef struct _IMAGE_NT_HEADERS64 {
    uint32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    uint32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_ROM_HEADERS {
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
} IMAGE_ROM_HEADERS, *PIMAGE_ROM_HEADERS;

#ifdef _WIN64
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
#else
typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
#endif

// IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is the same either way.

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
                                         ((arch_t) ntheader +                                              \
                                          FIELD_OFFSET ( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
                                          ((PIMAGE_NT_HEADERS) (ntheader))->FileHeader.SizeOfOptionalHeader   \
                                         ))

// Subsystem Values

#define IMAGE_SUBSYSTEM_UNKNOWN              0          // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE               1          // Image doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI          2          // Image runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI          3          // Image runs in the Windows character subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI              5          // image runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI            7          // image runs in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS       8          // image is a native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       9          // Image runs in the Windows CE subsystem.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION      10         //
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11     //
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER   12         //
#define IMAGE_SUBSYSTEM_EFI_ROM              13
#define IMAGE_SUBSYSTEM_XBOX                 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

// DllCharacteristics Entries

//      IMAGE_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
//      IMAGE_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
//      IMAGE_LIBRARY_THREAD_INIT             0x0004     // Reserved.
//      IMAGE_LIBRARY_THREAD_TERM             0x0008     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040            // DLL can move.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080      // Code Integrity Image
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT    0x0100            // Image is NX compatible
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200            // Image understands isolation and doesn't want it
#define IMAGE_DLLCHARACTERISTICS_NO_SEH       0x0400            // Image does not use SEH.  No SE handler may reside in this image
#define IMAGE_DLLCHARACTERISTICS_NO_BIND      0x0800            // Do not bind this image.
//                                            0x1000     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER   0x2000            // Driver uses WDM model
//                                            0x4000     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE     0x8000

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0     // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1     // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2     // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3     // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4     // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5     // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6     // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7     // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8     // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9     // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10     // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11     // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12     // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13     // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14     // COM Runtime descriptor

#if 0
//
// Non-COFF Object file header
//

typedef struct ANON_OBJECT_HEADER {
    uint16 Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
    uint16 Sig2;            // Must be 0xffff
    uint16 Version;         // >= 1 (implies the CLSID field is present)
    uint16 Machine;
    uint32 TimeDateStamp;
    CLSID ClassID;          // Used to invoke CoCreateInstance
    uint32 SizeOfData;      // Size of data that follows the header
}ANON_OBJECT_HEADER;

typedef struct ANON_OBJECT_HEADER_V2 {
    uint16 Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
    uint16 Sig2;            // Must be 0xffff
    uint16 Version;         // >= 2 (implies the Flags field is present - otherwise V1)
    uint16 Machine;
    uint32 TimeDateStamp;
    CLSID ClassID;              // Used to invoke CoCreateInstance
    uint32 SizeOfData;          // Size of data that follows the header
    uint32 Flags;               // 0x1 -> contains metadata
    uint32 MetaDataSize;        // Size of CLR metadata
    uint32 MetaDataOffset;      // Offset of CLR metadata
}ANON_OBJECT_HEADER_V2;
#endif

//
// Section header format.
//

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    byte_t Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32 PhysicalAddress;
        uint32 VirtualSize;
    } Misc;
    uint32 VirtualAddress;
    uint32 SizeOfRawData;
    uint32 PointerToRawData;
    uint32 PointerToRelocations;
    uint32 PointerToLinenumbers;
    uint16 NumberOfRelocations;
    uint16 NumberOfLinenumbers;
    uint32 Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40

//
// Section characteristics.
//
//      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
//      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008    // Reserved.
//      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

#define IMAGE_SCN_CNT_CODE                   0x00000020     // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040     // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080     // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER                  0x00000100     // Reserved.
#define IMAGE_SCN_LNK_INFO                   0x00000200     // Section contains comments or some other type of information.
//      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
#define IMAGE_SCN_LNK_REMOVE                 0x00000800     // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT                 0x00001000     // Section contents comdat.
//                                           0x00002000  // Reserved.
//      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000     // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_GPREL                      0x00008000     // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA                0x00008000
//      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000

#define IMAGE_SCN_ALIGN_1BYTES               0x00100000     //
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000     //
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000     //
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000     //
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000     // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000     //
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000     //
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000     //
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000     //
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000     //
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000     //
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000     //
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000     //
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000     //
// Unused                                    0x00F00000
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000     // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000     // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000     // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000     // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                 0x10000000     // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000     // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000     // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000     // Section is writeable.

//
// TLS Chaacteristic Flags
//
#define IMAGE_SCN_SCALE_INDEX                0x00000001    // Tls index is scaled

//
// Symbol format.
//

typedef struct _IMAGE_SYMBOL {
    union {
        byte_t ShortName[8];
        struct {
            uint32 Short;       // if 0, use LongName
            uint32 Long;        // offset into string table
        } Name;
        uint32 LongName[2];     // PBYTE [2]
    } N;
    uint32 Value;
    uint16 SectionNumber;
    uint16 Type;
    byte_t StorageClass;
    byte_t NumberOfAuxSymbols;
} IMAGE_SYMBOL;
typedef IMAGE_SYMBOL UNALIGNED *PIMAGE_SYMBOL;

#define IMAGE_SIZEOF_SYMBOL                  18

//
// Section values.
//
// Symbols have a section number of the section in which they are
// defined. Otherwise, section numbers have the following meanings:
//

#define IMAGE_SYM_UNDEFINED           (uint16) 0        // Symbol is undefined or is common.
#define IMAGE_SYM_ABSOLUTE            (uint16) - 1      // Symbol is an absolute value.
#define IMAGE_SYM_DEBUG               (uint16) - 2      // Symbol is a special debug item.
#define IMAGE_SYM_SECTION_MAX         0xFEFF            // Values 0xFF00-0xFFFF are special

//
// Type (fundamental) values.
//

#define IMAGE_SYM_TYPE_NULL                 0x0000      // no type.
#define IMAGE_SYM_TYPE_VOID                 0x0001      //
#define IMAGE_SYM_TYPE_CHAR                 0x0002      // type character.
#define IMAGE_SYM_TYPE_SHORT                0x0003      // type short integer.
#define IMAGE_SYM_TYPE_INT                  0x0004      //
#define IMAGE_SYM_TYPE_LONG                 0x0005      //
#define IMAGE_SYM_TYPE_FLOAT                0x0006      //
#define IMAGE_SYM_TYPE_DOUBLE               0x0007      //
#define IMAGE_SYM_TYPE_STRUCT               0x0008      //
#define IMAGE_SYM_TYPE_UNION                0x0009      //
#define IMAGE_SYM_TYPE_ENUM                 0x000A      // enumeration.
#define IMAGE_SYM_TYPE_MOE                  0x000B      // member of enumeration.
#define IMAGE_SYM_TYPE_BYTE                 0x000C      //
#define IMAGE_SYM_TYPE_WORD                 0x000D      //
#define IMAGE_SYM_TYPE_UINT                 0x000E      //
#define IMAGE_SYM_TYPE_DWORD                0x000F      //
#define IMAGE_SYM_TYPE_PCODE                0x8000      //
//
// Type (derived) values.
//

#define IMAGE_SYM_DTYPE_NULL                0       // no derived type.
#define IMAGE_SYM_DTYPE_POINTER             1       // pointer.
#define IMAGE_SYM_DTYPE_FUNCTION            2       // function.
#define IMAGE_SYM_DTYPE_ARRAY               3       // array.

//
// Storage classes.
//
#define IMAGE_SYM_CLASS_END_OF_FUNCTION     (byte_t) -1
#define IMAGE_SYM_CLASS_NULL                0x0000
#define IMAGE_SYM_CLASS_AUTOMATIC           0x0001
#define IMAGE_SYM_CLASS_EXTERNAL            0x0002
#define IMAGE_SYM_CLASS_STATIC              0x0003
#define IMAGE_SYM_CLASS_REGISTER            0x0004
#define IMAGE_SYM_CLASS_EXTERNAL_DEF        0x0005
#define IMAGE_SYM_CLASS_LABEL               0x0006
#define IMAGE_SYM_CLASS_UNDEFINED_LABEL     0x0007
#define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    0x0008
#define IMAGE_SYM_CLASS_ARGUMENT            0x0009
#define IMAGE_SYM_CLASS_STRUCT_TAG          0x000A
#define IMAGE_SYM_CLASS_MEMBER_OF_UNION     0x000B
#define IMAGE_SYM_CLASS_UNION_TAG           0x000C
#define IMAGE_SYM_CLASS_TYPE_DEFINITION     0x000D
#define IMAGE_SYM_CLASS_UNDEFINED_STATIC    0x000E
#define IMAGE_SYM_CLASS_ENUM_TAG            0x000F
#define IMAGE_SYM_CLASS_MEMBER_OF_ENUM      0x0010
#define IMAGE_SYM_CLASS_REGISTER_PARAM      0x0011
#define IMAGE_SYM_CLASS_BIT_FIELD           0x0012

#define IMAGE_SYM_CLASS_FAR_EXTERNAL        0x0044    //

#define IMAGE_SYM_CLASS_BLOCK               0x0064
#define IMAGE_SYM_CLASS_FUNCTION            0x0065
#define IMAGE_SYM_CLASS_END_OF_STRUCT       0x0066
#define IMAGE_SYM_CLASS_FILE                0x0067
// new
#define IMAGE_SYM_CLASS_SECTION             0x0068
#define IMAGE_SYM_CLASS_WEAK_EXTERNAL       0x0069

#define IMAGE_SYM_CLASS_CLR_TOKEN           0x006B

// type packing constants

#define N_BTMASK                            0x000F
#define N_TMASK                             0x0030
#define N_TMASK1                            0x00C0
#define N_TMASK2                            0x00F0
#define N_BTSHFT                            4
#define N_TSHIFT                            2
// MACROS

// Basic Type of  x
#define BTYPE(x) ((x) & N_BTMASK)

// Is x a pointer?
#ifndef ISPTR
#define ISPTR(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT))
#endif

// Is x a function?
#ifndef ISFCN
#define ISFCN(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT))
#endif

// Is x an array?

#ifndef ISARY
#define ISARY(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_ARRAY << N_BTSHFT))
#endif

// Is x a structure, union, or enumeration TAG?
#ifndef ISTAG
#define ISTAG(x) ((x) == IMAGE_SYM_CLASS_STRUCT_TAG || (x) == IMAGE_SYM_CLASS_UNION_TAG || (x) == IMAGE_SYM_CLASS_ENUM_TAG)
#endif

#ifndef INCREF
#define INCREF(x) ((((x) & ~N_BTMASK) << N_TSHIFT) | (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT) | ((x) & N_BTMASK))
#endif
#ifndef DECREF
#define DECREF(x) ((((x) >> N_TSHIFT) & ~N_BTMASK) | ((x) & N_BTMASK))
#endif

//
// Auxiliary entry format.
//

typedef union _IMAGE_AUX_SYMBOL {
    struct {
        uint32 TagIndex;               // struct, union, or enum tag index
        union {
            struct {
                uint16 Linenumber;          // declaration line number
                uint16 Size;                // size of struct, union, or enum
            } LnSz;
            uint32 TotalSize;
        } Misc;
        union {
            struct {                  // if ISFCN, tag, or .bb
                uint32 PointerToLinenumber;
                uint32 PointerToNextFunction;
            } Function;
            struct {                  // if ISARY, up to 4 dimen.
                uint16 Dimension[4];
            } Array;
        } FcnAry;
        uint16 TvIndex;                 // tv index
    } Sym;
    struct {
        byte_t Name[IMAGE_SIZEOF_SYMBOL];
    } File;
    struct {
        uint32 Length;                  // section length
        uint16 NumberOfRelocations;     // number of relocation entries
        uint16 NumberOfLinenumbers;     // number of line numbers
        uint32 CheckSum;                // checksum for communal
        uint16 Number;                  // section number to associate with
        byte_t Selection;               // communal selection type
    } Section;
} IMAGE_AUX_SYMBOL;
typedef IMAGE_AUX_SYMBOL UNALIGNED *PIMAGE_AUX_SYMBOL;

typedef enum IMAGE_AUX_SYMBOL_TYPE {
    IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1,
} IMAGE_AUX_SYMBOL_TYPE;

typedef struct IMAGE_AUX_SYMBOL_TOKEN_DEF {
    byte_t bAuxType;                // IMAGE_AUX_SYMBOL_TYPE
    byte_t bReserved;               // Must be 0
    uint32 SymbolTableIndex;
    byte_t rgbReserved[12];         // Must be 0
} IMAGE_AUX_SYMBOL_TOKEN_DEF;

typedef IMAGE_AUX_SYMBOL_TOKEN_DEF UNALIGNED *PIMAGE_AUX_SYMBOL_TOKEN_DEF;

//
// Communal selection types.
//

#define IMAGE_COMDAT_SELECT_NODUPLICATES    1
#define IMAGE_COMDAT_SELECT_ANY             2
#define IMAGE_COMDAT_SELECT_SAME_SIZE       3
#define IMAGE_COMDAT_SELECT_EXACT_MATCH     4
#define IMAGE_COMDAT_SELECT_ASSOCIATIVE     5
#define IMAGE_COMDAT_SELECT_LARGEST         6
#define IMAGE_COMDAT_SELECT_NEWEST          7

#define IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY  1
#define IMAGE_WEAK_EXTERN_SEARCH_LIBRARY    2
#define IMAGE_WEAK_EXTERN_SEARCH_ALIAS      3

//
// Relocation format.
//

typedef struct _IMAGE_RELOCATION {
    union {
        uint32 VirtualAddress;
        uint32 RelocCount;         // Set to the real count when IMAGE_SCN_LNK_NRELOC_OVFL is set
    };
    uint32 SymbolTableIndex;
    uint16 Type;
} IMAGE_RELOCATION;
typedef IMAGE_RELOCATION UNALIGNED *PIMAGE_RELOCATION;

//
// I386 relocation types.
//
#define IMAGE_REL_I386_ABSOLUTE         0x0000      // Reference is absolute, no relocation is necessary
#define IMAGE_REL_I386_DIR16            0x0001      // Direct 16-bit reference to the symbols virtual address
#define IMAGE_REL_I386_REL16            0x0002      // PC-relative 16-bit reference to the symbols virtual address
#define IMAGE_REL_I386_DIR32            0x0006      // Direct 32-bit reference to the symbols virtual address
#define IMAGE_REL_I386_DIR32NB          0x0007      // Direct 32-bit reference to the symbols virtual address, base not included
#define IMAGE_REL_I386_SEG12            0x0009      // Direct 16-bit reference to the segment-selector bits of a 32-bit virtual address
#define IMAGE_REL_I386_SECTION          0x000A
#define IMAGE_REL_I386_SECREL           0x000B
#define IMAGE_REL_I386_TOKEN            0x000C      // clr token
#define IMAGE_REL_I386_SECREL7          0x000D      // 7 bit offset from base of section containing target
#define IMAGE_REL_I386_REL32            0x0014      // PC-relative 32-bit reference to the symbols virtual address

//
// MIPS relocation types.
//
#define IMAGE_REL_MIPS_ABSOLUTE         0x0000    // Reference is absolute, no relocation is necessary
#define IMAGE_REL_MIPS_REFHALF          0x0001
#define IMAGE_REL_MIPS_REFWORD          0x0002
#define IMAGE_REL_MIPS_JMPADDR          0x0003
#define IMAGE_REL_MIPS_REFHI            0x0004
#define IMAGE_REL_MIPS_REFLO            0x0005
#define IMAGE_REL_MIPS_GPREL            0x0006
#define IMAGE_REL_MIPS_LITERAL          0x0007
#define IMAGE_REL_MIPS_SECTION          0x000A
#define IMAGE_REL_MIPS_SECREL           0x000B
#define IMAGE_REL_MIPS_SECRELLO         0x000C      // Low 16-bit section relative referemce (used for >32k TLS)
#define IMAGE_REL_MIPS_SECRELHI         0x000D      // High 16-bit section relative reference (used for >32k TLS)
#define IMAGE_REL_MIPS_TOKEN            0x000E      // clr token
#define IMAGE_REL_MIPS_JMPADDR16        0x0010
#define IMAGE_REL_MIPS_REFWORDNB        0x0022
#define IMAGE_REL_MIPS_PAIR             0x0025

//
// Alpha Relocation types.
//
#define IMAGE_REL_ALPHA_ABSOLUTE        0x0000
#define IMAGE_REL_ALPHA_REFLONG         0x0001
#define IMAGE_REL_ALPHA_REFQUAD         0x0002
#define IMAGE_REL_ALPHA_GPREL32         0x0003
#define IMAGE_REL_ALPHA_LITERAL         0x0004
#define IMAGE_REL_ALPHA_LITUSE          0x0005
#define IMAGE_REL_ALPHA_GPDISP          0x0006
#define IMAGE_REL_ALPHA_BRADDR          0x0007
#define IMAGE_REL_ALPHA_HINT            0x0008
#define IMAGE_REL_ALPHA_INLINE_REFLONG  0x0009
#define IMAGE_REL_ALPHA_REFHI           0x000A
#define IMAGE_REL_ALPHA_REFLO           0x000B
#define IMAGE_REL_ALPHA_PAIR            0x000C
#define IMAGE_REL_ALPHA_MATCH           0x000D
#define IMAGE_REL_ALPHA_SECTION         0x000E
#define IMAGE_REL_ALPHA_SECREL          0x000F
#define IMAGE_REL_ALPHA_REFLONGNB       0x0010
#define IMAGE_REL_ALPHA_SECRELLO        0x0011      // Low 16-bit section relative reference
#define IMAGE_REL_ALPHA_SECRELHI        0x0012      // High 16-bit section relative reference
#define IMAGE_REL_ALPHA_REFQ3           0x0013      // High 16 bits of 48 bit reference
#define IMAGE_REL_ALPHA_REFQ2           0x0014      // Middle 16 bits of 48 bit reference
#define IMAGE_REL_ALPHA_REFQ1           0x0015      // Low 16 bits of 48 bit reference
#define IMAGE_REL_ALPHA_GPRELLO         0x0016      // Low 16-bit GP relative reference
#define IMAGE_REL_ALPHA_GPRELHI         0x0017      // High 16-bit GP relative reference

//
// IBM PowerPC relocation types.
//
#define IMAGE_REL_PPC_ABSOLUTE          0x0000      // NOP
#define IMAGE_REL_PPC_ADDR64            0x0001      // 64-bit address
#define IMAGE_REL_PPC_ADDR32            0x0002      // 32-bit address
#define IMAGE_REL_PPC_ADDR24            0x0003      // 26-bit address, shifted left 2 (branch absolute)
#define IMAGE_REL_PPC_ADDR16            0x0004      // 16-bit address
#define IMAGE_REL_PPC_ADDR14            0x0005      // 16-bit address, shifted left 2 (load doubleword)
#define IMAGE_REL_PPC_REL24             0x0006      // 26-bit PC-relative offset, shifted left 2 (branch relative)
#define IMAGE_REL_PPC_REL14             0x0007      // 16-bit PC-relative offset, shifted left 2 (br cond relative)
#define IMAGE_REL_PPC_TOCREL16          0x0008      // 16-bit offset from TOC base
#define IMAGE_REL_PPC_TOCREL14          0x0009      // 16-bit offset from TOC base, shifted left 2 (load doubleword)

#define IMAGE_REL_PPC_ADDR32NB          0x000A      // 32-bit addr w/o image base
#define IMAGE_REL_PPC_SECREL            0x000B      // va of containing section (as in an image sectionhdr)
#define IMAGE_REL_PPC_SECTION           0x000C      // sectionheader number
#define IMAGE_REL_PPC_IFGLUE            0x000D      // substitute TOC restore instruction iff symbol is glue code
#define IMAGE_REL_PPC_IMGLUE            0x000E      // symbol is glue code; virtual address is TOC restore instruction
#define IMAGE_REL_PPC_SECREL16          0x000F      // va of containing section (limited to 16 bits)
#define IMAGE_REL_PPC_REFHI             0x0010
#define IMAGE_REL_PPC_REFLO             0x0011
#define IMAGE_REL_PPC_PAIR              0x0012
#define IMAGE_REL_PPC_SECRELLO          0x0013      // Low 16-bit section relative reference (used for >32k TLS)
#define IMAGE_REL_PPC_SECRELHI          0x0014      // High 16-bit section relative reference (used for >32k TLS)
#define IMAGE_REL_PPC_GPREL             0x0015
#define IMAGE_REL_PPC_TOKEN             0x0016      // clr token

#define IMAGE_REL_PPC_TYPEMASK          0x00FF      // mask to isolate above values in IMAGE_RELOCATION.Type

// Flag bits in IMAGE_RELOCATION.TYPE

#define IMAGE_REL_PPC_NEG               0x0100      // subtract reloc value rather than adding it
#define IMAGE_REL_PPC_BRTAKEN           0x0200      // fix branch prediction bit to predict branch taken
#define IMAGE_REL_PPC_BRNTAKEN          0x0400      // fix branch prediction bit to predict branch not taken
#define IMAGE_REL_PPC_TOCDEFN           0x0800      // toc slot defined in file (or, data in toc)

//
// Hitachi SH3 relocation types.
//
#define IMAGE_REL_SH3_ABSOLUTE          0x0000      // No relocation
#define IMAGE_REL_SH3_DIRECT16          0x0001      // 16 bit direct
#define IMAGE_REL_SH3_DIRECT32          0x0002      // 32 bit direct
#define IMAGE_REL_SH3_DIRECT8           0x0003      // 8 bit direct, -128..255
#define IMAGE_REL_SH3_DIRECT8_WORD      0x0004      // 8 bit direct .W (0 ext.)
#define IMAGE_REL_SH3_DIRECT8_LONG      0x0005      // 8 bit direct .L (0 ext.)
#define IMAGE_REL_SH3_DIRECT4           0x0006      // 4 bit direct (0 ext.)
#define IMAGE_REL_SH3_DIRECT4_WORD      0x0007      // 4 bit direct .W (0 ext.)
#define IMAGE_REL_SH3_DIRECT4_LONG      0x0008      // 4 bit direct .L (0 ext.)
#define IMAGE_REL_SH3_PCREL8_WORD       0x0009      // 8 bit PC relative .W
#define IMAGE_REL_SH3_PCREL8_LONG       0x000A      // 8 bit PC relative .L
#define IMAGE_REL_SH3_PCREL12_WORD      0x000B      // 12 LSB PC relative .W
#define IMAGE_REL_SH3_STARTOF_SECTION   0x000C      // Start of EXE section
#define IMAGE_REL_SH3_SIZEOF_SECTION    0x000D      // Size of EXE section
#define IMAGE_REL_SH3_SECTION           0x000E      // Section table index
#define IMAGE_REL_SH3_SECREL            0x000F      // Offset within section
#define IMAGE_REL_SH3_DIRECT32_NB       0x0010      // 32 bit direct not based
#define IMAGE_REL_SH3_GPREL4_LONG       0x0011      // GP-relative addressing
#define IMAGE_REL_SH3_TOKEN             0x0012      // clr token
#define IMAGE_REL_SHM_PCRELPT           0x0013      // Offset from current
//  instruction in longwords
//  if not NOMODE, insert the
//  inverse of the low bit at
//  bit 32 to select PTA/PTB
#define IMAGE_REL_SHM_REFLO             0x0014      // Low bits of 32-bit address
#define IMAGE_REL_SHM_REFHALF           0x0015      // High bits of 32-bit address
#define IMAGE_REL_SHM_RELLO             0x0016      // Low bits of relative reference
#define IMAGE_REL_SHM_RELHALF           0x0017      // High bits of relative reference
#define IMAGE_REL_SHM_PAIR              0x0018      // offset operand for relocation

#define IMAGE_REL_SH_NOMODE             0x8000      // relocation ignores section mode

#define IMAGE_REL_ARM_ABSOLUTE          0x0000      // No relocation required
#define IMAGE_REL_ARM_ADDR32            0x0001      // 32 bit address
#define IMAGE_REL_ARM_ADDR32NB          0x0002      // 32 bit address w/o image base
#define IMAGE_REL_ARM_BRANCH24          0x0003      // 24 bit offset << 2 & sign ext.
#define IMAGE_REL_ARM_BRANCH11          0x0004      // Thumb: 2 11 bit offsets
#define IMAGE_REL_ARM_TOKEN             0x0005      // clr token
#define IMAGE_REL_ARM_GPREL12           0x0006      // GP-relative addressing (ARM)
#define IMAGE_REL_ARM_GPREL7            0x0007      // GP-relative addressing (Thumb)
#define IMAGE_REL_ARM_BLX24             0x0008
#define IMAGE_REL_ARM_BLX11             0x0009
#define IMAGE_REL_ARM_SECTION           0x000E      // Section table index
#define IMAGE_REL_ARM_SECREL            0x000F      // Offset within section

#define IMAGE_REL_AM_ABSOLUTE           0x0000
#define IMAGE_REL_AM_ADDR32             0x0001
#define IMAGE_REL_AM_ADDR32NB           0x0002
#define IMAGE_REL_AM_CALL32             0x0003
#define IMAGE_REL_AM_FUNCINFO           0x0004
#define IMAGE_REL_AM_REL32_1            0x0005
#define IMAGE_REL_AM_REL32_2            0x0006
#define IMAGE_REL_AM_SECREL             0x0007
#define IMAGE_REL_AM_SECTION            0x0008
#define IMAGE_REL_AM_TOKEN              0x0009

//
// x64 relocations
//
#define IMAGE_REL_AMD64_ABSOLUTE        0x0000      // Reference is absolute, no relocation is necessary
#define IMAGE_REL_AMD64_ADDR64          0x0001      // 64-bit address (VA).
#define IMAGE_REL_AMD64_ADDR32          0x0002      // 32-bit address (VA).
#define IMAGE_REL_AMD64_ADDR32NB        0x0003      // 32-bit address w/o image base (RVA).
#define IMAGE_REL_AMD64_REL32           0x0004      // 32-bit relative address from byte following reloc
#define IMAGE_REL_AMD64_REL32_1         0x0005      // 32-bit relative address from byte distance 1 from reloc
#define IMAGE_REL_AMD64_REL32_2         0x0006      // 32-bit relative address from byte distance 2 from reloc
#define IMAGE_REL_AMD64_REL32_3         0x0007      // 32-bit relative address from byte distance 3 from reloc
#define IMAGE_REL_AMD64_REL32_4         0x0008      // 32-bit relative address from byte distance 4 from reloc
#define IMAGE_REL_AMD64_REL32_5         0x0009      // 32-bit relative address from byte distance 5 from reloc
#define IMAGE_REL_AMD64_SECTION         0x000A      // Section index
#define IMAGE_REL_AMD64_SECREL          0x000B      // 32 bit offset from base of section containing target
#define IMAGE_REL_AMD64_SECREL7         0x000C      // 7 bit unsigned offset from base of section containing target
#define IMAGE_REL_AMD64_TOKEN           0x000D      // 32 bit metadata token
#define IMAGE_REL_AMD64_SREL32          0x000E      // 32 bit signed span-dependent value emitted into object
#define IMAGE_REL_AMD64_PAIR            0x000F
#define IMAGE_REL_AMD64_SSPAN32         0x0010      // 32 bit signed span-dependent value applied at link time

//
// IA64 relocation types.
//
#define IMAGE_REL_IA64_ABSOLUTE         0x0000
#define IMAGE_REL_IA64_IMM14            0x0001
#define IMAGE_REL_IA64_IMM22            0x0002
#define IMAGE_REL_IA64_IMM64            0x0003
#define IMAGE_REL_IA64_DIR32            0x0004
#define IMAGE_REL_IA64_DIR64            0x0005
#define IMAGE_REL_IA64_PCREL21B         0x0006
#define IMAGE_REL_IA64_PCREL21M         0x0007
#define IMAGE_REL_IA64_PCREL21F         0x0008
#define IMAGE_REL_IA64_GPREL22          0x0009
#define IMAGE_REL_IA64_LTOFF22          0x000A
#define IMAGE_REL_IA64_SECTION          0x000B
#define IMAGE_REL_IA64_SECREL22         0x000C
#define IMAGE_REL_IA64_SECREL64I        0x000D
#define IMAGE_REL_IA64_SECREL32         0x000E
//
#define IMAGE_REL_IA64_DIR32NB          0x0010
#define IMAGE_REL_IA64_SREL14           0x0011
#define IMAGE_REL_IA64_SREL22           0x0012
#define IMAGE_REL_IA64_SREL32           0x0013
#define IMAGE_REL_IA64_UREL32           0x0014
#define IMAGE_REL_IA64_PCREL60X         0x0015      // This is always a BRL and never converted
#define IMAGE_REL_IA64_PCREL60B         0x0016      // If possible, convert to MBB bundle with NOP.B in slot 1
#define IMAGE_REL_IA64_PCREL60F         0x0017      // If possible, convert to MFB bundle with NOP.F in slot 1
#define IMAGE_REL_IA64_PCREL60I         0x0018      // If possible, convert to MIB bundle with NOP.I in slot 1
#define IMAGE_REL_IA64_PCREL60M         0x0019      // If possible, convert to MMB bundle with NOP.M in slot 1
#define IMAGE_REL_IA64_IMMGPREL64       0x001A
#define IMAGE_REL_IA64_TOKEN            0x001B      // clr token
#define IMAGE_REL_IA64_GPREL32          0x001C
#define IMAGE_REL_IA64_ADDEND           0x001F

//
// CEF relocation types.
//
#define IMAGE_REL_CEF_ABSOLUTE          0x0000      // Reference is absolute, no relocation is necessary
#define IMAGE_REL_CEF_ADDR32            0x0001      // 32-bit address (VA).
#define IMAGE_REL_CEF_ADDR64            0x0002      // 64-bit address (VA).
#define IMAGE_REL_CEF_ADDR32NB          0x0003      // 32-bit address w/o image base (RVA).
#define IMAGE_REL_CEF_SECTION           0x0004      // Section index
#define IMAGE_REL_CEF_SECREL            0x0005      // 32 bit offset from base of section containing target
#define IMAGE_REL_CEF_TOKEN             0x0006      // 32 bit metadata token

//
// clr relocation types.
//
#define IMAGE_REL_CEE_ABSOLUTE          0x0000                                                              // Reference is absolute, no relocation is necessary
#define IMAGE_REL_CEE_ADDR32            0x0001                                                              // 32-bit address (VA).
#define IMAGE_REL_CEE_ADDR64            0x0002                                                              // 64-bit address (VA).
#define IMAGE_REL_CEE_ADDR32NB          0x0003                                                              // 32-bit address w/o image base (RVA).
#define IMAGE_REL_CEE_SECTION           0x0004                                                              // Section index
#define IMAGE_REL_CEE_SECREL            0x0005                                                              // 32 bit offset from base of section containing target
#define IMAGE_REL_CEE_TOKEN             0x0006                                                              // 32 bit metadata token

#define IMAGE_REL_M32R_ABSOLUTE         0x0000                                                              // No relocation required
#define IMAGE_REL_M32R_ADDR32           0x0001                                                              // 32 bit address
#define IMAGE_REL_M32R_ADDR32NB         0x0002                                                              // 32 bit address w/o image base
#define IMAGE_REL_M32R_ADDR24           0x0003                                                              // 24 bit address
#define IMAGE_REL_M32R_GPREL16          0x0004                                                              // GP relative addressing
#define IMAGE_REL_M32R_PCREL24          0x0005                                                              // 24 bit offset << 2 & sign ext.
#define IMAGE_REL_M32R_PCREL16          0x0006                                                              // 16 bit offset << 2 & sign ext.
#define IMAGE_REL_M32R_PCREL8           0x0007                                                              // 8 bit offset << 2 & sign ext.
#define IMAGE_REL_M32R_REFHALF          0x0008                                                              // 16 MSBs
#define IMAGE_REL_M32R_REFHI            0x0009                                                              // 16 MSBs; adj for LSB sign ext.
#define IMAGE_REL_M32R_REFLO            0x000A                                                              // 16 LSBs
#define IMAGE_REL_M32R_PAIR             0x000B                                                              // Link HI and LO
#define IMAGE_REL_M32R_SECTION          0x000C                                                              // Section table index
#define IMAGE_REL_M32R_SECREL32         0x000D                                                              // 32 bit section relative reference
#define IMAGE_REL_M32R_TOKEN            0x000E                                                              // clr token

#define IMAGE_REL_EBC_ABSOLUTE          0x0000                                                              // No relocation required
#define IMAGE_REL_EBC_ADDR32NB          0x0001                                                              // 32 bit address w/o image base
#define IMAGE_REL_EBC_REL32             0x0002                                                              // 32-bit relative address from byte following reloc
#define IMAGE_REL_EBC_SECTION           0x0003                                                              // Section table index
#define IMAGE_REL_EBC_SECREL            0x0004                                                              // Offset within section

#define EXT_IMM64(Value, Address, Size, InstPos, ValPos)                                                    /* Intel-IA64-Filler */           \
    Value |= (((uint64) ((*(Address) >> InstPos) & (((uint64) 1 << Size) - 1))) << ValPos)                  // Intel-IA64-Filler

#define INS_IMM64(Value, Address, Size, InstPos, ValPos)                                                    /* Intel-IA64-Filler */ \
    *(PDWORD) Address = (*(PDWORD) Address & ~(((1 << Size) - 1) << InstPos)) |                             /* Intel-IA64-Filler */ \
                        ((uint32) ((((uint64) Value >> ValPos) & (((uint64) 1 << Size) - 1))) << InstPos)   // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM7B_INST_WORD_X         3                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM7B_SIZE_X              7                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X     4                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM7B_VAL_POS_X           0                                                          // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM9D_INST_WORD_X         3                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM9D_SIZE_X              9                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X     18                                                         // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM9D_VAL_POS_X           7                                                          // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM5C_INST_WORD_X         3                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM5C_SIZE_X              5                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X     13                                                         // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM5C_VAL_POS_X           16                                                         // Intel-IA64-Filler

#define EMARCH_ENC_I17_IC_INST_WORD_X            3                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IC_SIZE_X                 1                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IC_INST_WORD_POS_X        12                                                         // Intel-IA64-Filler
#define EMARCH_ENC_I17_IC_VAL_POS_X              21                                                         // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM41a_INST_WORD_X        1                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41a_SIZE_X             10                                                         // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X    14                                                         // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41a_VAL_POS_X          22                                                         // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM41b_INST_WORD_X        1                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41b_SIZE_X             8                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X    24                                                         // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41b_VAL_POS_X          32                                                         // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM41c_INST_WORD_X        2                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41c_SIZE_X             23                                                         // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X    0                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41c_VAL_POS_X          40                                                         // Intel-IA64-Filler

#define EMARCH_ENC_I17_SIGN_INST_WORD_X          3                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_SIGN_SIZE_X               1                                                          // Intel-IA64-Filler
#define EMARCH_ENC_I17_SIGN_INST_WORD_POS_X      27                                                         // Intel-IA64-Filler
#define EMARCH_ENC_I17_SIGN_VAL_POS_X            63                                                         // Intel-IA64-Filler

#define X3_OPCODE_INST_WORD_X                    3                                                          // Intel-IA64-Filler
#define X3_OPCODE_SIZE_X                         4                                                          // Intel-IA64-Filler
#define X3_OPCODE_INST_WORD_POS_X                28                                                         // Intel-IA64-Filler
#define X3_OPCODE_SIGN_VAL_POS_X                 0                                                          // Intel-IA64-Filler

#define X3_I_INST_WORD_X                         3                                                          // Intel-IA64-Filler
#define X3_I_SIZE_X                              1                                                          // Intel-IA64-Filler
#define X3_I_INST_WORD_POS_X                     27                                                         // Intel-IA64-Filler
#define X3_I_SIGN_VAL_POS_X                      59                                                         // Intel-IA64-Filler

#define X3_D_WH_INST_WORD_X                      3                                                          // Intel-IA64-Filler
#define X3_D_WH_SIZE_X                           3                                                          // Intel-IA64-Filler
#define X3_D_WH_INST_WORD_POS_X                  24                                                         // Intel-IA64-Filler
#define X3_D_WH_SIGN_VAL_POS_X                   0                                                          // Intel-IA64-Filler

#define X3_IMM20_INST_WORD_X                     3                                                          // Intel-IA64-Filler
#define X3_IMM20_SIZE_X                          20                                                         // Intel-IA64-Filler
#define X3_IMM20_INST_WORD_POS_X                 4                                                          // Intel-IA64-Filler
#define X3_IMM20_SIGN_VAL_POS_X                  0                                                          // Intel-IA64-Filler

#define X3_IMM39_1_INST_WORD_X                   2                                                          // Intel-IA64-Filler
#define X3_IMM39_1_SIZE_X                        23                                                         // Intel-IA64-Filler
#define X3_IMM39_1_INST_WORD_POS_X               0                                                          // Intel-IA64-Filler
#define X3_IMM39_1_SIGN_VAL_POS_X                36                                                         // Intel-IA64-Filler

#define X3_IMM39_2_INST_WORD_X                   1                                                          // Intel-IA64-Filler
#define X3_IMM39_2_SIZE_X                        16                                                         // Intel-IA64-Filler
#define X3_IMM39_2_INST_WORD_POS_X               16                                                         // Intel-IA64-Filler
#define X3_IMM39_2_SIGN_VAL_POS_X                20                                                         // Intel-IA64-Filler

#define X3_P_INST_WORD_X                         3                                                          // Intel-IA64-Filler
#define X3_P_SIZE_X                              4                                                          // Intel-IA64-Filler
#define X3_P_INST_WORD_POS_X                     0                                                          // Intel-IA64-Filler
#define X3_P_SIGN_VAL_POS_X                      0                                                          // Intel-IA64-Filler

#define X3_TMPLT_INST_WORD_X                     0                                                          // Intel-IA64-Filler
#define X3_TMPLT_SIZE_X                          4                                                          // Intel-IA64-Filler
#define X3_TMPLT_INST_WORD_POS_X                 0                                                          // Intel-IA64-Filler
#define X3_TMPLT_SIGN_VAL_POS_X                  0                                                          // Intel-IA64-Filler

#define X3_BTYPE_QP_INST_WORD_X                  2                                                          // Intel-IA64-Filler
#define X3_BTYPE_QP_SIZE_X                       9                                                          // Intel-IA64-Filler
#define X3_BTYPE_QP_INST_WORD_POS_X              23                                                         // Intel-IA64-Filler
#define X3_BTYPE_QP_INST_VAL_POS_X               0                                                          // Intel-IA64-Filler

#define X3_EMPTY_INST_WORD_X                     1                                                          // Intel-IA64-Filler
#define X3_EMPTY_SIZE_X                          2                                                          // Intel-IA64-Filler
#define X3_EMPTY_INST_WORD_POS_X                 14                                                         // Intel-IA64-Filler
#define X3_EMPTY_INST_VAL_POS_X                  0                                                          // Intel-IA64-Filler

//
// Line number format.
//

typedef struct _IMAGE_LINENUMBER {
    union {
        uint32 SymbolTableIndex;                // Symbol table index of function name if Linenumber is 0.
        uint32 VirtualAddress;                  // Virtual address of line number.
    } Type;
    uint16 Linenumber;                          // Line number.
} IMAGE_LINENUMBER;
typedef IMAGE_LINENUMBER UNALIGNED *PIMAGE_LINENUMBER;

//
// Based relocation format.
//

typedef struct _IMAGE_BASE_RELOCATION {
    uint32 VirtualAddress;
    uint32 SizeOfBlock;
//  uint16    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;

//
// Based relocation types.
//

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MIPS_JMPADDR          5
#define IMAGE_REL_BASED_MIPS_JMPADDR16        9
#define IMAGE_REL_BASED_IA64_IMM64            9
#define IMAGE_REL_BASED_DIR64                 10

//
// Archive format.
//

#define IMAGE_ARCHIVE_START_SIZE             8
#define IMAGE_ARCHIVE_START                  "!<arch>\n"
#define IMAGE_ARCHIVE_END                    "`\n"
#define IMAGE_ARCHIVE_PAD                    "\n"
#define IMAGE_ARCHIVE_LINKER_MEMBER          "/               "
#define IMAGE_ARCHIVE_LONGNAMES_MEMBER       "//              "

typedef struct _IMAGE_ARCHIVE_MEMBER_HEADER {
    byte_t Name[16];        // File member name - `/' terminated.
    byte_t Date[12];        // File member date - decimal.
    byte_t UserID[6];       // File member user id - decimal.
    byte_t GroupID[6];      // File member group id - decimal.
    byte_t Mode[8];         // File member mode - octal.
    byte_t Size[10];        // File member size - decimal.
    byte_t EndHeader[2];    // String to end header.
} IMAGE_ARCHIVE_MEMBER_HEADER, *PIMAGE_ARCHIVE_MEMBER_HEADER;

#define IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR      60

//
// DLL support.
//

//
// Export Format
//

typedef struct _IMAGE_EXPORT_DIRECTORY {
    uint32 Characteristics;
    uint32 TimeDateStamp;
    uint16 MajorVersion;
    uint16 MinorVersion;
    uint32 Name;
    uint32 Base;
    uint32 NumberOfFunctions;
    uint32 NumberOfNames;
    uint32 AddressOfFunctions;          // RVA from base of image
    uint32 AddressOfNames;              // RVA from base of image
    uint32 AddressOfNameOrdinals;       // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

//
// Import Format
//

typedef struct _IMAGE_IMPORT_BY_NAME {
    uint16 Hint;
    byte_t Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        uint64 ForwarderString;     // PBYTE
        uint64 Function;            // PDWORD
        uint64 Ordinal;
        uint64 AddressOfData;       // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        uint32 ForwarderString;     // PBYTE
        uint32 Function;            // PDWORD
        uint32 Ordinal;
        uint32 AddressOfData;       // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

typedef struct _IMAGE_TLS_DIRECTORY64 {
    uint64 StartAddressOfRawData;
    uint64 EndAddressOfRawData;
    uint64 AddressOfIndex;          // PDWORD
    uint64 AddressOfCallBacks;      // PIMAGE_TLS_CALLBACK *;
    uint32 SizeOfZeroFill;
    uint32 Characteristics;
} IMAGE_TLS_DIRECTORY64;
typedef IMAGE_TLS_DIRECTORY64 * PIMAGE_TLS_DIRECTORY64;

typedef struct _IMAGE_TLS_DIRECTORY32 {
    uint32 StartAddressOfRawData;
    uint32 EndAddressOfRawData;
    uint32 AddressOfIndex;              // PDWORD
    uint32 AddressOfCallBacks;          // PIMAGE_TLS_CALLBACK *
    uint32 SizeOfZeroFill;
    uint32 Characteristics;
} IMAGE_TLS_DIRECTORY32;
typedef IMAGE_TLS_DIRECTORY32 * PIMAGE_TLS_DIRECTORY32;

#ifdef _WIN64
#define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL64 (Ordinal)
typedef IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA64 PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL64 (Ordinal)
typedef IMAGE_TLS_DIRECTORY64 IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY64 PIMAGE_TLS_DIRECTORY;
#else
#define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL32 (Ordinal)
typedef IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA32 PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL32 (Ordinal)
typedef IMAGE_TLS_DIRECTORY32 IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY32 PIMAGE_TLS_DIRECTORY;
#endif

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        uint32 Characteristics;             // 0 for terminating null import descriptor
        uint32 OriginalFirstThunk;          // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    uint32 TimeDateStamp;                   // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    uint32 ForwarderChain;                  // -1 if no forwarders
    uint32 Name;
    uint32 FirstThunk;                      // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

//
// New format import descriptors pointed to by DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ]
//

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    uint32 TimeDateStamp;
    uint16 OffsetModuleName;
    uint16 NumberOfModuleForwarderRefs;
// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR, *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF {
    uint32 TimeDateStamp;
    uint16 OffsetModuleName;
    uint16 Reserved;
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;

//
// Resource Format.
//

//
// Resource directory consists of two counts, following by a variable length
// array of directory entries.  The first count is the number of entries at
// beginning of the array that have actual names associated with each entry.
// The entries are in ascending order, case insensitive strings.  The second
// count is the number of entries that immediately follow the named entries.
// This second count identifies the number of entries that have 16-bit integer
// Ids as their name.  These entries are also sorted in ascending order.
//
// This structure allows fast lookup by either name or number, but for any
// given resource entry only one form of lookup is supported, not both.
// This is consistant with the syntax of the .RC file and the .RES file.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    uint32 Characteristics;
    uint32 TimeDateStamp;
    uint16 MajorVersion;
    uint16 MinorVersion;
    uint16 NumberOfNamedEntries;
    uint16 NumberOfIdEntries;
//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

#define IMAGE_RESOURCE_NAME_IS_STRING        0x80000000
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY     0x80000000
//
// Each directory contains the 32-bit Name of the entry and an offset,
// relative to the beginning of the resource directory of the data associated
// with this directory entry.  If the name of the entry is an actual text
// string instead of an integer Id, then the high order bit of the name field
// is set to one and the low order 31-bits are an offset, relative to the
// beginning of the resource directory of the string, which is of type
// IMAGE_RESOURCE_DIRECTORY_STRING.  Otherwise the high bit is clear and the
// low-order 16-bits are the integer Id that identify this resource directory
// entry. If the directory entry is yet another resource directory (i.e. a
// subdirectory), then the high order bit of the offset field will be
// set to indicate this.  Otherwise the high bit is clear and the offset
// field points to a resource data entry.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            uint32 NameOffset : 31;
            uint32 NameIsString : 1;
        };
        uint32 Name;
        uint16 Id;
    };
    union {
        uint32 OffsetToData;
        struct {
            uint32 OffsetToDirectory : 31;
            uint32 DataIsDirectory : 1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

//
// For resource directory entries that have actual string names, the Name
// field of the directory entry points to an object of the following type.
// All of these string objects are stored together after the last resource
// directory entry and before the first resource data object.  This minimizes
// the impact of these variable length objects on the alignment of the fixed
// size directory entry objects.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
    uint16 Length;
    char NameString[1];
} IMAGE_RESOURCE_DIRECTORY_STRING, *PIMAGE_RESOURCE_DIRECTORY_STRING;

#if 0
typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
    uint16 Length;
    WCHAR NameString[1];
}IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;
#endif

//
// Each resource data entry describes a leaf node in the resource directory
// tree.  It contains an offset, relative to the beginning of the resource
// directory of the data for the resource, a size field that gives the number
// of bytes of data at that offset, a CodePage that should be used when
// decoding code point values within the resource data.  Typically for new
// applications the code page would be the unicode code page.
//

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    uint32 OffsetToData;
    uint32 Size;
    uint32 CodePage;
    uint32 Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

//
// Load Configuration Directory Entry
//

typedef struct {
    uint32 Size;
    uint32 TimeDateStamp;
    uint16 MajorVersion;
    uint16 MinorVersion;
    uint32 GlobalFlagsClear;
    uint32 GlobalFlagsSet;
    uint32 CriticalSectionDefaultTimeout;
    uint32 DeCommitFreeBlockThreshold;
    uint32 DeCommitTotalFreeThreshold;
    uint32 LockPrefixTable; // VA
    uint32 MaximumAllocationSize;
    uint32 VirtualMemoryThreshold;
    uint32 ProcessHeapFlags;
    uint32 ProcessAffinityMask;
    uint16 CSDVersion;
    uint16 Reserved1;
    uint32 EditList;        // VA
    uint32 SecurityCookie;  // VA
    uint32 SEHandlerTable;  // VA
    uint32 SEHandlerCount;
} IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

typedef struct {
    uint32 Size;
    uint32 TimeDateStamp;
    uint16 MajorVersion;
    uint16 MinorVersion;
    uint32 GlobalFlagsClear;
    uint32 GlobalFlagsSet;
    uint32 CriticalSectionDefaultTimeout;
    uint64 DeCommitFreeBlockThreshold;
    uint64 DeCommitTotalFreeThreshold;
    uint64 LockPrefixTable;       // VA
    uint64 MaximumAllocationSize;
    uint64 VirtualMemoryThreshold;
    uint64 ProcessAffinityMask;
    uint32 ProcessHeapFlags;
    uint16 CSDVersion;
    uint16 Reserved1;
    uint64 EditList;        // VA
    uint64 SecurityCookie;  // VA
    uint64 SEHandlerTable;  // VA
    uint64 SEHandlerCount;
} IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

#ifdef _WIN64
typedef IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY;
typedef PIMAGE_LOAD_CONFIG_DIRECTORY64 PIMAGE_LOAD_CONFIG_DIRECTORY;
#else
typedef IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY;
typedef PIMAGE_LOAD_CONFIG_DIRECTORY32 PIMAGE_LOAD_CONFIG_DIRECTORY;
#endif

//
// WIN CE Exception table format
//

//
// Function table entry format.  Function table is pointed to by the
// IMAGE_DIRECTORY_ENTRY_EXCEPTION directory entry.
//

typedef struct _IMAGE_CE_RUNTIME_FUNCTION_ENTRY {
    uint32 FuncStart;
    uint32 PrologLen : 8;
    uint32 FuncLen : 22;
    uint32 ThirtyTwoBit : 1;
    uint32 ExceptionFlag : 1;
} IMAGE_CE_RUNTIME_FUNCTION_ENTRY, *PIMAGE_CE_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY {
    uint64 BeginAddress;
    uint64 EndAddress;
    uint64 ExceptionHandler;
    uint64 HandlerData;
    uint64 PrologEndAddress;
} IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY {
    uint32 BeginAddress;
    uint32 EndAddress;
    uint32 ExceptionHandler;
    uint32 HandlerData;
    uint32 PrologEndAddress;
} IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    uint32 BeginAddress;
    uint32 EndAddress;
    uint32 UnwindInfoAddress;
} _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;

typedef _IMAGE_RUNTIME_FUNCTION_ENTRY IMAGE_IA64_RUNTIME_FUNCTION_ENTRY;
typedef _PIMAGE_RUNTIME_FUNCTION_ENTRY PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY;

#if defined (_AXP64_)

typedef IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY IMAGE_AXP64_RUNTIME_FUNCTION_ENTRY;
typedef PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY PIMAGE_AXP64_RUNTIME_FUNCTION_ENTRY;
typedef IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY IMAGE_RUNTIME_FUNCTION_ENTRY;
typedef PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY PIMAGE_RUNTIME_FUNCTION_ENTRY;

#elif defined (_ALPHA_)

typedef IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY IMAGE_RUNTIME_FUNCTION_ENTRY;
typedef PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY PIMAGE_RUNTIME_FUNCTION_ENTRY;

#else

typedef _IMAGE_RUNTIME_FUNCTION_ENTRY IMAGE_RUNTIME_FUNCTION_ENTRY;
typedef _PIMAGE_RUNTIME_FUNCTION_ENTRY PIMAGE_RUNTIME_FUNCTION_ENTRY;

#endif

//
// Debug Format
//

typedef struct _IMAGE_DEBUG_DIRECTORY {
    uint32 Characteristics;
    uint32 TimeDateStamp;
    uint16 MajorVersion;
    uint16 MinorVersion;
    uint32 Type;
    uint32 SizeOfData;
    uint32 AddressOfRawData;
    uint32 PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

#define IMAGE_DEBUG_TYPE_UNKNOWN          0
#define IMAGE_DEBUG_TYPE_COFF             1
#define IMAGE_DEBUG_TYPE_CODEVIEW         2
#define IMAGE_DEBUG_TYPE_FPO              3
#define IMAGE_DEBUG_TYPE_MISC             4
#define IMAGE_DEBUG_TYPE_EXCEPTION        5
#define IMAGE_DEBUG_TYPE_FIXUP            6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC      7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    8
#define IMAGE_DEBUG_TYPE_BORLAND          9
#define IMAGE_DEBUG_TYPE_RESERVED10       10
#define IMAGE_DEBUG_TYPE_CLSID            11

typedef struct _IMAGE_COFF_SYMBOLS_HEADER {
    uint32 NumberOfSymbols;
    uint32 LvaToFirstSymbol;
    uint32 NumberOfLinenumbers;
    uint32 LvaToFirstLinenumber;
    uint32 RvaToFirstByteOfCode;
    uint32 RvaToLastByteOfCode;
    uint32 RvaToFirstByteOfData;
    uint32 RvaToLastByteOfData;
} IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;

#define FRAME_FPO       0
#define FRAME_TRAP      1
#define FRAME_TSS       2
#define FRAME_NONFPO    3

typedef struct _FPO_DATA {
    uint32 ulOffStart;              // offset 1st byte of function code
    uint32 cbProcSize;              // # bytes in function
    uint32 cdwLocals;               // # bytes in locals/4
    uint16 cdwParams;               // # bytes in params/4
    uint16 cbProlog : 8;            // # bytes in prolog
    uint16 cbRegs : 3;              // # regs saved
    uint16 fHasSEH : 1;             // TRUE if SEH in func
    uint16 fUseBP : 1;              // TRUE if EBP has been allocated
    uint16 reserved : 1;            // reserved for future use
    uint16 cbFrame : 2;             // frame type
} FPO_DATA, *PFPO_DATA;
#define SIZEOF_RFPO_DATA 16

#define IMAGE_DEBUG_MISC_EXENAME    1

typedef struct _IMAGE_DEBUG_MISC {
    uint32 DataType;            // type of misc data, see defines
    uint32 Length;              // total length of record, rounded to four
                                // byte multiple.
    uint32 Unicode;             // TRUE if data is unicode string
    byte_t Reserved[3];
    byte_t Data[1];             // Actual data
} IMAGE_DEBUG_MISC, *PIMAGE_DEBUG_MISC;

//
// Function table extracted from MIPS/ALPHA/IA64 images.  Does not contain
// information needed only for runtime support.  Just those fields for
// each entry needed by a debugger.
//

typedef struct _IMAGE_FUNCTION_ENTRY {
    uint32 StartingAddress;
    uint32 EndingAddress;
    uint32 EndOfPrologue;
} IMAGE_FUNCTION_ENTRY, *PIMAGE_FUNCTION_ENTRY;

typedef struct _IMAGE_FUNCTION_ENTRY64 {
    uint64 StartingAddress;
    uint64 EndingAddress;
    union {
        uint64 EndOfPrologue;
        uint64 UnwindInfoAddress;
    };
} IMAGE_FUNCTION_ENTRY64, *PIMAGE_FUNCTION_ENTRY64;

//
// Debugging information can be stripped from an image file and placed
// in a separate .DBG file, whose file name part is the same as the
// image file name part (e.g. symbols for CMD.EXE could be stripped
// and placed in CMD.DBG).  This is indicated by the IMAGE_FILE_DEBUG_STRIPPED
// flag in the Characteristics field of the file header.  The beginning of
// the .DBG file contains the following structure which captures certain
// information from the image file.  This allows a debug to proceed even if
// the original image file is not accessable.  This header is followed by
// zero of more IMAGE_SECTION_HEADER structures, followed by zero or more
// IMAGE_DEBUG_DIRECTORY structures.  The latter structures and those in
// the image file contain file offsets relative to the beginning of the
// .DBG file.
//
// If symbols have been stripped from an image, the IMAGE_DEBUG_MISC structure
// is left in the image file, but not mapped.  This allows a debugger to
// compute the name of the .DBG file, from the name of the image in the
// IMAGE_DEBUG_MISC structure.
//

typedef struct _IMAGE_SEPARATE_DEBUG_HEADER {
    uint16 Signature;
    uint16 Flags;
    uint16 Machine;
    uint16 Characteristics;
    uint32 TimeDateStamp;
    uint32 CheckSum;
    uint32 ImageBase;
    uint32 SizeOfImage;
    uint32 NumberOfSections;
    uint32 ExportedNamesSize;
    uint32 DebugDirectorySize;
    uint32 SectionAlignment;
    uint32 Reserved[2];
} IMAGE_SEPARATE_DEBUG_HEADER, *PIMAGE_SEPARATE_DEBUG_HEADER;

typedef struct _NON_PAGED_DEBUG_INFO {
    uint16 Signature;
    uint16 Flags;
    uint32 Size;
    uint16 Machine;
    uint16 Characteristics;
    uint32 TimeDateStamp;
    uint32 CheckSum;
    uint32 SizeOfImage;
    uint64 ImageBase;
    //DebugDirectorySize
    //IMAGE_DEBUG_DIRECTORY
} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;

#ifndef _MAC
#define IMAGE_SEPARATE_DEBUG_SIGNATURE 0x4944
#define NON_PAGED_DEBUG_SIGNATURE      0x494E
#else
#define IMAGE_SEPARATE_DEBUG_SIGNATURE 0x4449   // DI
#define NON_PAGED_DEBUG_SIGNATURE      0x4E49   // NI
#endif

#define IMAGE_SEPARATE_DEBUG_FLAGS_MASK 0x8000
#define IMAGE_SEPARATE_DEBUG_MISMATCH   0x8000  // when DBG was updated, the
// old checksum didn't match.

//
//  The .arch section is made up of headers, each describing an amask position/value
//  pointing to an array of IMAGE_ARCHITECTURE_ENTRY's.  Each "array" (both the header
//  and entry arrays) are terminiated by a quadword of 0xffffffffL.
//
//  NOTE: There may be quadwords of 0 sprinkled around and must be skipped.
//

typedef struct _ImageArchitectureHeader {
    unsigned int AmaskValue : 1;                // 1 -> code section depends on mask bit
                                                // 0 -> new instruction depends on mask bit
    int : 7;                                    // MBZ
    unsigned int AmaskShift : 8;                // Amask bit in question for this fixup
    int : 16;                                   // MBZ
    uint32 FirstEntryRVA;                       // RVA into .arch section to array of ARCHITECTURE_ENTRY's
} IMAGE_ARCHITECTURE_HEADER, *PIMAGE_ARCHITECTURE_HEADER;

typedef struct _ImageArchitectureEntry {
    uint32 FixupInstRVA;                            // RVA of instruction to fixup
    uint32 NewInst;                                 // fixup instruction (see alphaops.h)
} IMAGE_ARCHITECTURE_ENTRY, *PIMAGE_ARCHITECTURE_ENTRY;

// The following structure defines the new import object.  Note the values of the first two fields,
// which must be set as stated in order to differentiate old and new import members.
// Following this structure, the linker emits two null-terminated strings used to recreate the
// import at the time of use.  The first string is the import's name, the second is the dll's name.

#define IMPORT_OBJECT_HDR_SIG2  0xffff

typedef struct IMPORT_OBJECT_HEADER {
    uint16 Sig1;                        // Must be IMAGE_FILE_MACHINE_UNKNOWN
    uint16 Sig2;                        // Must be IMPORT_OBJECT_HDR_SIG2.
    uint16 Version;
    uint16 Machine;
    uint32 TimeDateStamp;               // Time/date stamp
    uint32 SizeOfData;                  // particularly useful for incremental links

    union {
        uint16 Ordinal;                 // if grf & IMPORT_OBJECT_ORDINAL
        uint16 Hint;
    };

    uint16 Type : 2;                    // IMPORT_TYPE
    uint16 NameType : 3;                // IMPORT_NAME_TYPE
    uint16 Reserved : 11;               // Reserved. Must be zero.
} IMPORT_OBJECT_HEADER;

typedef enum IMPORT_OBJECT_TYPE {
    IMPORT_OBJECT_CODE  = 0,
    IMPORT_OBJECT_DATA  = 1,
    IMPORT_OBJECT_CONST = 2,
} IMPORT_OBJECT_TYPE;

typedef enum IMPORT_OBJECT_NAME_TYPE {
    IMPORT_OBJECT_ORDINAL           = 0,    // Import by ordinal
    IMPORT_OBJECT_NAME              = 1,    // Import name == public symbol name.
    IMPORT_OBJECT_NAME_NO_PREFIX    = 2,    // Import name == public symbol name skipping leading ?, @, or optionally _.
    IMPORT_OBJECT_NAME_UNDECORATE   = 3,    // Import name == public symbol name skipping leading ?, @, or optionally _
                                            // and truncating at first @
} IMPORT_OBJECT_NAME_TYPE;

#pragma pack(pop)

namespace hotplace {
namespace io {

}
}  // namespace

#endif
