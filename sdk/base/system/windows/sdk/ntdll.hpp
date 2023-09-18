/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_NTDLL__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_NTDLL__

typedef LONG NTSTATUS;
#include <winternl.h>

/* "NtQueryInformationProcess" */
#define DECLARE_NAMEOF_API_NTQUERYINFORMATIONPROCESS CHAR NAMEOF_API_NTQUERYINFORMATIONPROCESS[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 0, };

/* @brief
    [NtQueryInformationProcess may be altered or unavailable in future versions of Windows. Applications should use the alternate functions listed in this topic.]
    Retrieves information about the specified process.
 */
typedef NTSTATUS (__stdcall *NTQUERYINFORMATIONPROCESS)(HANDLE, UINT, PVOID, ULONG, PULONG);

/* "VerSetConditionMask" */
#define DECLARE_NAMEOF_API_VERSETCONDITIONMASK CHAR NAMEOF_API_VERSETCONDITIONMASK[] = { 'V', 'e', 'r', 'S', 'e', 't', 'C', 'o', 'n', 'd', 'i', 't', 'i', 'o', 'n', 'M', 'a', 's', 'k', 0, };

/* @brief
    Sets the bits of a 64-bit value to indicate the comparison operator to use for a specified operating system version attribute.
    This function is used to build the dwlConditionMask parameter of the VerifyVersionInfo function.
 */
typedef ULONGLONG (__stdcall *VERSETCONDITIONMASK)(ULONGLONG, ULONG, UCHAR);

/* "NtSetInformationThread" */
#define DECLARE_NAMEOF_API_NTSETINFORMATIONTHREAD CHAR NAMEOF_API_NTSETINFORMATIONTHREAD[] = { 'N', 't', 'S', 'e', 't', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'T', 'h', 'r', 'e', 'a', 'd', 0, };

typedef NTSTATUS (__stdcall *NTSETINFORMATIONTHREAD)(HANDLE, UINT, PVOID, ULONG);

typedef enum _SECTION_INHERIT {
    ViewShare   = 1,
    ViewUnmap   = 2
} SECTION_INHERIT;

#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L


#if (_MSC_FULL_VER >= 140050727) // Visual Studio 6.0

#else

#if (_WIN32_WINNT >= 0x0500)
#else

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is (MaximumLength / 2), length_is ((Length) / 2) ] USHORT * Buffer;
#else           // MIDL_PASS
    PWSTR Buffer;
#endif          // MIDL_PASS
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;               // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;         // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#endif      // _WIN32_WINNT >= 0x0500

#endif      // Visual Studio 6.0

#ifndef __MINGW32__
#define InitializeObjectAttributes( p, n, a, r, s ) { \
        (p)->Length = sizeof ( OBJECT_ATTRIBUTES );   \
        (p)->RootDirectory = r;                       \
        (p)->Attributes = a;                          \
        (p)->ObjectName = n;                          \
        (p)->SecurityDescriptor = s;                  \
        (p)->SecurityQualityOfService = nullptr;      \
}
#endif

/* "NtUnmapViewOfSection" */
#define DECLARE_NAMEOF_API_NTUNMAPVIEWOFSECTION CHAR NAMEOF_API_NTUNMAPVIEWOFSECTION[] = { 'N', 't', 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0, };
/* "NtOpenSection" */
#define DECLARE_NAMEOF_API_NTOPENSECTION CHAR NAMEOF_API_NTOPENSECTION[] = { 'N', 't', 'O', 'p', 'e', 'n', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0, };
/* "NtMapViewOfSection" */
#define DECLARE_NAMEOF_API_NTMAPVIEWOFSECTION CHAR NAMEOF_API_NTMAPVIEWOFSECTION[] = { 'N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0, };
/* "RtlInitUnicodeString" */
#define DECLARE_NAMEOF_API_RTLINITUNICODESTRING CHAR NAMEOF_API_RTLINITUNICODESTRING[] = { 'R', 't', 'l', 'I', 'n', 'i', 't', 'U', 'n', 'i', 'c', 'o', 'd', 'e', 'S', 't', 'r', 'i', 'n', 'g', 0, };
/* "RtlNtStatusToDosError" */
#define DECLARE_NAMEOF_API_RTLNTSTATUSTODOSERROR CHAR NAMEOF_API_RTLNTSTATUSTODOSERROR[] = { 'R', 't', 'l', 'N', 't', 'S', 't', 'a', 't', 'u', 's', 'T', 'o', 'D', 'o', 's', 'E', 'r', 'r', 'o', 'r', 0, };

/* @brief
    The ZwUnmapViewOfSection routine unmaps a view of a section from the virtual address space of a subject process.
    Note
    If the call to this function occurs in user mode, you should use the name "NtUnmapViewOfSection" instead of "ZwUnmapViewOfSection".
 */
typedef NTSTATUS (__stdcall *NTUNMAPVIEWOFSECTION)
(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
);

/* @brief
    The ZwOpenSection routine opens a handle for an existing section object.
    Note
    If the call to this function occurs in user mode, you should use the name "NtOpenSection" instead of "ZwOpenSection".
 */
typedef NTSTATUS (__stdcall *NTOPENSECTION)
(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);

/* @brief
    The ZwMapViewOfSection routine maps a view of a section into the virtual address space of a subject process.
    Note
    If the call to this function occurs in user mode, you should use the name "NtMapViewOfSection" instead of "ZwMapViewOfSection".
 */
typedef NTSTATUS (__stdcall *NTMAPVIEWOFSECTION)
(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG ZeroBits,
    IN ULONG CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset,
    IN OUT PULONG ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Protect
);

/* @brief
    The RtlInitUnicodeString routine is obsolete and is exported only to support existing driver binaries.
    Drivers should use the safe-string routines RtlUnicodeStringInit and RtlUnicodeStringInitEx instead.
 */
typedef VOID (__stdcall *RTLINITUNICODESTRING)
(
    IN OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString
);

/* @brief
    Converts the specified NTSTATUS code to its equivalent system error code.
 */
typedef ULONG (__stdcall *RTLNTSTATUSTODOSERROR)
(
    IN NTSTATUS Status
);

/* "NtQuerySystemInformation" */
#define DECLARE_NAMEOF_API_NTQUERYSYSTEMINFORMATION CHAR NAMEOF_API_NTQUERYSYSTEMINFORMATION[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 0, };
/* "NtDuplicateObject" */
#define DECLARE_NAMEOF_API_NTDUPLICATEOBJECT CHAR NAMEOF_API_NTDUPLICATEOBJECT[] = { 'N', 't', 'D', 'u', 'p', 'l', 'i', 'c', 'a', 't', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0, };
/* "NtQueryObject" */
#define DECLARE_NAMEOF_API_NTQUERYOBJECT CHAR NAMEOF_API_NTQUERYOBJECT[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'O', 'b', 'j', 'e', 'c', 't', 0, };

/* @brief
    [NtQuerySystemInformation may be altered or unavailable in future versions of Windows. Applications should use the alternate functions listed in this topic.]
    Retrieves the specified system information.
 */
typedef NTSTATUS (__stdcall *NTQUERYSYSTEMINFORMATION)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
/* @brief
    The ZwDuplicateObject routine creates a handle that is a duplicate of the specified source handle.
    If the call to this function occurs in user mode, you should use the name "NtDuplicateObject" instead of "ZwDuplicateObject".
 */
typedef NTSTATUS (__stdcall *NTDUPLICATEOBJECT)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
/* @brief
    The ZwQueryObject routine provides information about a supplied object.
    If the call to the ZwQueryObject function occurs in user mode, you should use the name "NtQueryObject" instead of "ZwQueryObject".
 */
typedef NTSTATUS (__stdcall *NTQUERYOBJECT)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

#endif
