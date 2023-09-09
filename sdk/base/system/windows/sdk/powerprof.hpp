/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab textwidth=130 colorcolumn=+1: */
/**
 * @file powerprof.h
 * @author Soo Han, Kim (hush@ahnlab.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_POWERPROF__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_POWERPROF__

#include <powrprof.h>

/* "GetPwrDiskSpindownRange" */
#define DECLARE_NAMEOF_API_GETPWRDISKSPINDOWNRANGE char NAMEOF_API_GETPWRDISKSPINDOWNRANGE[] = { 'G', 'e', 't', 'P', 'w', 'r', 'D', 'i', 's', 'k', 'S', 'p', 'i', 'n', 'd', 'o', 'w', 'n', 'R', 'a', 'n', 'g', 'e', 0, };
/* "EnumPwrSchemes" */
#define DECLARE_NAMEOF_API_ENUMPWRSCHEMES char NAMEOF_API_ENUMPWRSCHEMES[] = { 'E', 'n', 'u', 'm', 'P', 'w', 'r', 'S', 'c', 'h', 'e', 'm', 'e', 's', 0, };
/* "ReadGlobalPwrPolicy" */
#define DECLARE_NAMEOF_API_READGLOBALPWRPOLICY char NAMEOF_API_READGLOBALPWRPOLICY[] = { 'R', 'e', 'a', 'd', 'G', 'l', 'o', 'b', 'a', 'l', 'P', 'w', 'r', 'P', 'o', 'l', 'i', 'c', 'y', 0, };
/* "ReadPwrScheme" */
#define DECLARE_NAMEOF_API_READPWRSCHEME char NAMEOF_API_READPWRSCHEME[] = { 'R', 'e', 'a', 'd', 'P', 'w', 'r', 'S', 'c', 'h', 'e', 'm', 'e', 0, };
/* "WritePwrScheme" */
#define DECLARE_NAMEOF_API_WRITEPWRSCHEME char NAMEOF_API_WRITEPWRSCHEME[] = { 'W', 'r', 'i', 't', 'e', 'P', 'w', 'r', 'S', 'c', 'h', 'e', 'm', 'e', 0, };
/* "WriteGlobalPwrPolicy" */
#define DECLARE_NAMEOF_API_WRITEGLOBALPWRPOLICY char NAMEOF_API_WRITEGLOBALPWRPOLICY[] = { 'W', 'r', 'i', 't', 'e', 'G', 'l', 'o', 'b', 'a', 'l', 'P', 'w', 'r', 'P', 'o', 'l', 'i', 'c', 'y', 0, };
/* "DeletePwrScheme" */
#define DECLARE_NAMEOF_API_DELETEPWRSCHEME char NAMEOF_API_DELETEPWRSCHEME[] = { 'D', 'e', 'l', 'e', 't', 'e', 'P', 'w', 'r', 'S', 'c', 'h', 'e', 'm', 'e', 0, };
/* "GetActivePwrScheme" */
#define DECLARE_NAMEOF_API_GETACTIVEPWRSCHEME char NAMEOF_API_GETACTIVEPWRSCHEME[] = { 'G', 'e', 't', 'A', 'c', 't', 'i', 'v', 'e', 'P', 'w', 'r', 'S', 'c', 'h', 'e', 'm', 'e', 0, };
/* "SetActivePwrScheme" */
#define DECLARE_NAMEOF_API_SETACTIVEPWRSCHEME char NAMEOF_API_SETACTIVEPWRSCHEME[] = { 'S', 'e', 't', 'A', 'c', 't', 'i', 'v', 'e', 'P', 'w', 'r', 'S', 'c', 'h', 'e', 'm', 'e', 0, };
/* "GetPwrCapabilities" */
#define DECLARE_NAMEOF_API_GETPWRCAPABILITIES char NAMEOF_API_GETPWRCAPABILITIES[] = { 'G', 'e', 't', 'P', 'w', 'r', 'C', 'a', 'p', 'a', 'b', 'i', 'l', 'i', 't', 'i', 'e', 's', 0, };
/* "IsPwrSuspendAllowed" */
#define DECLARE_NAMEOF_API_ISPWRSUSPENDALLOWED char NAMEOF_API_ISPWRSUSPENDALLOWED[] = { 'I', 's', 'P', 'w', 'r', 'S', 'u', 's', 'p', 'e', 'n', 'd', 'A', 'l', 'l', 'o', 'w', 'e', 'd', 0, };
/* "IsPwrHibernateAllowed" */
#define DECLARE_NAMEOF_API_ISPWRHIBERNATEALLOWED char NAMEOF_API_ISPWRHIBERNATEALLOWED[] = { 'I', 's', 'P', 'w', 'r', 'H', 'i', 'b', 'e', 'r', 'n', 'a', 't', 'e', 'A', 'l', 'l', 'o', 'w', 'e', 'd', 0, };
/* "IsPwrShutdownAllowed" */
#define DECLARE_NAMEOF_API_ISPWRSHUTDOWNALLOWED char NAMEOF_API_ISPWRSHUTDOWNALLOWED[] = { 'I', 's', 'P', 'w', 'r', 'S', 'h', 'u', 't', 'd', 'o', 'w', 'n', 'A', 'l', 'l', 'o', 'w', 'e', 'd', 0, };
/* "IsAdminOverrideActive" */
//#define DECLARE_NAMEOF_API_ISADMINOVERRIDEACTIVE char NAMEOF_API_ISADMINOVERRIDEACTIVE[] = { 'I', 's', 'A', 'd', 'm', 'i', 'n', 'O', 'v', 'e', 'r', 'r', 'i', 'd', 'e', 'A', 'c', 't', 'i', 'v', 'e', 0, };
/* "SetSuspendState" */
#define DECLARE_NAMEOF_API_SETSUSPENDSTATE char NAMEOF_API_SETSUSPENDSTATE[] = { 'S', 'e', 't', 'S', 'u', 's', 'p', 'e', 'n', 'd', 'S', 't', 'a', 't', 'e', 0, };
/* "GetCurrentPowerPolicies" */
#define DECLARE_NAMEOF_API_GETCURRENTPOWERPOLICIES char NAMEOF_API_GETCURRENTPOWERPOLICIES[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'o', 'w', 'e', 'r', 'P', 'o', 'l', 'i', 'c', 'i', 'e', 's', 0, };
/* "CanUserWritePwrScheme" */
#define DECLARE_NAMEOF_API_CANUSERWRITEPWRSCHEME char NAMEOF_API_CANUSERWRITEPWRSCHEME[] = { 'C', 'a', 'n', 'U', 's', 'e', 'r', 'W', 'r', 'i', 't', 'e', 'P', 'w', 'r', 'S', 'c', 'h', 'e', 'm', 'e', 0, };
/* "ReadProcessorPwrScheme" */
#define DECLARE_NAMEOF_API_READPROCESSORPWRSCHEME char NAMEOF_API_READPROCESSORPWRSCHEME[] = { 'R', 'e', 'a', 'd', 'P', 'r', 'o', 'c', 'e', 's', 's', 'o', 'r', 'P', 'w', 'r', 'S', 'c', 'h', 'e', 'm', 'e', 0, };
/* "WriteProcessorPwrScheme" */
#define DECLARE_NAMEOF_API_WRITEPROCESSORPWRSCHEME char NAMEOF_API_WRITEPROCESSORPWRSCHEME[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'o', 'r', 'P', 'w', 'r', 'S', 'c', 'h', 'e', 'm', 'e', 0, };
/* "ValidatePowerPolicies" */
//#define DECLARE_NAMEOF_API_VALIDATEPOWERPOLICIES char NAMEOF_API_VALIDATEPOWERPOLICIES[] = { 'V', 'a', 'l', 'i', 'd', 'a', 't', 'e', 'P', 'o', 'w', 'e', 'r', 'P', 'o', 'l', 'i', 'c', 'i', 'e', 's', 0, };

/* @brief
    [GetPwrDiskSpindownRange is available for use in the operating systems specified in the Requirements section. It may be altered or unavailable in subsequent versions.]
    Retrieves the disk spindown range.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * GETPWRDISKSPINDOWNRANGE)(PUINT, PUINT);
/* @brief
    [EnumPwrSchemes is available for use in the operating systems specified in the Requirements section. It may be altered or unavailable in subsequent versions. Applications written for Windows Vista and later should use PowerEnumerate instead.]
    Enumerates all power schemes. For each power scheme enumerated, the function calls a callback function with information about the power scheme.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * ENUMPWRSCHEMES)(PWRSCHEMESENUMPROC, LPARAM);
/* @brief
    [ReadGlobalPwrPolicy is available for use in the operating systems specified in the Requirements section. It may be altered or unavailable in subsequent versions.]
    Retrieves the current global power policy settings.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * READGLOBALPWRPOLICY)(PGLOBAL_POWER_POLICY);
/* @brief
    [ReadPwrScheme is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions.]
    Retrieves the power policy settings that are unique to the specified power scheme.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * READPWRSCHEME)(UINT, PPOWER_POLICY);
/* @brief
    [WritePwrScheme is no longer available for use as of Windows Vista.
    Instead, use the PowerEnumerate function to enumerate power settings for a specified scheme, and the power write functions to write individual settings.]
    Writes policy settings that are unique to the specified power scheme.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * WRITEPWRSCHEME)(PUINT, LPTSTR, LPTSTR, PPOWER_POLICY);
/* @brief
    [WriteGlobalPwrPolicy is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions.]
    Writes global power policy settings.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * WRITEGLOBALPWRPOLICY)(PGLOBAL_POWER_POLICY);
/* @brief
    [DeletePwrScheme is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions. Applications written for Windows Vista and later should use PowerDeleteScheme instead.]
    Deletes the specified power scheme.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * DELETEPWRSCHEME)(UINT);
/* @brief
    [GetActivePwrScheme is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions. Applications written for Windows Vista and later should use PowerGetActiveScheme instead.]
    Retrieves the index of the active power scheme.
   @comment
    see PowerControl
 */
typedef BOOLEAN (WINAPI * GETACTIVEPWRSCHEME)(PUINT);
/* @brief
    [SetActivePwrScheme is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions. Applications written for Windows Vista and later should use PowerSetActiveScheme instead.]
    Sets the active power scheme.
   @comment
    see PowerControl
 */
typedef BOOLEAN (WINAPI * SETACTIVEPWRSCHEME)(UINT, PGLOBAL_POWER_POLICY, PPOWER_POLICY);
/* @brief
    Retrieves information about the system power capabilities.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * GETPWRCAPABILITIES)(PSYSTEM_POWER_CAPABILITIES);
/* @brief
    [IsPwrSuspendAllowed is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions. Applications written for Windows Vista and later should use GetPwrCapabilities instead.]
    Determines whether the computer supports the sleep states.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * ISPWRSUSPENDALLOWED)(VOID);
/* @brief
    [IsPwrHibernateAllowed is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions. Applications written for Windows Vista and later should use GetPwrCapabilities instead.]
    Determines whether the computer supports hibernation.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * ISPWRHIBERNATEALLOWED)(VOID);
/* @brief
    [IsPwrShutdownAllowed is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions.]
    Determines whether the computer supports the soft off power state.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * ISPWRSHUTDOWNALLOWED)(VOID);
/* @brief
 */
//typedef BOOLEAN (WINAPI * ISADMINOVERRIDEACTIVE)(PADMINISTRATOR_POWER_POLICY);
/* @brief
    Suspends the system by shutting power down. Depending on the Hibernate parameter, the system either enters a suspend (sleep) state or hibernation (S4).
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * SETSUSPENDSTATE)(BOOLEAN, BOOLEAN, BOOLEAN);
/* @brief
    Retrieves the current system power policy settings.
   @comment
    see PowerControl
 */
typedef BOOLEAN (WINAPI * GETCURRENTPOWERPOLICIES)(PGLOBAL_POWER_POLICY, PPOWER_POLICY);
/* @brief
    [CanUserWritePwrScheme is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions. Applications written for Windows Vista and later should use PowerSettingAccessCheck instead.]
    Determines whether the current user has sufficient privilege to write a power scheme.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * CANUSERWRITEPWRSCHEME)(VOID);
/* @brief
    [ReadProcessorPwrScheme is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions.]
    Retrieves the processor power policy settings for the specified power scheme.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * READPROCESSORPWRSCHEME)(UINT, PMACHINE_PROCESSOR_POWER_POLICY);
/* @brief
    [WriteProcessorPwrScheme is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions.]
    Writes processor power policy settings for the specified power scheme.
   @comment
    사용하지 않음
 */
typedef BOOLEAN (WINAPI * WRITEPROCESSORPWRSCHEME)(UINT, PMACHINE_PROCESSOR_POWER_POLICY);

#if _MSC_FULL_VER >= 140050727
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
#else
#define DEFINE_POWER_DATA_ACCESSOR
#endif
#else
#define DEFINE_POWER_DATA_ACCESSOR
#endif

#if defined DEFINE_POWER_DATA_ACCESSOR
/* Vista, 2008 */

#ifndef __MINGW32__
typedef enum _POWER_DATA_ACCESSOR {
    //
    // Used by read/write and enumeration engines
    //
    ACCESS_AC_POWER_SETTING_INDEX = 0,
    ACCESS_DC_POWER_SETTING_INDEX,
    ACCESS_FRIENDLY_NAME,
    ACCESS_DESCRIPTION,
    ACCESS_POSSIBLE_POWER_SETTING,
    ACCESS_POSSIBLE_POWER_SETTING_FRIENDLY_NAME,
    ACCESS_POSSIBLE_POWER_SETTING_DESCRIPTION,
    ACCESS_DEFAULT_AC_POWER_SETTING,
    ACCESS_DEFAULT_DC_POWER_SETTING,
    ACCESS_POSSIBLE_VALUE_MIN,
    ACCESS_POSSIBLE_VALUE_MAX,
    ACCESS_POSSIBLE_VALUE_INCREMENT,
    ACCESS_POSSIBLE_VALUE_UNITS,
    ACCESS_ICON_RESOURCE,
    ACCESS_DEFAULT_SECURITY_DESCRIPTOR,
    ACCESS_ATTRIBUTES,

    //
    // Used by enumeration engine.
    //
    ACCESS_SCHEME = 16,
    ACCESS_SUBGROUP,
    ACCESS_INDIVIDUAL_SETTING,

    //
    // Used by access check
    //
    ACCESS_ACTIVE_SCHEME,
    ACCESS_CREATE_SCHEME

} POWER_DATA_ACCESSOR, *PPOWER_DATA_ACCESSOR;
#endif

#endif

/* "PowerGetActiveScheme" */
#define DECLARE_NAMEOF_API_POWERGETACTIVESCHEME char NAMEOF_API_POWERGETACTIVESCHEME[] = { 'P', 'o', 'w', 'e', 'r', 'G', 'e', 't', 'A', 'c', 't', 'i', 'v', 'e', 'S', 'c', 'h', 'e', 'm', 'e', 0, };
/* "PowerEnumerate" */
#define DECLARE_NAMEOF_API_POWERENUMERATE char NAMEOF_API_POWERENUMERATE[] = { 'P', 'o', 'w', 'e', 'r', 'E', 'n', 'u', 'm', 'e', 'r', 'a', 't', 'e', 0, };
/* "PowerReadFriendlyName" */
#define DECLARE_NAMEOF_API_POWERREADFRIENDLYNAME char NAMEOF_API_POWERREADFRIENDLYNAME[] = { 'P', 'o', 'w', 'e', 'r', 'R', 'e', 'a', 'd', 'F', 'r', 'i', 'e', 'n', 'd', 'l', 'y', 'N', 'a', 'm', 'e', 0, };
/* "PowerReadACValue" */
#define DECLARE_NAMEOF_API_POWERREADACVALUE char NAMEOF_API_POWERREADACVALUE[] = { 'P', 'o', 'w', 'e', 'r', 'R', 'e', 'a', 'd', 'A', 'C', 'V', 'a', 'l', 'u', 'e', 0, };
/* "PowerReadDCValue" */
#define DECLARE_NAMEOF_API_POWERREADDCVALUE char NAMEOF_API_POWERREADDCVALUE[] = { 'P', 'o', 'w', 'e', 'r', 'R', 'e', 'a', 'd', 'D', 'C', 'V', 'a', 'l', 'u', 'e', 0, };
/* "PowerReadACValueIndex" */
#define DECLARE_NAMEOF_API_POWERREADACVALUEINDEX char NAMEOF_API_POWERREADACVALUEINDEX[] = { 'P', 'o', 'w', 'e', 'r', 'R', 'e', 'a', 'd', 'A', 'C', 'V', 'a', 'l', 'u', 'e', 'I', 'n', 'd', 'e', 'x', 0, };
/* "PowerWriteACValueIndex" */
#define DECLARE_NAMEOF_API_POWERWRITEACVALUEINDEX char NAMEOF_API_POWERWRITEACVALUEINDEX[] = { 'P', 'o', 'w', 'e', 'r', 'W', 'r', 'i', 't', 'e', 'A', 'C', 'V', 'a', 'l', 'u', 'e', 'I', 'n', 'd', 'e', 'x', 0, };
/* "PowerWriteDCValueIndex" */
#define DECLARE_NAMEOF_API_POWERWRITEDCVALUEINDEX char NAMEOF_API_POWERWRITEDCVALUEINDEX[] = { 'P', 'o', 'w', 'e', 'r', 'W', 'r', 'i', 't', 'e', 'D', 'C', 'V', 'a', 'l', 'u', 'e', 'I', 'n', 'd', 'e', 'x', 0, };
/* "PowerSetActiveScheme" */
#define DECLARE_NAMEOF_API_POWERSETACTIVESCHEME char NAMEOF_API_POWERSETACTIVESCHEME[] = { 'P', 'o', 'w', 'e', 'r', 'S', 'e', 't', 'A', 'c', 't', 'i', 'v', 'e', 'S', 'c', 'h', 'e', 'm', 'e', 0, };
/* CallNtPowerInformation */
#define DECLARE_NAMEOF_API_CALLNTPOWERINFORMATION char NAMEOF_API_CALLNTPOWERINFORMATION[] = { _T ('C'), _T ('a'), _T ('l'), _T ('l'), _T ('N'), _T ('t'), _T ('P'), _T ('o'), _T ('w'), _T ('e'), _T ('r'), _T ('I'), _T ('n'), _T ('f'), _T ('o'), _T ('r'), _T ('m'), _T ('a'), _T ('t'), _T ('i'), _T ('o'), _T ('n'), 0, };
/* PowerSettingRegisterNotification */
#define DECLARE_NAMEOF_API_POWERSETTINGREGISTERNOTIFICATION char NAMEOF_API_POWERSETTINGREGISTERNOTIFICATION[] = { _T ('P'), _T ('o'), _T ('w'), _T ('e'), _T ('r'), _T ('S'), _T ('e'), _T ('t'), _T ('t'), _T ('i'), _T ('n'), _T ('g'), _T ('R'), _T ('e'), _T ('g'), _T ('i'), _T ('s'), _T ('t'), _T ('e'), _T ('r'), _T ('N'), _T ('o'), _T ('t'), _T ('i'), _T ('f'), _T ('i'), _T ('c'), _T ('a'), _T ('t'), _T ('i'), _T ('o'), _T ('n'), 0, };
/* PowerSettingUnregisterNotification */
#define DECLARE_NAMEOF_API_POWERSETTINGUNREGISTERNOTIFICATION char NAMEOF_API_POWERSETTINGUNREGISTERNOTIFICATION[] = { _T ('P'), _T ('o'), _T ('w'), _T ('e'), _T ('r'), _T ('S'), _T ('e'), _T ('t'), _T ('t'), _T ('i'), _T ('n'), _T ('g'), _T ('U'), _T ('n'), _T ('r'), _T ('e'), _T ('g'), _T ('i'), _T ('s'), _T ('t'), _T ('e'), _T ('r'), _T ('N'), _T ('o'), _T ('t'), _T ('i'), _T ('f'), _T ('i'), _T ('c'), _T ('a'), _T ('t'), _T ('i'), _T ('o'), _T ('n'), 0, };

/* @brief   PowerGetActiveScheme
 */
typedef DWORD (WINAPI * POWERGETACTIVESCHEME)(HKEY UserRootPowerKey, GUID **ActivePolicyGuid);
/* @brief   PowerEnumerate
 */
typedef DWORD (WINAPI * POWERENUMERATE)(HKEY RootPowerKey, const GUID *SchemeGuid, const GUID *SubGroupOfPowerSettingsGuid, POWER_DATA_ACCESSOR AccessFlags, ULONG Index, UCHAR *Buffer, DWORD *BufferSize);
/* @brief   PowerReadFriendlyName
 */
typedef DWORD (WINAPI * POWERREADFRIENDLYNAME)(HKEY RootPowerKey, const GUID *SchemeGuid, const GUID *SubGroupOfPowerSettingsGuid, const GUID *PowerSettingGuid, PUCHAR Buffer, LPDWORD BufferSize);
/* @brief   PowerReadACValue
 */
typedef DWORD (WINAPI * POWERREADACVALUE)(HKEY RootPowerKey, const GUID *SchemeGuid, const GUID *SubGroupOfPowerSettingsGuid, const GUID *PowerSettingGuid, PULONG Type, LPBYTE Buffer, LPDWORD BufferSize);
/* @brief   PowerReadDCValue
 */
typedef DWORD (WINAPI * POWERREADDCVALUE)(HKEY RootPowerKey, const GUID *SchemeGuid, const GUID *SubGroupOfPowerSettingsGuid, const GUID *PowerSettingGuid, PULONG Type, LPBYTE Buffer, LPDWORD BufferSize);
/* @brief   PowerReadACValueIndex
 */
typedef DWORD (WINAPI * POWERREADACVALUEINDEX)(HKEY RootPowerKey, const GUID *SchemeGuid, const GUID *SubGroupOfPowerSettingsGuid, const GUID *PowerSettingGuid, LPDWORD AcValueIndex);
/* @brief   PowerWriteDCValueIndex
 */
typedef DWORD (WINAPI * POWERWRITEDCVALUEINDEX)(HKEY RootPowerKey, const GUID *SchemeGuid, const GUID *SubGroupOfPowerSettingsGuid, const GUID *PowerSettingGuid, DWORD DcValueIndex);
/* @brief   PowerWriteACValueIndex
 */
typedef DWORD (WINAPI * POWERWRITEACVALUEINDEX)(HKEY RootPowerKey, const GUID *SchemeGuid, const GUID *SubGroupOfPowerSettingsGuid, const GUID *PowerSettingGuid, DWORD DcValueIndex);
/* @brief   PowerSetActiveScheme
 */
typedef DWORD (WINAPI * POWERSETACTIVESCHEME)(HKEY UserRootPowerKey, const GUID *SchemeGuid);
/* @brief   CallNtPowerInformation
 */
typedef DWORD (WINAPI * CALLNTPOWERINFORMATION)(POWER_INFORMATION_LEVEL InformationLevel, PVOID lpInputBuffer, ULONG nInputBufferSize, PVOID lpOutputBuffer, ULONG nOutputBufferSize);
#if _MSC_FULL_VER >= 140050727
#else
typedef PVOID HPOWERNOTIFY;
typedef HPOWERNOTIFY *PHPOWERNOTIFY;
#endif
/* @brief   PowerSettingRegisterNotification
 */
typedef DWORD (WINAPI * POWERSETTINGREGISTERNOTIFICATION)(LPCGUID SettingGuid, DWORD dwFlags, HANDLE Recipient, PHPOWERNOTIFY RegistrationHandle);
/* @brief   PowerSettingUnregisterNotification
 */
typedef DWORD (WINAPI * POWERSETTINGUNREGISTERNOTIFICATION)(HPOWERNOTIFY Handle);

#endif
