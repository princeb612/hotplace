/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab textwidth=130 colorcolumn=+1: */
/**
 * @file setupapi.h
 * @author Soo Han, Kim (hush@ahnlab.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_SETUPAPI__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_SETUPAPI__

#include <setupapi.h>

/* SetupDiGetClassDevsA, SetupDiGetClassDevsW */
#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_SETUPDIGETCLASSDEVS  DECLARE_NAMEOF_API_SETUPDIGETCLASSDEVSA
#define NAMEOF_API_SETUPDIGETCLASSDEVS          NAMEOF_API_SETUPDIGETCLASSDEVSA
#define SETUPDIGETCLASSDEVS                     SETUPDIGETCLASSDEVSA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_SETUPDIGETCLASSDEVS  DECLARE_NAMEOF_API_SETUPDIGETCLASSDEVSW
#define NAMEOF_API_SETUPDIGETCLASSDEVS          NAMEOF_API_SETUPDIGETCLASSDEVSW
#define SETUPDIGETCLASSDEVS                     SETUPDIGETCLASSDEVSW
#endif

#define DECLARE_NAMEOF_API_SETUPDIGETCLASSDEVSA CHAR NAMEOF_API_SETUPDIGETCLASSDEVSA[] = { 'S', 'e', 't', 'u', 'p', 'D', 'i', 'G', 'e', 't', 'C', 'l', 'a', 's', 's', 'D', 'e', 'v', 's', 'A', 0, };
#define DECLARE_NAMEOF_API_SETUPDIGETCLASSDEVSW CHAR NAMEOF_API_SETUPDIGETCLASSDEVSW[] = { 'S', 'e', 't', 'u', 'p', 'D', 'i', 'G', 'e', 't', 'C', 'l', 'a', 's', 's', 'D', 'e', 'v', 's', 'W', 0, };

typedef HDEVINFO (__stdcall* SETUPDIGETCLASSDEVSA)(
    __in_opt CONST GUID *ClassGuid,
    __in_opt PCSTR Enumerator,
    __in_opt HWND hwndParent,
    ___in DWORD Flags
    );

typedef HDEVINFO (__stdcall* SETUPDIGETCLASSDEVSW)(
    __in_opt CONST GUID *ClassGuid,
    __in_opt PCWSTR Enumerator,
    __in_opt HWND hwndParent,
    ___in DWORD Flags
    );

/* SetupDiEnumDeviceInfo */
#define DECLARE_NAMEOF_API_SETUPDIENUMDEVICEINFO CHAR NAMEOF_API_SETUPDIENUMDEVICEINFO[] = { 'S', 'e', 't', 'u', 'p', 'D', 'i', 'E', 'n', 'u', 'm', 'D', 'e', 'v', 'i', 'c', 'e', 'I', 'n', 'f', 'o', 0, };

typedef BOOL (__stdcall* SETUPDIENUMDEVICEINFO)(
    ___in HDEVINFO DeviceInfoSet,
    ___in DWORD MemberIndex,
    ___out PSP_DEVINFO_DATA DeviceInfoData
    );

/* SetupDiGetDeviceRegistryPropertyA, SetupDiGetDeviceRegistryPropertyW */
#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTY DECLARE_NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTYA
#define NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTY         NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTYA
#define SETUPDIGETDEVICEREGISTRYPROPERTY                    SETUPDIGETDEVICEREGISTRYPROPERTYA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTY DECLARE_NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTYW
#define NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTY         NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTYW
#define SETUPDIGETDEVICEREGISTRYPROPERTY                    SETUPDIGETDEVICEREGISTRYPROPERTYW
#endif

#define DECLARE_NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTYA CHAR NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTYA[] = { 'S', 'e', 't', 'u', 'p', 'D', 'i', 'G', 'e', 't', 'D', 'e', 'v', 'i', 'c', 'e', 'R', 'e', 'g', 'i', 's', 't', 'r', 'y', 'P', 'r', 'o', 'p', 'e', 'r', 't', 'y', 'A', 0, };
#define DECLARE_NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTYW CHAR NAMEOF_API_SETUPDIGETDEVICEREGISTRYPROPERTYW[] = { 'S', 'e', 't', 'u', 'p', 'D', 'i', 'G', 'e', 't', 'D', 'e', 'v', 'i', 'c', 'e', 'R', 'e', 'g', 'i', 's', 't', 'r', 'y', 'P', 'r', 'o', 'p', 'e', 'r', 't', 'y', 'W', 0, };

typedef BOOL (__stdcall* SETUPDIGETDEVICEREGISTRYPROPERTYA)(
    ___in HDEVINFO DeviceInfoSet,
    ___in PSP_DEVINFO_DATA DeviceInfoData,
    ___in DWORD Property,
    __out_opt PDWORD PropertyRegDataType,
    __out_bcount_opt (PropertyBufferSize) PBYTE PropertyBuffer,
    ___in DWORD PropertyBufferSize,
    __out_opt PDWORD RequiredSize
    );

typedef BOOL (__stdcall* SETUPDIGETDEVICEREGISTRYPROPERTYW)(
    ___in HDEVINFO DeviceInfoSet,
    ___in PSP_DEVINFO_DATA DeviceInfoData,
    ___in DWORD Property,
    __out_opt PDWORD PropertyRegDataType,
    __out_bcount_opt (PropertyBufferSize) PBYTE PropertyBuffer,
    ___in DWORD PropertyBufferSize,
    __out_opt PDWORD RequiredSize
    );

/* SetupDiGetDeviceInstanceIdA, SetupDiGetDeviceInstanceIdW */
#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_SETUPDIGETDEVICEINSTANCEID   DECLARE_NAMEOF_API_SETUPDIGETDEVICEINSTANCEIDA
#define NAMEOF_API_SETUPDIGETDEVICEINSTANCEID           NAMEOF_API_SETUPDIGETDEVICEINSTANCEIDA
#define SETUPDIGETDEVICEINSTANCEID                      SETUPDIGETDEVICEINSTANCEIDA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_SETUPDIGETDEVICEINSTANCEID   DECLARE_NAMEOF_API_SETUPDIGETDEVICEINSTANCEIDW
#define NAMEOF_API_SETUPDIGETDEVICEINSTANCEID           NAMEOF_API_SETUPDIGETDEVICEINSTANCEIDW
#define SETUPDIGETDEVICEINSTANCEID                      SETUPDIGETDEVICEINSTANCEIDW
#endif

#define DECLARE_NAMEOF_API_SETUPDIGETDEVICEINSTANCEIDA CHAR NAMEOF_API_SETUPDIGETDEVICEINSTANCEIDA[] = { 'S', 'e', 't', 'u', 'p', 'D', 'i', 'G', 'e', 't', 'D', 'e', 'v', 'i', 'c', 'e', 'I', 'n', 's', 't', 'a', 'n', 'c', 'e', 'I', 'd', 'A', 0, };
#define DECLARE_NAMEOF_API_SETUPDIGETDEVICEINSTANCEIDW CHAR NAMEOF_API_SETUPDIGETDEVICEINSTANCEIDW[] = { 'S', 'e', 't', 'u', 'p', 'D', 'i', 'G', 'e', 't', 'D', 'e', 'v', 'i', 'c', 'e', 'I', 'n', 's', 't', 'a', 'n', 'c', 'e', 'I', 'd', 'W', 0, };

typedef BOOL (__stdcall* SETUPDIGETDEVICEINSTANCEIDA)(
    ___in HDEVINFO DeviceInfoSet,
    ___in PSP_DEVINFO_DATA DeviceInfoData,
    __out_ecount_opt (DeviceInstanceIdSize) PSTR DeviceInstanceId,
    ___in DWORD DeviceInstanceIdSize,
    __out_opt PDWORD RequiredSize
    );

typedef BOOL (__stdcall* SETUPDIGETDEVICEINSTANCEIDW)(
    ___in HDEVINFO DeviceInfoSet,
    ___in PSP_DEVINFO_DATA DeviceInfoData,
    __out_ecount_opt (DeviceInstanceIdSize) PWSTR DeviceInstanceId,
    ___in DWORD DeviceInstanceIdSize,
    __out_opt PDWORD RequiredSize
    );

/* SetupDiDestroyDeviceInfoList */
#define DECLARE_NAMEOF_API_SETUPDIDESTROYDEVICEINFOLIST CHAR NAMEOF_API_SETUPDIDESTROYDEVICEINFOLIST[] = { 'S', 'e', 't', 'u', 'p', 'D', 'i', 'D', 'e', 's', 't', 'r', 'o', 'y', 'D', 'e', 'v', 'i', 'c', 'e', 'I', 'n', 'f', 'o', 'L', 'i', 's', 't', 0, };

typedef BOOL (__stdcall *SETUPDIDESTROYDEVICEINFOLIST)(
    ___in HDEVINFO DeviceInfoSet
    );

#endif
