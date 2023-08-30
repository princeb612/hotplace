/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab textwidth=130 colorcolumn=+1: */
/**
 * @file wscapi.h
 * @author Soo Han, Kim (hush@ahnlab.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SDK_WSCAPI__
#define __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SDK_WSCAPI__

/* WscRegisterForChanges */
#define DECLARE_NAMEOF_API_WSCREGISTERFORCHANGES CHAR NAMEOF_API_WSCREGISTERFORCHANGES[] = { 'W', 's', 'c', 'R', 'e', 'g', 'i', 's', 't', 'e', 'r', 'F', 'o', 'r', 'C', 'h', 'a', 'n', 'g', 'e', 's', 0, };
/* "WscUnRegisterChanges" */
#define DECLARE_NAMEOF_API_WSCUNREGISTERCHANGES CHAR NAMEOF_API_WSCUNREGISTERCHANGES[] = { 'W', 's', 'c', 'U', 'n', 'R', 'e', 'g', 'i', 's', 't', 'e', 'r', 'C', 'h', 'a', 'n', 'g', 'e', 's', 0, };
/* "WscGetSecurityProviderHealth" */
#define DECLARE_NAMEOF_API_WSCGETSECURITYPROVIDERHEALTH CHAR NAMEOF_API_WSCGETSECURITYPROVIDERHEALTH[] = { 'W', 's', 'c', 'G', 'e', 't', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'P', 'r', 'o', 'v', 'i', 'd', 'e', 'r', 'H', 'e', 'a', 'l', 't', 'h', 0, };

/* @brief
    Registers a callback function to be run when Windows Security Center (WSC) detects a change that could affect the health of one of the security providers.
 */
typedef HRESULT (__stdcall *WSCREGISTERFORCHANGES)
(
    __in LPVOID Reserved,
    __out PHANDLE phCallbackRegistration,
    __in LPTHREAD_START_ROUTINE lpCallbackAddress,
    __in PVOID pContext
);

/* @brief
    Cancels a callback registration that was made by a call to the WscRegisterForChanges function.
 */
typedef HRESULT (__stdcall *WSCUNREGISTERCHANGES)
(
    __in HANDLE hRegistrationHandle
);

/* @brief
    Gets the aggregate health state of the security provider categories represented by the specified WSC_SECURITY_PROVIDER enumeration values.
 */
typedef HRESULT (__stdcall *WSCGETSECURITYPROVIDERHEALTH)
(
    __in DWORD Providers,
    __out /*PWSC_SECURITY_PROVIDER_HEALTH*/ INT* pHealth
);

#endif
