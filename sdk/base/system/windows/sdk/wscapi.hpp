/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WSCAPI__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WSCAPI__

/* WscRegisterForChanges */
#define DECLARE_NAMEOF_API_WSCREGISTERFORCHANGES                                                                    \
    CHAR NAMEOF_API_WSCREGISTERFORCHANGES[] = {                                                                     \
        'W', 's', 'c', 'R', 'e', 'g', 'i', 's', 't', 'e', 'r', 'F', 'o', 'r', 'C', 'h', 'a', 'n', 'g', 'e', 's', 0, \
    };
/* "WscUnRegisterChanges" */
#define DECLARE_NAMEOF_API_WSCUNREGISTERCHANGES                                                                \
    CHAR NAMEOF_API_WSCUNREGISTERCHANGES[] = {                                                                 \
        'W', 's', 'c', 'U', 'n', 'R', 'e', 'g', 'i', 's', 't', 'e', 'r', 'C', 'h', 'a', 'n', 'g', 'e', 's', 0, \
    };
/* "WscGetSecurityProviderHealth" */
#define DECLARE_NAMEOF_API_WSCGETSECURITYPROVIDERHEALTH                                                                                                \
    CHAR NAMEOF_API_WSCGETSECURITYPROVIDERHEALTH[] = {                                                                                                 \
        'W', 's', 'c', 'G', 'e', 't', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'P', 'r', 'o', 'v', 'i', 'd', 'e', 'r', 'H', 'e', 'a', 'l', 't', 'h', 0, \
    };

/* @brief
    Registers a callback function to be run when Windows Security Center (WSC) detects a change that could affect the health of one of the security providers.
 */
typedef HRESULT(__stdcall *WSCREGISTERFORCHANGES)(___in LPVOID Reserved, ___out PHANDLE phCallbackRegistration, ___in LPTHREAD_START_ROUTINE lpCallbackAddress,
                                                  ___in PVOID pContext);

/* @brief
    Cancels a callback registration that was made by a call to the WscRegisterForChanges function.
 */
typedef HRESULT(__stdcall *WSCUNREGISTERCHANGES)(___in HANDLE hRegistrationHandle);

/* @brief
    Gets the aggregate health state of the security provider categories represented by the specified WSC_SECURITY_PROVIDER enumeration values.
 */
typedef HRESULT(__stdcall *WSCGETSECURITYPROVIDERHEALTH)(___in DWORD Providers, ___out /*PWSC_SECURITY_PROVIDER_HEALTH*/ INT *pHealth);

#endif
