/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab textwidth=130 colorcolumn=+1: */
/**
 * @file wintrust.h
 * @author Soo Han, Kim (hush@ahnlab.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WINTRUST__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WINTRUST__

#include <wintrust.h>

/* "WinVerifyTrust" */
#define DECLARE_NAMEOF_API_WINVERIFYTRUST char NAMEOF_API_WINVERIFYTRUST[] = { 'W', 'i', 'n', 'V', 'e', 'r', 'i', 'f', 'y', 'T', 'r', 'u', 's', 't', 0, };
/* "WintrustLoadFunctionPointers" */
#define DECLARE_NAMEOF_API_WINTRUSTLOADFUNCTIONPOINTERS char NAMEOF_API_WINTRUSTLOADFUNCTIONPOINTERS[] = { 'W', 'i', 'n', 't', 'r', 'u', 's', 't', 'L', 'o', 'a', 'd', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 'P', 'o', 'i', 'n', 't', 'e', 'r', 's', 0, };

/* @brief
    The WinVerifyTrust function performs a trust verification action on a specified object.
    The function passes the inquiry to a trust provider that supports the action identifier, if one exists.
    For certificate verification, use the CertGetCertificateChain and CertVerifyCertificateChainPolicy functions.
 */
typedef BOOL (__stdcall * WINVERIFYTRUST)(HWND hwnd, GUID* pguidAction, LPVOID pvData);
/* @brief
    [The WintrustLoadFunctionPointers function is available for use in the operating systems specified in the Requirements section.
    It may be altered or unavailable in subsequent versions.
    For certificate verification, use the CertGetCertificateChain and CertVerifyCertificateChainPolicy functions.
    For Microsoft Authenticode technology signature verification, use the .NET Framework.]

    The WintrustLoadFunctionPointers function loads function entry points for a specified action GUID.
    This function has no associated import library.
    You must use the LoadLibrary and GetProcAddress functions to dynamically link to Wintrust.dll.
   @comment
    XP, 2003 이후에는 CryptQueryObject 를 사용하도록 처리하고 있다. (Helper Authenticode 참고)
 */
typedef BOOL (__stdcall * WINTRUSTLOADFUNCTIONPOINTERS)(GUID *pgActionID, CRYPT_PROVIDER_FUNCTIONS *pPfns);

#endif
