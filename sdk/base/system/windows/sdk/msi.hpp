/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_MSI__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_MSI__

#undef NAMEOF_API_MSIGETFILEVERSION

/* "MsiGetFileVersionA" */
#define DECLARE_NAMEOF_API_MSIGETFILEVERSIONA                                                        \
    CHAR NAMEOF_API_MSIGETFILEVERSIONA[] = {                                                         \
        'M', 's', 'i', 'G', 'e', 't', 'F', 'i', 'l', 'e', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'A', 0, \
    };
/* "MsiGetFileVersionW" */
#define DECLARE_NAMEOF_API_MSIGETFILEVERSIONW                                                        \
    CHAR NAMEOF_API_MSIGETFILEVERSIONW[] = {                                                         \
        'M', 's', 'i', 'G', 'e', 't', 'F', 'i', 'l', 'e', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'W', 0, \
    };

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_MSIGETFILEVERSION DECLARE_NAMEOF_API_MSIGETFILEVERSIONA
#define NAMEOF_API_MSIGETFILEVERSION NAMEOF_API_MSIGETFILEVERSIONA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_MSIGETFILEVERSION DECLARE_NAMEOF_API_MSIGETFILEVERSIONW
#define NAMEOF_API_MSIGETFILEVERSION NAMEOF_API_MSIGETFILEVERSIONW
#endif

/* @brief
    The MsiGetFileVersion returns the version string and language string in the format that the installer expects to find them in the database.
    If you want only version information, set lpLangBuf and pcchLangBuf to 0 (zero).
    If you just want language information, set lpVersionBuf and pcchVersionBuf to 0 (zero).
 */
typedef UINT(WINAPI* MSIGETFILEVERSION)(LPCTSTR szFilePath, LPTSTR lpVersionBuf, DWORD* pcchVersionBuf, LPTSTR lpLangBuf, DWORD* pcchLangBuf);

#endif
