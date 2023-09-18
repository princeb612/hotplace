/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_OCCACHE__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_OCCACHE__

// RemoveControlByName
// Internet Explorer 5.0

/* "RemoveControlByName" */
#define DECLARE_NAMEOF_API_REMOVECONTROLBYNAME CHAR NAMEOF_API_REMOVECONTROLBYNAME[] = { 'R', 'e', 'm', 'o', 'v', 'e', 'C', 'o', 'n', 't', 'r', 'o', 'l', 'B', 'y', 'N', 'a', 'm', 'e', 0, };

/* @brief
    Removes the registry entries and all of the files associated with the specified control.
 */
typedef HRESULT (WINAPI *REMOVECONTROLBYNAME)
(
    LPCTSTR lpszFile,
    LPCTSTR lpszCLSID,
    LPCTSTR lpszTypeLibID,
    BOOL bForceRemove,
    DWORD dwIsDistUnit
);

#endif
