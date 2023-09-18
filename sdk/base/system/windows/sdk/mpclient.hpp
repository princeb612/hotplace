/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_MPCLIENT__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_MPCLIENT__

// Windowsdefender.h

/* "WDEnable" */
#define DECLARE_NAMEOF_API_WDENABLE CHAR NAMEOF_API_WDENABLE[] = { 'W', 'D', 'E', 'n', 'a', 'b', 'l', 'e', 0, };
/* "WDStatus" */
#define DECLARE_NAMEOF_API_WDSTATUS CHAR NAMEOF_API_WDSTATUS[] = { 'W', 'D', 'S', 't', 'a', 't', 'u', 's', 0, };

/* @brief
    Returns the current status of Windows Defender.
 */
typedef HRESULT (WINAPI *WDSTATUS)(BOOL* pfEnabled);
/* @biref
    Changes Windows Defender status to on or off.
 */
typedef HRESULT (WINAPI *WDENABLE)(BOOL fEnable);

#endif
