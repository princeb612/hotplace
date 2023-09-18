/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WINIO__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WINIO__

/* "InitializeWinIo" */
#define DECLARE_NAMEOF_API_INITIALIZEWINIO char NAMEOF_API_INITIALIZEWINIO[] = { 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'W', 'i', 'n', 'I', 'o', 0, };
/* "ShutdownWinIo" */
#define DECLARE_NAMEOF_API_SHUTDOWNWINIO char NAMEOF_API_SHUTDOWNWINIO[] = { 'S', 'h', 'u', 't', 'd', 'o', 'w', 'n', 'W', 'i', 'n', 'I', 'o', 0, };
/* "GetPhysLong" */
#define DECLARE_NAMEOF_API_GETPHYSLONG char NAMEOF_API_GETPHYSLONG[] = { 'G', 'e', 't', 'P', 'h', 'y', 's', 'L', 'o', 'n', 'g', 0, };

typedef bool (__stdcall *INITIALIZEWINIO)();
typedef void (__stdcall *SHUTDOWNWINIO)();
typedef bool (__stdcall *GETPHYSLONG)(PBYTE pbPhysAddr, PDWORD pdwPhysVal);

#endif
