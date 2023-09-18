/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_USER32__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_USER32__

/* "IsWow64Message" */
#define DECLARE_NAMEOF_API_ISWOW64MESSAGE char NAMEOF_API_ISWOW64MESSAGE[] = { 'I', 's', 'W', 'o', 'w', '6', '4', 'M', 'e', 's', 's', 'a', 'g', 'e', 0, };

/* @brief
    Determines whether the last message read from the current thread's queue originated from a WOW64 process.
 */
typedef BOOL (__stdcall *ISWOW64MESSAGE)(void);

/* "LockWorkStation" */
#define DECLARE_NAMEOF_API_LOCKWORKSTATION char NAMEOF_API_LOCKWORKSTATION[] = { 'L', 'o', 'c', 'k', 'W', 'o', 'r', 'k', 'S', 't', 'a', 't', 'i', 'o', 'n', 0, };

/* @brief
    Locks the workstation's display. Locking a workstation protects it from unauthorized use.
 */
typedef BOOL (__stdcall *LOCKWORKSTATION)(void);

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_REGISTERDEVICENOTIFICATION   DECLARE_NAMEOF_API_REGISTERDEVICENOTIFICATIONA

#define NAMEOF_API_REGISTERDEVICENOTIFICATION           NAMEOF_API_REGISTERDEVICENOTIFICATIONA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_REGISTERDEVICENOTIFICATION   DECLARE_NAMEOF_API_REGISTERDEVICENOTIFICATIONW

#define NAMEOF_API_REGISTERDEVICENOTIFICATION           NAMEOF_API_REGISTERDEVICENOTIFICATIONW
#endif

/* "RegisterDeviceNotificationA" */
#define DECLARE_NAMEOF_API_REGISTERDEVICENOTIFICATIONA char NAMEOF_API_REGISTERDEVICENOTIFICATIONA[] = { 'R', 'e', 'g', 'i', 's', 't', 'e', 'r', 'D', 'e', 'v', 'i', 'c', 'e', 'N', 'o', 't', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', 'A', 0, };
/* "RegisterDeviceNotificationW" */
#define DECLARE_NAMEOF_API_REGISTERDEVICENOTIFICATIONW char NAMEOF_API_REGISTERDEVICENOTIFICATIONW[] = { 'R', 'e', 'g', 'i', 's', 't', 'e', 'r', 'D', 'e', 'v', 'i', 'c', 'e', 'N', 'o', 't', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', 'W', 0, };
/* "UnregisterDeviceNotification" */
#define DECLARE_NAMEOF_API_UNREGISTERDEVICENOTIFICATION char NAMEOF_API_UNREGISTERDEVICENOTIFICATION[] = { 'U', 'n', 'r', 'e', 'g', 'i', 's', 't', 'e', 'r', 'D', 'e', 'v', 'i', 'c', 'e', 'N', 'o', 't', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', 0, };

/* @brief
    Registers the device or type of device for which a window will receive notifications.
 */
typedef HDEVNOTIFY (__stdcall *REGISTERDEVICENOTIFICATION)(HANDLE hRecipient, LPVOID NotificationFilter, DWORD Flags);
/* @brief
    Closes the specified device notification handle.
 */
typedef BOOL (__stdcall *UNREGISTERDEVICENOTIFICATION)(HDEVNOTIFY Handle);

#endif
