/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_USERENV__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_USERENV__

/* "CreateEnvironmentBlock" */
#define DECLARE_NAMEOF_API_CREATEENVIRONMENTBLOCK                                                                        \
    CHAR NAMEOF_API_CREATEENVIRONMENTBLOCK[] = {                                                                         \
        'C', 'r', 'e', 'a', 't', 'e', 'E', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', 'B', 'l', 'o', 'c', 'k', 0, \
    };

/* @brief
    Retrieves the environment variables for the specified user. This block can then be passed to the CreateProcessAsUser function.
   @comment
    NT4+
 */
typedef BOOL(__stdcall *CREATEENVIRONMENTBLOCK)(LPVOID *lpEnvironment, HANDLE hToken, BOOL bInherit);

/* "DestroyEnvironmentBlock" */
#define DECLARE_NAMEOF_API_DESTROYENVIRONMENTBLOCK                                                                            \
    CHAR NAMEOF_API_DESTROYENVIRONMENTBLOCK[] = {                                                                             \
        'D', 'e', 's', 't', 'r', 'o', 'y', 'E', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', 'B', 'l', 'o', 'c', 'k', 0, \
    };

/* @brief
    Retrieves the path to the root directory of the specified user's profile.
   @comment
    NT4+
 */
typedef BOOL(__stdcall *GETUSERPROFILEDIRECTORY)(HANDLE hToken, LPTSTR lpProfileDir, LPDWORD lpcchSize);

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSER DECLARE_NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSERA

#define NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSER NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSERA
#define EXPANDENVIRONMENTSTRINGSFORUSER EXPANDENVIRONMENTSTRINGSFORUSERA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSER DECLARE_NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSERW

#define NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSER NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSERW
#define EXPANDENVIRONMENTSTRINGSFORUSER EXPANDENVIRONMENTSTRINGSFORUSERW
#endif

/* "ExpandEnvironmentStringsForUserA" */
#define DECLARE_NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSERA                                  \
    CHAR NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSERA[] = {                                   \
        'E', 'x', 'p', 'a', 'n', 'd', 'E', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', \
        'S', 't', 'r', 'i', 'n', 'g', 's', 'F', 'o', 'r', 'U', 's', 'e', 'r', 'A', 0,        \
    };
/* "ExpandEnvironmentStringsForUserW" */
#define DECLARE_NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSERW                                  \
    CHAR NAMEOF_API_EXPANDENVIRONMENTSTRINGSFORUSERW[] = {                                   \
        'E', 'x', 'p', 'a', 'n', 'd', 'E', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', \
        'S', 't', 'r', 'i', 'n', 'g', 's', 'F', 'o', 'r', 'U', 's', 'e', 'r', 'W', 0,        \
    };

/* @brief
    Expands the source string by using the environment block established for the specified user.
 */
typedef BOOL(__stdcall *EXPANDENVIRONMENTSTRINGSFORUSERA)(HANDLE hToken, LPCSTR lpSrc, LPSTR lpDest, DWORD dwSize);

typedef BOOL(__stdcall *EXPANDENVIRONMENTSTRINGSFORUSERW)(HANDLE hToken, LPCWSTR lpSrc, LPWSTR lpDest, DWORD dwSize);

#undef NAMEOF_API_GETUSERPROFILEDIRECTORY

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_GETUSERPROFILEDIRECTORY DECLARE_NAMEOF_API_GETUSERPROFILEDIRECTORYA

#define NAMEOF_API_GETUSERPROFILEDIRECTORY NAMEOF_API_GETUSERPROFILEDIRECTORYA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_GETUSERPROFILEDIRECTORY DECLARE_NAMEOF_API_GETUSERPROFILEDIRECTORYW

#define NAMEOF_API_GETUSERPROFILEDIRECTORY NAMEOF_API_GETUSERPROFILEDIRECTORYW
#endif

/* "GetUserProfileDirectoryA" */
#define DECLARE_NAMEOF_API_GETUSERPROFILEDIRECTORYA                                                                                \
    CHAR NAMEOF_API_GETUSERPROFILEDIRECTORYA[] = {                                                                                 \
        'G', 'e', 't', 'U', 's', 'e', 'r', 'P', 'r', 'o', 'f', 'i', 'l', 'e', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'A', 0, \
    };
/* "GetUserProfileDirectoryW" */
#define DECLARE_NAMEOF_API_GETUSERPROFILEDIRECTORYW                                                                                \
    CHAR NAMEOF_API_GETUSERPROFILEDIRECTORYW[] = {                                                                                 \
        'G', 'e', 't', 'U', 's', 'e', 'r', 'P', 'r', 'o', 'f', 'i', 'l', 'e', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'W', 0, \
    };

/* @brief
    Frees environment variables created by the CreateEnvironmentBlock function.
 */
typedef BOOL(__stdcall *DESTROYENVIRONMENTBLOCK)(LPVOID lpEnvironment);

#endif
