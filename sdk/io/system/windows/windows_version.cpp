/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/system/windows/sdk.hpp>
#include <hotplace/sdk/io/system/windows/windows_version.hpp>

namespace hotplace {
namespace io {

#ifndef PRODUCT_ULTIMATE
#define PRODUCT_ULTIMATE                            0x00000001
#endif
#ifndef PRODUCT_HOME_BASIC
#define PRODUCT_HOME_BASIC                          0x00000002
#endif
#ifndef PRODUCT_HOME_PREMIUM
#define PRODUCT_HOME_PREMIUM                        0x00000003
#endif
#ifndef PRODUCT_ENTERPRISE
#define PRODUCT_ENTERPRISE                          0x00000004
#endif
#ifndef PRODUCT_HOME_BASIC_N
#define PRODUCT_HOME_BASIC_N                        0x00000005
#endif
#ifndef PRODUCT_BUSINESS
#define PRODUCT_BUSINESS                            0x00000006
#endif
#ifndef PRODUCT_STANDARD_SERVER
#define PRODUCT_STANDARD_SERVER                     0x00000007
#endif
#ifndef PRODUCT_DATACENTER_SERVER
#define PRODUCT_DATACENTER_SERVER                   0x00000008
#endif
#ifndef PRODUCT_SMALLBUSINESS_SERVER
#define PRODUCT_SMALLBUSINESS_SERVER                0x00000009
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER
#define PRODUCT_ENTERPRISE_SERVER                   0x0000000A
#endif
#ifndef PRODUCT_STARTER
#define PRODUCT_STARTER                             0x0000000B
#endif
#ifndef PRODUCT_DATACENTER_SERVER_CORE
#define PRODUCT_DATACENTER_SERVER_CORE              0x0000000C
#endif
#ifndef PRODUCT_STANDARD_SERVER_CORE
#define PRODUCT_STANDARD_SERVER_CORE                0x0000000D
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_CORE
#define PRODUCT_ENTERPRISE_SERVER_CORE              0x0000000E
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_IA64
#define PRODUCT_ENTERPRISE_SERVER_IA64              0x0000000F
#endif
#ifndef PRODUCT_BUSINESS_N
#define PRODUCT_BUSINESS_N                          0x00000010
#endif
#ifndef PRODUCT_WEB_SERVER
#define PRODUCT_WEB_SERVER                          0x00000011
#endif
#ifndef PRODUCT_CLUSTER_SERVER
#define PRODUCT_CLUSTER_SERVER                      0x00000012
#endif
#ifndef PRODUCT_HOME_SERVER
#define PRODUCT_HOME_SERVER                         0x00000013
#endif
#ifndef PRODUCT_STORAGE_EXPRESS_SERVER
#define PRODUCT_STORAGE_EXPRESS_SERVER              0x00000014
#endif
#ifndef PRODUCT_STORAGE_STANDARD_SERVER
#define PRODUCT_STORAGE_STANDARD_SERVER             0x00000015
#endif
#ifndef PRODUCT_STORAGE_WORKGROUP_SERVER
#define PRODUCT_STORAGE_WORKGROUP_SERVER            0x00000016
#endif
#ifndef PRODUCT_STORAGE_ENTERPRISE_SERVER
#define PRODUCT_STORAGE_ENTERPRISE_SERVER           0x00000017
#endif
#ifndef PRODUCT_SERVER_FOR_SMALLBUSINESS
#define PRODUCT_SERVER_FOR_SMALLBUSINESS            0x00000018
#endif
#ifndef PRODUCT_SMALLBUSINESS_SERVER_PREMIUM
#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM        0x00000019
#endif
#ifndef PRODUCT_HOME_PREMIUM_N
#define PRODUCT_HOME_PREMIUM_N                      0x0000001A
#endif
#ifndef PRODUCT_ENTERPRISE_N
#define PRODUCT_ENTERPRISE_N                        0x0000001B
#endif
#ifndef PRODUCT_ULTIMATE_N
#define PRODUCT_ULTIMATE_N                          0x0000001C
#endif
#ifndef PRODUCT_WEB_SERVER_CORE
#define PRODUCT_WEB_SERVER_CORE                     0x0000001D
#endif
#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT
#define PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT    0x0000001E
#endif
#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY
#define PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY      0x0000001F
#endif
#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING
#define PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING     0x00000020
#endif
#ifndef PRODUCT_SERVER_FOUNDATION
#define PRODUCT_SERVER_FOUNDATION                   0x00000021
#endif
#ifndef PRODUCT_HOME_PREMIUM_SERVER
#define PRODUCT_HOME_PREMIUM_SERVER                 0x00000022
#endif
#ifndef PRODUCT_SERVER_FOR_SMALLBUSINESS_V
#define PRODUCT_SERVER_FOR_SMALLBUSINESS_V          0x00000023
#endif
#ifndef PRODUCT_STANDARD_SERVER_V
#define PRODUCT_STANDARD_SERVER_V                   0x00000024
#endif
#ifndef PRODUCT_DATACENTER_SERVER_V
#define PRODUCT_DATACENTER_SERVER_V                 0x00000025
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_V
#define PRODUCT_ENTERPRISE_SERVER_V                 0x00000026
#endif
#ifndef PRODUCT_DATACENTER_SERVER_CORE_V
#define PRODUCT_DATACENTER_SERVER_CORE_V            0x00000027
#endif
#ifndef PRODUCT_STANDARD_SERVER_CORE_V
#define PRODUCT_STANDARD_SERVER_CORE_V              0x00000028
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_CORE_V
#define PRODUCT_ENTERPRISE_SERVER_CORE_V            0x00000029
#endif
#ifndef PRODUCT_HYPERV
#define PRODUCT_HYPERV                              0x0000002A
#endif
#ifndef PRODUCT_STORAGE_EXPRESS_SERVER_CORE
#define PRODUCT_STORAGE_EXPRESS_SERVER_CORE         0x0000002B
#endif
#ifndef PRODUCT_STORAGE_STANDARD_SERVER_CORE
#define PRODUCT_STORAGE_STANDARD_SERVER_CORE        0x0000002C
#endif
#ifndef PRODUCT_STORAGE_WORKGROUP_SERVER_CORE
#define PRODUCT_STORAGE_WORKGROUP_SERVER_CORE       0x0000002D
#endif
#ifndef PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE
#define PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE      0x0000002E
#endif
#ifndef PRODUCT_STARTER_N
#define PRODUCT_STARTER_N                           0x0000002F
#endif
#ifndef PRODUCT_PROFESSIONAL
#define PRODUCT_PROFESSIONAL                        0x00000030
#endif
#ifndef PRODUCT_PROFESSIONAL_N
#define PRODUCT_PROFESSIONAL_N                      0x00000031
#endif
#ifndef PRODUCT_SB_SOLUTION_SERVER
#define PRODUCT_SB_SOLUTION_SERVER                  0x00000032
#endif
#ifndef PRODUCT_SERVER_FOR_SB_SOLUTIONS
#define PRODUCT_SERVER_FOR_SB_SOLUTIONS             0x00000033
#endif
#ifndef PRODUCT_STANDARD_SERVER_SOLUTIONS
#define PRODUCT_STANDARD_SERVER_SOLUTIONS           0x00000034
#endif
#ifndef PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE
#define PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE      0x00000035
#endif
#ifndef PRODUCT_SB_SOLUTION_SERVER_EM
#define PRODUCT_SB_SOLUTION_SERVER_EM               0x00000036
#endif
#ifndef PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM
#define PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM          0x00000037
#endif
#ifndef PRODUCT_SOLUTION_EMBEDDEDSERVER
#define PRODUCT_SOLUTION_EMBEDDEDSERVER             0x00000038
#endif
/*Windows Essential Server Solution Management*/
#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT
#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT       0x0000003B
#endif
/*Windows Essential Server Solution Additional*/
#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL
#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL       0x0000003C
#endif
/*Windows Essential Server Solution Management SVC*/
#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC
#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC    0x0000003D
#endif
/*Windows Essential Server Solution Additional SVC*/
#ifndef PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC
#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC    0x0000003E
#endif
#ifndef PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE
#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE   0x0000003F
#endif
#ifndef PRODUCT_CLUSTER_SERVER_V
#define PRODUCT_CLUSTER_SERVER_V                    0x00000040
#endif
#ifndef PRODUCT_STARTER_E
#define PRODUCT_STARTER_E                           0x00000042
#endif
#ifndef PRODUCT_HOME_BASIC_E
#define PRODUCT_HOME_BASIC_E                        0x00000043
#endif
#ifndef PRODUCT_HOME_PREMIUM_E
#define PRODUCT_HOME_PREMIUM_E                      0x00000044
#endif
#ifndef PRODUCT_PROFESSIONAL_E
#define PRODUCT_PROFESSIONAL_E                      0x00000045
#endif
#ifndef PRODUCT_ENTERPRISE_E
#define PRODUCT_ENTERPRISE_E                        0x00000046
#endif
#ifndef PRODUCT_ULTIMATE_E
#define PRODUCT_ULTIMATE_E                          0x00000047
#endif
#ifndef PRODUCT_ENTERPRISE_EVALUATION
#define PRODUCT_ENTERPRISE_EVALUATION               0x00000048
#endif
#ifndef PRODUCT_MULTIPOINT_STANDARD_SERVER
#define PRODUCT_MULTIPOINT_STANDARD_SERVER          0x0000004C
#endif
#ifndef PRODUCT_MULTIPOINT_PREMIUM_SERVER
#define PRODUCT_MULTIPOINT_PREMIUM_SERVER           0x0000004D
#endif
#ifndef PRODUCT_STANDARD_EVALUATION_SERVER
#define PRODUCT_STANDARD_EVALUATION_SERVER          0x0000004F
#endif
#ifndef PRODUCT_DATACENTER_EVALUATION_SERVER
#define PRODUCT_DATACENTER_EVALUATION_SERVER        0x00000050
#endif
#ifndef PRODUCT_ENTERPRISE_N_EVALUATION
#define PRODUCT_ENTERPRISE_N_EVALUATION             0x00000054
#endif
#ifndef PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER
#define PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER 0x0000005F
#endif
#ifndef PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER
#define PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER  0x00000060
#endif
#ifndef PRODUCT_CORE_N
#define PRODUCT_CORE_N                              0x00000062
#endif
#ifndef PRODUCT_CORE_COUNTRYSPECIFIC
#define PRODUCT_CORE_COUNTRYSPECIFIC                0x00000063
#endif
#ifndef PRODUCT_CORE_SINGLELANGUAGE
#define PRODUCT_CORE_SINGLELANGUAGE                 0x00000064
#endif
#ifndef PRODUCT_CORE
#define PRODUCT_CORE                                0x00000065
#endif
#ifndef PRODUCT_PROFESSIONAL_WMC
#define PRODUCT_PROFESSIONAL_WMC                    0x00000067
#endif

#ifndef PRODUCT_UNLICENSED
#define PRODUCT_UNLICENSED                          0xABCDABCD
#endif

#ifndef SM_TABLETPC
#define SM_TABLETPC             86
#endif
#ifndef SM_MEDIACENTER
#define SM_MEDIACENTER          87
#endif
#ifndef SM_STARTER
#define SM_STARTER              88
#endif
#ifndef SM_SERVERR2
#define SM_SERVERR2             89
#endif

#ifndef VER_SUITE_WH_SERVER
#define VER_SUITE_WH_SERVER 0x8000
#endif
#ifndef VER_SUITE_STORAGE_SERVER
#define VER_SUITE_STORAGE_SERVER 0x2000
#endif

windows_version windows_version::_instance;

windows_version::windows_version () : _version (WINDOWSVERSION_UNKNOWN), _flags (0), _max_verfify (100)
{
    memset (&_osvi_getversion, 0, sizeof _osvi_getversion);
    memset (&_osvi_getversionexw, 0, sizeof _osvi_getversionexw);
    memset (&_sysinfo, 0, sizeof _sysinfo);
}

windows_version::~windows_version ()
{
    // do nothing
}

windows_version* windows_version::get_instance ()
{
    return &_instance;
}

const OSVERSIONINFOEXA* windows_version::get_osvi ()
{
    detect ();
    return &_osvi_vercond;
}

return_t windows_version::detect ()
{
    return_t ret = errorcode_t::success;
    BOOL bret = TRUE;

    __try2
    {
        if (windows_version_flag_t::winver_detected & _flags) {
            __leave2;
        }

        std::set<return_t> results;

        ret = detect_getversion ();
        results.insert (ret);

        ret = detect_versionlie ();
        results.insert (ret);

        ret = detect_version ();
        results.insert (ret);

        if (1 == results.size () && errorcode_t::success == *results.begin ()) {
            _flags |= windows_version_flag_t::winver_detected;
        }
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t windows_version::detect_getversion ()
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (windows_version_flag_t::winver_detect_getversion & _flags) {
            __leave2;
        }

        _osvi_getversion.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEXA);
        _osvi_getversionexw.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEXW);

        BOOL bret = GetVersionExA ((LPOSVERSIONINFOA) &_osvi_getversion);   // Win95+
        GetVersionExW ((LPOSVERSIONINFOW) &_osvi_getversionexw);            // Win95+
        if (FALSE == bret) {
            _osvi_getversion.dwOSVersionInfoSize = sizeof (OSVERSIONINFOA);
            _osvi_getversionexw.dwOSVersionInfoSize = sizeof (OSVERSIONINFOW);
            bret = GetVersionExA ((LPOSVERSIONINFOA) &_osvi_getversion);
            GetVersionExW ((LPOSVERSIONINFOW) &_osvi_getversionexw);
            if (FALSE == bret) {
                ret = GetLastError ();
                __leave2;
            }
        }

        _flags |= windows_version_flag_t::winver_detect_getversion;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t windows_version::detect_versionlie ()
{
    return_t ret = errorcode_t::success;

    /* step.2 VerifyVersionInfo */
    return_t test = errorcode_t::success;
    HMODULE ntdll_handle = nullptr;
    HMODULE kernel32_handle = nullptr;
    VERSETCONDITIONMASK lpfnVerSetConditionMask = nullptr;
    VERIFYVERSIONINFO lpfnVerifyVersionInfo = nullptr;

    __try2
    {
        if (0 == (windows_version_flag_t::winver_detect_getversion & _flags)) {
            ret = errorcode_t::not_ready;
            __leave2;
        }
        if (windows_version_flag_t::winver_detect_version_lie & _flags) {
            __leave2;
        }

        memcpy_inline (&_osvi_vercond, sizeof (_osvi_vercond), &_osvi_getversion, sizeof (_osvi_getversion));

        DECLARE_DLLNAME_NTDLL;
        DECLARE_DLLNAME_KERNEL32;

        test = load_library (&ntdll_handle, DLLNAME_NTDLL, loadlibrary_path_t::system_path, nullptr);
        if (errorcode_t::success != test) {
            __leave2;
        }

        test = get_module_handle (&kernel32_handle, DLLNAME_KERNEL32, loadlibrary_path_t::system_path, nullptr);
        if (errorcode_t::success != test) {
            __leave2;
        }

        DECLARE_NAMEOF_API_VERIFYVERSIONINFO;
        DECLARE_NAMEOF_API_VERSETCONDITIONMASK;

        GETPROCADDRESS (VERSETCONDITIONMASK, lpfnVerSetConditionMask, ntdll_handle, NAMEOF_API_VERSETCONDITIONMASK, test, __leave2);
        GETPROCADDRESS (VERIFYVERSIONINFO, lpfnVerifyVersionInfo, kernel32_handle, NAMEOF_API_VERIFYVERSIONINFO, test, __leave2);

        //OSVERSIONINFOEX OSVer;
        //memset (&OSVer, 0, sizeof (OSVer));
        //OSVer.dwOSVersionInfoSize = sizeof (OSVer);

        DWORDLONG condition_mask = 0;
        condition_mask = (*lpfnVerSetConditionMask)(condition_mask, VER_MAJORVERSION,     VER_GREATER_EQUAL);
        condition_mask = (*lpfnVerSetConditionMask)(condition_mask, VER_MINORVERSION,     VER_GREATER_EQUAL);
        condition_mask = (*lpfnVerSetConditionMask)(condition_mask, VER_PLATFORMID,       VER_GREATER_EQUAL);
        condition_mask = (*lpfnVerSetConditionMask)(condition_mask, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
        condition_mask = (*lpfnVerSetConditionMask)(condition_mask, VER_SERVICEPACKMINOR, VER_GREATER_EQUAL);
        condition_mask = (*lpfnVerSetConditionMask)(condition_mask, VER_PRODUCT_TYPE,     VER_GREATER_EQUAL);

        uint32 major = 3; /* HighVersionLie compatibility */;
        uint32 minor = 0;

        for (; major < _max_verfify;) {
            _osvi_vercond.dwMajorVersion = major + 1;
            _osvi_vercond.dwMinorVersion = minor;
            BOOL bret = (*lpfnVerifyVersionInfo)(&_osvi_vercond, VER_MAJORVERSION, condition_mask);
            if (TRUE == bret) { /* equal or newer */
                major++;
            } else {
                break;
            }
        }
        _osvi_vercond.dwMajorVersion = major;

        for (; minor < _max_verfify;) { /* minor */
            _osvi_vercond.dwMinorVersion = minor + 1;
            BOOL bret = (*lpfnVerifyVersionInfo)(&_osvi_vercond, VER_MAJORVERSION | VER_MINORVERSION, condition_mask);
            if (TRUE == bret) { /* equal or newer */
                minor++;
            } else {
                break;
            }
        }
        _osvi_vercond.dwMinorVersion = minor;

        /*
         * 1. windows 8.1
         * 2. compatible mode
         */
        DWORD platform_id = 0;                      /* VER_PLATFORM_WIN32_WINDOWS 1, VER_PLATFORM_WIN32_NT 2 */
        for (; platform_id < _max_verfify;) {       /* platformid */
            _osvi_vercond.dwPlatformId = platform_id + 1;
            BOOL bret = (*lpfnVerifyVersionInfo)(&_osvi_vercond, VER_PLATFORMID, condition_mask);
            if (TRUE == bret) { /* equal or newer */
                platform_id++;
            } else {
                break;
            }
        }
        _osvi_vercond.dwPlatformId = platform_id;

        WORD sp_major = 0;
        WORD sp_minor = 0;
        for (; sp_major < _max_verfify;) {
            _osvi_vercond.wServicePackMajor = sp_major + 1;
            BOOL bret = (*lpfnVerifyVersionInfo)(&_osvi_vercond, VER_SERVICEPACKMAJOR, condition_mask);
            if (TRUE == bret) { /* equal or newer */
                sp_major++;
            } else {
                break;
            }
        }
        _osvi_vercond.wServicePackMajor = sp_major;

        for (; sp_minor < _max_verfify;) {
            _osvi_vercond.wServicePackMinor = sp_minor + 1;
            BOOL bret = (*lpfnVerifyVersionInfo)(&_osvi_vercond, VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR, condition_mask);
            if (TRUE == bret) { /* equal or newer */
                sp_minor++;
            } else {
                break;
            }
        }
        _osvi_vercond.wServicePackMinor = sp_minor;

        WORD product_type = 0;
        for (; product_type < _max_verfify;) {
            _osvi_vercond.wProductType = (BYTE) product_type + 1;
            BOOL bret = (*lpfnVerifyVersionInfo)(&_osvi_vercond, VER_PRODUCT_TYPE, condition_mask);
            if (TRUE == bret) { /* equal or newer */
                product_type++;;
            } else {
                break;
            }
        }
        _osvi_vercond.wProductType = (BYTE) product_type;

        std::set <bool> results;
        results.insert (_osvi_getversion.dwMajorVersion == _osvi_vercond.dwMajorVersion);
        results.insert (_osvi_getversion.dwMinorVersion == _osvi_vercond.dwMinorVersion);
        if (1 == results.size () && true == *results.begin ()) {
            // do nothing
        } else {
            _flags |= windows_version_flag_t::winver_detect_compatibility_mode; /* compatibility */
        }
        _flags |= windows_version_flag_t::winver_detect_version_lie;
    }
    __finally2
    {
        if (nullptr != ntdll_handle) {
            FreeLibrary (ntdll_handle);
        }
    }

    return ret;
}

return_t windows_version::detect_version ()
{
    return_t ret = errorcode_t::success;
    windowsversion_t version_code = WINDOWSVERSION_UNKNOWN;
    DWORD product_type = 0; /* major >= 6 */

    __try2
    {
        if (windows_version_flag_t::winver_test_version == (_flags & windows_version_flag_t::winver_test_version)) {
            // do nothing
            __leave2;
        }

#if defined _MBCS || defined MBCS
        LPOSVERSIONINFOEXA osvi_ptr = &_osvi_getversion;
#elif defined _UNICODE || defined UNICODE
        LPOSVERSIONINFOEXW osvi_ptr = &_osvi_getversionexw;
#endif

        DECLARE_DLLNAME_KERNEL32;
        HMODULE kernel32_module = nullptr;
        ret = get_module_handle (&kernel32_module, DLLNAME_KERNEL32, loadlibrary_path_t::system_path, nullptr);

        if (osvi_ptr->dwMajorVersion >= 6) {
            if (windows_version_flag_t::winver_detect_compatibility_mode != (_flags & windows_version_flag_t::winver_detect_compatibility_mode)) {
                DECLARE_NAMEOF_API_GETPRODUCTINFO;
                GETPRODUCTINFO lpfnGetProductInfo;

                GETPROCADDRESSONLY (GETPRODUCTINFO, lpfnGetProductInfo, kernel32_module, NAMEOF_API_GETPRODUCTINFO);
                if (lpfnGetProductInfo) {
                    lpfnGetProductInfo (osvi_ptr->dwMajorVersion, osvi_ptr->dwMinorVersion, osvi_ptr->wServicePackMajor, osvi_ptr->wServicePackMinor, &product_type);
                }
            }
        }

        {
            GETNATIVESYSTEMINFO lpfnGetNativeSystemInfo = nullptr;

            DECLARE_NAMEOF_API_GETNATIVESYSTEMINFO;

            GETPROCADDRESSONLY (GETNATIVESYSTEMINFO, lpfnGetNativeSystemInfo, kernel32_module, NAMEOF_API_GETNATIVESYSTEMINFO);
            if (lpfnGetNativeSystemInfo) {
                lpfnGetNativeSystemInfo (&_sysinfo);
            } else {
                GetSystemInfo (&_sysinfo);
            }
        }

        switch (osvi_ptr->dwPlatformId) {
            case VER_PLATFORM_WIN32_WINDOWS:
                switch (osvi_ptr->dwMajorVersion) {
                    case 4:
                        /*case WINDOWSMAJORVERSION_95:*/
                        /*case WINDOWSMAJORVERSION_98:*/
                        /*case WINDOWSMAJORVERSION_ME:*/
                        switch (osvi_ptr->dwMinorVersion) {
                            case WINDOWSMINORVERSION_95:
                                version_code = WINDOWSVERSION_WINDOWS95;

                                if (_T ('C') == osvi_ptr->szCSDVersion[1] || _T ('B') == osvi_ptr->szCSDVersion[1]) {
                                    version_code = WINDOWSVERSION_WINDOWS95_OSR2;
                                }
                                break;

                            case WINDOWSMINORVERSION_98:
                                version_code = WINDOWSVERSION_WINDOWS98;

                                if (_T ('A') == osvi_ptr->szCSDVersion[1]) {
                                    version_code = WINDOWSVERSION_WINDOWS98_SE;
                                }
                                break;

                            case WINDOWSMINORVERSION_ME:
                                version_code = WINDOWSVERSION_WINDOWSME;
                                break;
                        } /*end of switch(osvi_ptr->dwMinorVersion)*/
                        break; /*end of case 4:*/
                }       /*end of switch(osvi_ptr->dwMajorVersion)*/
                break;  /*end of case VER_PLATFORM_WIN32_WINDOWS:*/

            case VER_PLATFORM_WIN32_NT:
                switch (osvi_ptr->dwMajorVersion) {
                    case 10:
                        // Windows 10, Windows 11
                        switch (osvi_ptr->dwMinorVersion) {
                            case 0:
                                switch (osvi_ptr->wProductType) {
                                    case VER_NT_WORKSTATION:
                                        version_code = (windowsversion_t) (WINDOWSVERSION_WINDOWS10 + product_type);
                                        break;

                                    default:
                                        version_code = (windowsversion_t) (WINDOWSVERSION_WINDOWS2016 + product_type);
                                        break;
                                }
                                break;
                        }
                        break;
                    case 6:
                        /*case WINDOWSMAJORVERSION_VISTA:*/
                        /*case WINDOWSMAJORVERSION_2008:*/
                        switch (osvi_ptr->dwMinorVersion) {
                            case 0:
                                /*case WINDOWSMINORVERSION_VISTA:*/
                                /*case WINDOWSMINORVERSION_2008:*/
                                switch (osvi_ptr->wProductType) {
                                    case VER_NT_WORKSTATION:
                                        version_code = (windowsversion_t) (WINDOWSVERSION_WINDOWSVISTA + product_type);
                                        break; /*end of case VER_NT_WORKSTATION:*/

                                    default:
                                        version_code = (windowsversion_t) (WINDOWSVERSION_WINDOWS2008 + product_type);
                                        break;  /*end of default:*/
                                }               /*end of switch(osvi_ptr->wProductType)*/
                                break;          /*end of case 0:*/

                            case 1:
                                /*case WINDOWSMINORVERSION_7:*/
                                /*case WINDOWSMINORVERSION_2008R2:*/
                                switch (osvi_ptr->wProductType) {
                                    case VER_NT_WORKSTATION:
                                        version_code = (windowsversion_t) (WINDOWSVERSION_WINDOWS7 + product_type);
                                        break; /*end of case VER_NT_WORKSTATION:*/

                                    default:
                                        version_code = (windowsversion_t) (WINDOWSVERSION_WINDOWS2008_R2 + product_type);
                                        break;  /*end of default:*/
                                } /*end of switch(osvi_ptr->wProductType)*/
                                break;          /*end of case 1:*/

                            case 2:
                                /*case WINDOWSMINORVERSION_8:*/
                                /*case WINDOWSMINORVERSION_2012:*/
                                switch (osvi_ptr->wProductType) {
                                    case VER_NT_WORKSTATION:
                                        version_code = (windowsversion_t) (WINDOWSVERSION_WINDOWS8 + product_type);
                                        break; /*end of case VER_NT_WORKSTATION:*/
                                    default:
                                        version_code = (windowsversion_t) (WINDOWSVERSION_WINDOWS2012 + product_type);
                                        break;  /*end of default:*/
                                } /*end of switch(osvi_ptr->wProductType)*/
                                break;          /*end of case 2:*/

                            case 3:
                                /*case WINDOWSMINORVERSION_8_1:*/
                                /*case WINDOWSMINORVERSION_2012R2:*/
                                switch (osvi_ptr->wProductType) {
                                    case VER_NT_WORKSTATION:
                                        version_code = (windowsversion_t) (WINDOWSVERSION_WINDOWS8_1 + product_type);
                                        break; /*end of case VER_NT_WORKSTATION:*/
                                    default:
                                        version_code = (windowsversion_t) (WINDOWSVERSION_WINDOWS2012R2 + product_type);
                                        break;  /*end of default:*/
                                } /*end of switch(osvi_ptr->wProductType)*/
                                break;          /*end of case 2:*/
                        }                       /*end of switch(osvi_ptr->dwMinorVersion)*/
                        break;                  /*end of case 6:*/

                    case 5:
                        /*case WINDOWSMAJORVERSION_2000:*/
                        /*case WINDOWSMAJORVERSION_2003:*/
                        /*case WINDOWSMAJORVERSION_XP:*/
                        switch (osvi_ptr->dwMinorVersion) {
                            case WINDOWSMINORVERSION_2003:
                                switch (osvi_ptr->wProductType) {
                                    case VER_NT_WORKSTATION:
                                        if (PROCESSOR_ARCHITECTURE_AMD64 == _sysinfo.wProcessorArchitecture) {
                                            version_code = WINDOWSVERSION_WINDOWSXP_PROFESSIONAL_X64;
                                        }
                                        break;

                                    default:
                                        version_code = WINDOWSVERSION_WINDOWS2003;

                                        switch (_sysinfo.wProcessorArchitecture) {
                                            case PROCESSOR_ARCHITECTURE_IA64:
                                                if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_DATACENTER)) {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_IA64_DATACENTER;
                                                } else if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_ENTERPRISE)) {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_IA64_ENTERPRISE;
                                                } else {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_IA64;
                                                }
                                                break;

                                            case PROCESSOR_ARCHITECTURE_AMD64:
                                                if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_DATACENTER)) {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_AMD64_DATACENTER;
                                                } else if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_ENTERPRISE)) {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_AMD64_ENTERPRISE;
                                                } else {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_AMD64;
                                                }
                                                break;

                                            case PROCESSOR_ARCHITECTURE_INTEL:
                                                if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_WH_SERVER)) {
                                                    version_code = WINDOWSVERSION_WINDOWSHOMESERVER;
                                                } else if (0 != GetSystemMetrics (SM_SERVERR2)) {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_R2;
                                                } else if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_DATACENTER)) {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_DATACENTER;
                                                } else if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_ENTERPRISE)) {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_ENTERPRISE;
                                                } else if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_BLADE)) {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_WEBEDITION;
                                                } else if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_STORAGE_SERVER)) {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_STORAGESERVER;
                                                } else {
                                                    version_code = WINDOWSVERSION_WINDOWS2003_STANDARD;
                                                }
                                                break;
                                        }       /*end of switch(_sysinfo.wProcessorArchitecture)*/
                                        break;  /*end of default:*/
                                }               /*end of switch(osvi_ptr->wProductType)*/
                                break;          /*end of case WINDOWSMINORVERSION_2003:*/

                            case WINDOWSMINORVERSION_XP:
                                version_code = WINDOWSVERSION_WINDOWSXP;

                                switch (osvi_ptr->wProductType) {
                                    case VER_NT_WORKSTATION:

                                        if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_PERSONAL)) {
                                            version_code = WINDOWSVERSION_WINDOWSXP_HOME;
                                        } else {
                                            version_code = WINDOWSVERSION_WINDOWSXP_PROFESSIONAL;
                                        }
                                        break;

                                    default:
                                        //version_code = WINDOWSVERSION_WINDOWSXP_SERVER;
                                        break;
                                }
                                break; /*end of case WINDOWSMINORVERSION_XP:*/

                            case WINDOWSMINORVERSION_2000:
                                version_code = WINDOWSVERSION_WINDOWS2000;

                                switch (osvi_ptr->wProductType) {
                                    case VER_NT_WORKSTATION:
                                        if (0 == (osvi_ptr->wSuiteMask & VER_SUITE_PERSONAL)) {
                                            version_code = WINDOWSVERSION_WINDOWS2000_PROFESSIONAL;
                                        }
                                        break;

                                    default:
                                        if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_DATACENTER)) {
                                            version_code = WINDOWSVERSION_WINDOWS2000SERVER_DATACENTER;
                                        } else if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_ENTERPRISE)) {
                                            version_code = WINDOWSVERSION_WINDOWS2000SERVER_ADVANCED;
                                        } else {
                                            version_code = WINDOWSVERSION_WINDOWS2000SERVER;
                                        }
                                        break;
                                }
                                break;  /*end of case WINDOWSMINORVERSION_2000:*/
                        }               /*end of switch(osvi_ptr->dwMinorVersion)*/
                        break;          /*end of case 5:*/

                    case 4:
                        /*case WINDOWSMAJORVERSION_NT4:*/
                        version_code = WINDOWSVERSION_WINDOWSNT4;

                        //if(windows_version_flag_t::winver_detect_getversion != (get_status ()() & windows_version_flag_t::winver_detect_getversion)) /* SP6 and later */
                        {
                            switch (osvi_ptr->wProductType) {
                                case VER_NT_WORKSTATION:
                                    version_code = WINDOWSVERSION_WINDOWSNT4_WORKSTATION;
                                    break;

                                default:
                                    /*case VER_NT_DOMAIN_CONTROLLER:*/
                                    /*case VER_NT_SERVER:*/
                                    if (0 != (osvi_ptr->wSuiteMask & VER_SUITE_ENTERPRISE)) {
                                        version_code = WINDOWSVERSION_WINDOWSNT4SERVER_ENTERPRISE;
                                    } else {
                                        version_code = WINDOWSVERSION_WINDOWSNT4SERVER;
                                    }
                                    break;
                            }
                        }
                        //else    /* SP5 and earlier */
                        {

                        }
                        break;  /*end of case 4:*/
                }               /*end of switch(osvi_ptr->dwMajorVersion)*/
                break;          /*end of case VER_PLATFORM_WIN32_NT:*/
        }                       /*end of switch(osvi_ptr->dwPlatformId)*/

        if (WINDOWSVERSION_UNKNOWN != version_code) {
            _version = version_code;

            _flags |= windows_version_flag_t::winver_test_version;
        } else {
            ret = errorcode_t::internal_error;
        }
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

}
}  // namespace
