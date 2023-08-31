/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      version check
 *      - IsWindows10OrGreater (), IsWindowsServer ()
 *      - Windows 10 or newer
 *      - Windows Server 2016 or newer
 *      not identifiable
 *      - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
 *      -  ProductName, CurrentVersion
 *      identifiable
 *      - Win32_OperatingSystem::Caption
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_WINDOWSVERSION__
#define __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_WINDOWSVERSION__

#include <hotplace/sdk/io/system/sdk.hpp>

namespace hotplace {
namespace io {

enum windows_version_flag_t {
    winver_detect_getversion            = (1 << 0), ///<< 0000 0001 detect_getversion
    winver_detect_version_lie           = (1 << 1), ///<< 0000 0010 detect_versionlie
    winver_detect_compatibility_mode    = (1 << 2), ///<< 0000 0100 detect_versionlie compatibility mode
    winver_test_version                 = (1 << 3), ///<< 0000 1000 detect_version
    winver_detected                     = (1 << 7),
};

enum WINDOWSVERSION_MAJORVERSION {
    WINDOWSMAJORVERSION_95      = 4,
    WINDOWSMAJORVERSION_98      = 4,
    WINDOWSMAJORVERSION_ME      = 4,
    WINDOWSMAJORVERSION_NT3     = 3,
    WINDOWSMAJORVERSION_NT4     = 4,
    WINDOWSMAJORVERSION_2000    = 5,
    WINDOWSMAJORVERSION_2003    = 5,
    WINDOWSMAJORVERSION_XP      = 5,
    WINDOWSMAJORVERSION_VISTA   = 6,
    WINDOWSMAJORVERSION_2008    = 6,
    WINDOWSMAJORVERSION_7       = 6,
    WINDOWSMAJORVERSION_8       = 6,
    WINDOWSMAJORVERSION_2012    = 6,
    WINDOWSMAJORVERSION_10      = 10,
    WINDOWSMAJORVERSION_11      = 10,
    WINDOWSMAJORVERSION_2016    = 10,
    WINDOWSMAJORVERSION_2019    = 10,
    WINDOWSMAJORVERSION_2022    = 10,
};

enum WINDOWSVERSION_MINORVERSION {
    /* major 4 */
    WINDOWSMINORVERSION_95      = 0,    /* WINDOWSMAJORVERSION_95       4 */
    WINDOWSMINORVERSION_98      = 10,   /* WINDOWSMAJORVERSION_98       4 */
    WINDOWSMINORVERSION_ME      = 90,   /* WINDOWSMAJORVERSION_ME       4 */
    WINDOWSMINORVERSION_NT4     = 0,    /* WINDOWSMAJORVERSION_NT4      4 */
    /* major 5 */
    WINDOWSMINORVERSION_2000    = 0,    /* WINDOWSMAJORVERSION_2000     5 */
    WINDOWSMINORVERSION_2003    = 2,    /* WINDOWSMAJORVERSION_2003     5 */
    WINDOWSMINORVERSION_XP      = 1,    /* WINDOWSMAJORVERSION_XP       5 */
    /* major 6 */
    WINDOWSMINORVERSION_VISTA   = 0,    /* WINDOWSMAJORVERSION_VISTA    6 */
    WINDOWSMINORVERSION_2008    = 0,    /* WINDOWSMAJORVERSION_2008     6 */
    WINDOWSMINORVERSION_2008R2  = 1,    /* WINDOWSMAJORVERSION_2008     6 */
    WINDOWSMINORVERSION_7       = 1,    /* WINDOWSMAJORVERSION_7        6 */
    WINDOWSMINORVERSION_8       = 2,    /* WINDOWSMAJORVERSION_8        6 */
    WINDOWSMINORVERSION_8_1     = 3,    /* WINDOWSMAJORVERSION_8        6 */
    WINDOWSMINORVERSION_2012    = 2,    /* WINDOWSMAJORVERSION_2012     6 */
    WINDOWSMINORVERSION_2012R2  = 3,    /* WINDOWSMAJORVERSION_2012     6 */
    WINDOWSMINORVERSION_10      = 0,    /* WINDOWSMAJORVERSION_10      10 */
    WINDOWSMINORVERSION_11      = 0,    /* WINDOWSMAJORVERSION_11      10 */
    WINDOWSMINORVERSION_2016    = 0,    /* WINDOWSMAJORVERSION_2016    10 */
    WINDOWSMINORVERSION_2019    = 0,
    WINDOWSMINORVERSION_2022    = 0,
};

/*
 * (major << 24) | (minor << 16) | (platform << 8) | (Windows Product)
 *
 * platform
 * VER_NT_WORKSTATION = 0x00000001
 * VER_NT_DOMAIN_CONTROLLER = 0x00000002
 * VER_NT_SERVER = 0x00000003
 */
#define DEFINE_WINDOWSVERSION_OS(a, b, c, d) ((a << 24) | (b << 16) | (c << 8) | (d))

enum windowsversion_t {
    WINDOWSVERSION_UNKNOWN
        = 0,

    WINDOWSVERSION_WINDOWS95
        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_95, WINDOWSMINORVERSION_95, 0, 0),
    WINDOWSVERSION_WINDOWS95_OSR2,

    WINDOWSVERSION_WINDOWS98
        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_98, WINDOWSMINORVERSION_98, 0, 0),
    WINDOWSVERSION_WINDOWS98_SE,

    WINDOWSVERSION_WINDOWSME
        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_ME, WINDOWSMINORVERSION_ME, 0, 0),

    WINDOWSVERSION_WINDOWSNT3
        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_NT3, 0, VER_NT_WORKSTATION, 0),
    WINDOWSVERSION_WINDOWSNT351,

    WINDOWSVERSION_WINDOWSNT4
        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_NT4, WINDOWSMINORVERSION_NT4, VER_NT_WORKSTATION, 0),
    WINDOWSVERSION_WINDOWSNT4_WORKSTATION,

    WINDOWSVERSION_WINDOWSNT4SERVER
        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_NT4, WINDOWSMINORVERSION_NT4, VER_NT_SERVER, 0),
    WINDOWSVERSION_WINDOWSNT4SERVER_ENTERPRISE,

    WINDOWSVERSION_WINDOWS2000
        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_2000, WINDOWSMINORVERSION_2000, VER_NT_WORKSTATION, 0),
    WINDOWSVERSION_WINDOWS2000_PROFESSIONAL,

    WINDOWSVERSION_WINDOWS2000SERVER
        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_2000, WINDOWSMINORVERSION_2000, VER_NT_SERVER, 0),
    WINDOWSVERSION_WINDOWS2000SERVER_DATACENTER,
    WINDOWSVERSION_WINDOWS2000SERVER_ADVANCED,

    WINDOWSVERSION_WINDOWSXP
        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_XP, WINDOWSMINORVERSION_XP, VER_NT_WORKSTATION, 0),
    WINDOWSVERSION_WINDOWSXP_HOME,
    WINDOWSVERSION_WINDOWSXP_PROFESSIONAL,
    WINDOWSVERSION_WINDOWSXP_PROFESSIONAL_X64,
    WINDOWSVERSION_WINDOWSXP_SERVER,

    WINDOWSVERSION_WINDOWS2003
        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_2003, WINDOWSMINORVERSION_2003, VER_NT_SERVER, 0),
    WINDOWSVERSION_WINDOWS2003_STANDARD,
    WINDOWSVERSION_WINDOWS2003_ENTERPRISE,
    WINDOWSVERSION_WINDOWS2003_DATACENTER,
    WINDOWSVERSION_WINDOWS2003_WEBEDITION,
    WINDOWSVERSION_WINDOWS2003_IA64,
    WINDOWSVERSION_WINDOWS2003_IA64_ENTERPRISE,
    WINDOWSVERSION_WINDOWS2003_IA64_DATACENTER,
    WINDOWSVERSION_WINDOWS2003_AMD64,
    WINDOWSVERSION_WINDOWS2003_AMD64_ENTERPRISE,
    WINDOWSVERSION_WINDOWS2003_AMD64_DATACENTER,
    WINDOWSVERSION_WINDOWS2003_R2,
    WINDOWSVERSION_WINDOWSHOMESERVER,
    WINDOWSVERSION_WINDOWS2003_STORAGESERVER,

    /*
     * @remarks Windows Vista 부터 다음 정보를 참고한다.
     *          (major << 24) | (minor << 16) | (platform << 8) | (Windows Product)
     *
     *          PRODUCT_UNDEFINED                           0x00    * An unknown product
     *
     *          PRODUCT_STARTER                             0x0B    Starter, 6.0.0.0
     *          PRODUCT_STARTER_E                           0x42    * Not supported
     *          PRODUCT_STARTER_N                           0x2F    Starter N, 6.1.0.0
     *
     *          PRODUCT_HOME_BASIC                          0x02    Home Basic
     *          PRODUCT_HOME_BASIC_E                        0x43    * Not supported
     *          PRODUCT_HOME_BASIC_N                        0x05    Home Basic N
     *
     *          PRODUCT_HOME_PREMIUM                        0x03    Home Premium
     *          PRODUCT_HOME_PREMIUM_E                      0x44    * Not supported
     *          PRODUCT_HOME_PREMIUM_N                      0x1A    Home Premium N
     *
     *          PRODUCT_BUSINESS                            0x06    Business, 6.0.0.0
     *          PRODUCT_BUSINESS_N                          0x10    Business N, 6.0.0.0
     *
     *          PRODUCT_CLUSTER_SERVER                      0x12    HPC Edition
     *          PRODUCT_CLUSTER_SERVER_V                    0x40    Server Hyper Core V
     *
     *          PRODUCT_CORE_N                              0x62    Windows 8 N
     *          PRODUCT_CORE_COUNTRYSPECIFIC                0x63    Windows 8 China
     *          PRODUCT_CORE_SINGLELANGUAGE                 0x64    Windows 8 Single Language
     *          PRODUCT_CORE                                0x65    Windows 8, Windows 10 Home
     *
     *          PRODUCT_DATACENTER_SERVER                   0x08    Server Datacenter (full installation)
     *          PRODUCT_DATACENTER_SERVER_CORE              0x0C    Server Datacenter (core installation)
     *          PRODUCT_DATACENTER_SERVER_CORE_V            0x27    Server Datacenter without Hyper-V (core installation)
     *          PRODUCT_DATACENTER_SERVER_V                 0x25    Server Datacenter without Hyper-V (full installation)
     *          PRODUCT_DATACENTER_A_SERVER_CORE            0x91    Server Datacenter, Semi-Annual Channel (core installation)
     *          PRODUCT_DATACENTER_EVALUATION_SERVER        0x50    Server Datacenter (evaluation installation)
     *
     *          PRODUCT_EDUCATION                           0x79    Windows 10 Education
     *          PRODUCT_EDUCATION_N                         0x7A    Windows 10 Education N
     *
     *          PRODUCT_ENTERPRISE                          0x04    Enterprise
     *          PRODUCT_ENTERPRISE_E                        0x46    * Not supported
     *          PRODUCT_ENTERPRISE_N                        0x1B    Enterprise N
     *
     *          PRODUCT_ENTERPRISE_SERVER                   0x0A    Server Enterprise (full installation)
     *          PRODUCT_ENTERPRISE_SERVER_CORE              0x0E    Server Enterprise (core installation)
     *          PRODUCT_ENTERPRISE_SERVER_CORE_V            0x29    Server Enterprise without Hyper-V (core installation)
     *          PRODUCT_ENTERPRISE_SERVER_IA64              0x0F    Server Enterprise for Itanium-based Systems
     *          PRODUCT_ENTERPRISE_SERVER_V                 0x26    Server Enterprise without Hyper-V (full installation)
     *          PRODUCT_ENTERPRISE_EVALUATION               0x48    Server Enterprise (evaluation installation)
     *          PRODUCT_ENTERPRISE_S                        0x7D    Windows 10 Enterprise 2015 LTSB
     *          PRODUCT_ENTERPRISE_S_N                      0x7E    Windows 10 Enterprise 2015 LTSB N
     *          PRODUCT_ENTERPRISE_S_N_EVALUATION           0x82    Windows 10 Enterprise 2015 LTSB N Evaluation
     *          PRODUCT_ENTERPRISE_N_EVALUATION             0x54    Enterprise N (evaluation installation)
     *          PRODUCT_ENTERPRISE_S_EVALUATION             0x81    Windows 10 Enterprise 2015 LTSB Evaluation
     *
     *          PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT       0x3B    Windows Essential Server Solution Management
     *          PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL       0x3C    Windows Essential Server Solution Additional
     *          PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC    0x3D    Windows Essential Server Solution Management SVC
     *          PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC    0x3E    Windows Essential Server Solution Additional SVC
     *
     *          PRODUCT_IOTENTERPRISE                       0xBC    Windows IoT Enterprise
     *          PRODUCT_IOTENTERPRISE_S                     0xBF    Windows IoT Enterprise LTSC
     *          PRODUCT_IOTUAP                              0x7B    Windows 10 IoT Core
     *          PRODUCT_IOTUAPCOMMERCIAL                    0x83    Windows 10 IoT Core Commercial
     *
     *          PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT    0x1E    Windows Essential Business Server Management Server
     *          PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING     0x20    Windows Essential Business Server Messaging Server
     *          PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY      0x1F    Windows Essential Business Server Security Server
     *
     *          PRODUCT_MOBILE_CORE                         0x68    Windows 10 Mobile
     *          PRODUCT_MOBILE_ENTERPRISE                   0x85    Windows 10 Mobile Enterprise
     *
     *          PRODUCT_MULTIPOINT_STANDARD_SERVER          0x4C    Windows MultiPoint Server Standard (full installation)
     *          PRODUCT_MULTIPOINT_PREMIUM_SERVER           0x4D    Windows MultiPoint Server Premium (full installation)
     *
     *          PRODUCT_HOME_PREMIUM_SERVER                 0x22    Windows Home Server 2011
     *          PRODUCT_HOME_SERVER                         0x13    Windows Storage Server 2008 R2 Essentials
     *
     *          PRODUCT_HYPERV                              0x2A    Microsoft Hyper-V Server
     *
     *          PRODUCT_PPI_PRO                             0x77    Windows 10 Team
     *
     *          PRODUCT_PRO_FOR_EDUCATION                   0xA4    Windows 10 Pro Education
     *          PRODUCT_PRO_WORKSTATION                     0xA1    Windows 10 Pro for Workstations
     *          PRODUCT_PRO_WORKSTATION_N                   0xA2    Windows 10 Pro for Workstations N
     *
     *          PRODUCT_PROFESSIONAL                        0x30    Professional, 6.1.0.0
     *          PRODUCT_PROFESSIONAL_E                      0x45    * Not supported
     *          PRODUCT_PROFESSIONAL_N                      0x31    Professional N, 6.1.0.0
     *          PRODUCT_PROFESSIONAL_WMC                    0x67    Professional with Media Center
     *
     *          PRODUCT_SB_SOLUTION_SERVER                  0x32    Windows Small Business Server 2011 Essentials
     *          PRODUCT_SB_SOLUTION_SERVER_EM               0x36    Server For SB Solutions EM
     *
     *          PRODUCT_SERVER_FOR_SMALLBUSINESS            0x18    Windows Server 2008 for Windows Essential Server Solutions
     *          PRODUCT_SERVER_FOR_SMALLBUSINESS_V          0x23    Windows Server 2008 without Hyper-V for Windows Essential Server Solutions
     *          PRODUCT_SERVER_FOR_SB_SOLUTIONS             0x33    Server For SB Solutions
     *          PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM          0x37    Server For SB Solutions EM
     *          PRODUCT_SERVER_FOUNDATION                   0x21    Server Foundation
     *
     *          PRODUCT_SERVERRDSH                          0xAF    Windows 10 Enterprise for Virtual Desktops
     *
     *          PRODUCT_SMALLBUSINESS_SERVER                0x09    Windows Small Business Server
     *          PRODUCT_SMALLBUSINESS_SERVER_PREMIUM        0x19    Windows Small Business Server Premium
     *          PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE   0x3F    Small Business Server Premium (core installation)
     *
     *          PRODUCT_SOLUTION_EMBEDDEDSERVER             0x38    Windows MultiPoint Server
     *
     *          PRODUCT_STANDARD_SERVER                     0x07    Server Standard (full installation)
     *          PRODUCT_STANDARD_SERVER_CORE                0x0D    Server Standard (core installation)
     *          PRODUCT_STANDARD_SERVER_CORE_V              0x28    Server Standard without Hyper-V (core installation)
     *          PRODUCT_STANDARD_SERVER_V                   0x24    Server Standard without Hyper-V (full installation)
     *          PRODUCT_STANDARD_A_SERVER_CORE              0x92    Server Standard, Semi-Annual Channel (core installation)
     *          PRODUCT_STANDARD_SERVER_SOLUTIONS           0x34    Server Solutions Premium
     *          PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE      0x35    Server Solutions Premium (core installation)
     *          PRODUCT_STANDARD_EVALUATION_SERVER          0x4F    Server Standard (evaluation installation)
     *
     *          PRODUCT_STORAGE_ENTERPRISE_SERVER           0x17    Storage Server Enterprise
     *          PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE      0x2E    Storage Server Enterprise (core installation)
     *          PRODUCT_STORAGE_EXPRESS_SERVER              0x14    Storage Server Express
     *          PRODUCT_STORAGE_EXPRESS_SERVER_CORE         0x2B    Storage Server Express (core installation)
     *          PRODUCT_STORAGE_STANDARD_SERVER             0x15    Storage Server Standard
     *          PRODUCT_STORAGE_STANDARD_SERVER_CORE        0x2C    Storage Server Standard (core installation)
     *          PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER  0x60    Storage Server Standard (evaluation installation)
     *          PRODUCT_STORAGE_WORKGROUP_SERVER            0x16    Storage Server Workgroup
     *          PRODUCT_STORAGE_WORKGROUP_SERVER_CORE       0x2D    Storage Server Workgroup (core installation)
     *          PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER 0x5F    Storage Server Workgroup (evaluation installation)
     *
     *          PRODUCT_ULTIMATE                            0x01    Ultimate
     *          PRODUCT_ULTIMATE_E                          0x47    * Not supported
     *          PRODUCT_ULTIMATE_N                          0x1C    Ultimate N
     *
     *          PRODUCT_WEB_SERVER                          0x11    Web Server (full installation)
     *          PRODUCT_WEB_SERVER_CORE                     0x1D    Web Server (core installation)
     */
    WINDOWSVERSION_WINDOWSVISTA     = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_VISTA, WINDOWSMINORVERSION_VISTA, VER_NT_WORKSTATION, 0),
    WINDOWSVERSION_WINDOWS2008      = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_2008, WINDOWSMINORVERSION_2008, VER_NT_SERVER, 0),
    WINDOWSVERSION_WINDOWS2008_R2   = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_2008, WINDOWSMINORVERSION_2008R2, VER_NT_SERVER, 0),
    WINDOWSVERSION_WINDOWS7         = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_7, WINDOWSMINORVERSION_7, VER_NT_WORKSTATION, 0),
    WINDOWSVERSION_WINDOWS8         = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_8, WINDOWSMINORVERSION_8, VER_NT_WORKSTATION, 0),
    WINDOWSVERSION_WINDOWS8_1       = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_8, WINDOWSMINORVERSION_8_1, VER_NT_WORKSTATION, 0),
    WINDOWSVERSION_WINDOWS2012      = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_2012, WINDOWSMINORVERSION_2012, VER_NT_SERVER, 0),
    WINDOWSVERSION_WINDOWS2012R2    = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_2012, WINDOWSMINORVERSION_2012R2, VER_NT_SERVER, 0),
    WINDOWSVERSION_WINDOWS10        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_10, WINDOWSMINORVERSION_10, VER_NT_WORKSTATION, 0),
    WINDOWSVERSION_WINDOWS11        = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_11, WINDOWSMINORVERSION_11, VER_NT_WORKSTATION, 0),
    WINDOWSVERSION_WINDOWS2016      = DEFINE_WINDOWSVERSION_OS (WINDOWSMAJORVERSION_2016, WINDOWSMINORVERSION_2016, VER_NT_SERVER, 0),
};

enum WINDOWSVERSION_FORMAT {
    WINDOWSVERSION_FORMAT_EDITION               = 0,    /* Microsoft Windows 7 Professional KN */
    WINDOWSVERSION_FORMAT_EDITION_SP            = 1,    /* Microsoft Windows 7 Professional KN Service Pack 1 */
    WINDOWSVERSION_FORMAT_EDITION_SP_BUILD      = 2,    /* Microsoft Windows 7 Professional KN Service Pack 1 (7601) */
    WINDOWSVERSION_FORMAT_EDITION_SP_BUILD_BITS = 3,    /* Microsoft Windows 7 Professional KN Service Pack 1 (7601) 64-bit */
};

class windows_version
{
public:
    static windows_version* get_instance ();
    ~windows_version ();

    const OSVERSIONINFOEXA* get_osvi ();

protected:
    windows_version ();

    return_t detect ();

    return_t detect_getversion ();
    return_t detect_versionlie ();
    return_t detect_version ();

private:
    static windows_version _instance;
    /*
     * _osvi_getversion.dwPlatformId
     *          VER_PLATFORM_WIN32_WINDOWS
     *          VER_PLATFORM_WIN32_NT
     * _osvi_getversion.wProductType
     *          VER_NT_DOMAIN_CONTROLLER
     *          VER_NT_SERVER
     *          VER_NT_WORKSTATION
     */
    OSVERSIONINFOEXA _osvi_getversion;      ///<< reflect compatibility mode
    OSVERSIONINFOEXW _osvi_getversionexw;   ///<< reflect compatibility mode
    OSVERSIONINFOEXA _osvi_vercond;         ///<< regardless of compatibility mode
    /*
     *  _sysinfo.wProcessorArchitecture
     *          PROCESSOR_ARCHITECTURE_AMD64   9
     *          PROCESSOR_ARCHITECTURE_IA64    6
     *          PROCESSOR_ARCHITECTURE_INTEL   0
     *          PROCESSOR_ARCHITECTURE_UNKNOWN 0xffff
     */
    SYSTEM_INFO _sysinfo;

    windowsversion_t _version;  ///<< version
    uint32 _flags;              ///<< see windows_version_flag_t
    uint32 _max_verfify;        ///<< always _max_verfify > max(platform_id, major, minor, servicepack_major, servicepack_minor, product_type)
};

}
}  // namespace

#endif
