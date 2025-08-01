/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_SHLWAPI__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_SHLWAPI__

// #include <shlwapi.h>

/* "SHLoadIndirectString" */
#define DECLARE_NAMEOF_API_SHLOADINDIRECTSTRING                                                                \
    CHAR NAMEOF_API_SHLOADINDIRECTSTRING[] = {                                                                 \
        'S', 'H', 'L', 'o', 'a', 'd', 'I', 'n', 'd', 'i', 'r', 'e', 'c', 't', 'S', 't', 'r', 'i', 'n', 'g', 0, \
    };

typedef HRESULT(__stdcall* SHLOADINDIRECTSTRING)(LPCWSTR pszSource, LPWSTR pszOutBuf, UINT cchOutBuf, void** ppvReserved);

#if _MSC_FULL_VER >= 140050727
#include <PortableDevice.h>
#include <PortableDeviceApi.h>
#include <PortableDeviceTypes.h>
#include <shlwapi.h>
#else

/* file scope definition */
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501

/* sal */
#ifndef __MINGW32__
#include "psdk_rpcsal.h"
#include "psdk_specstrings.h"
#endif

/* REFPROPVARIANT (Microsoft SDKs/Windows/v6.0A/Include/PropIdl.h) */
#ifdef MIDL_PASS
// This is the LPPROPVARIANT definition for marshaling.
typedef struct tag_inner_PROPVARIANT* LPPROPVARIANT;

typedef const PROPVARIANT* REFPROPVARIANT;

#else

// This is the standard C layout of the PROPVARIANT.
typedef struct tagPROPVARIANT* LPPROPVARIANT;

#ifndef _REFPROPVARIANT_DEFINED
#define _REFPROPVARIANT_DEFINED
#ifdef __cplusplus
#define REFPROPVARIANT const PROPVARIANT&
#else
#define REFPROPVARIANT const PROPVARIANT* __MIDL_CONST
#endif
#endif

#endif  // MIDL_PASS

/* PROPERTYKEY (Microsoft SDKs/Windows/v6.0A/Include/WTypes.h) */
#ifndef PROPERTYKEY_DEFINED
#define PROPERTYKEY_DEFINED
typedef struct _tagpropertykey {
    GUID fmtid;
    DWORD pid;
} PROPERTYKEY;
#endif

/* SHCOLSTATEF (Microsoft SDKs/Windows/v6.0A/Include/shtypes.h) */
typedef DWORD SHCOLSTATEF;

/**
 * 1. Windows/6.0A ����
 * ; Visual Studio 2008 (9.0) SDK ��� Microsoft SDKs/Windows/v6.0A/Include �� ���� ���� ���� ����
 *
 * 1) Microsoft SDKs/Windows/v6.0A/Include/PortableDevice.h ����
 * 2) Microsoft SDKs/Windows/v6.0A/Include/PortableDeviceApi.h �� Microsoft SDKs/Windows/v6.0A/Include/PortableDeviceTypes.h ���� �� ����
 *    #define __REQUIRED_RPCNDR_H_VERSION__ 500 �� 475 ����
 * 3) propsys.h ���� �� ����
 *    #include <propkeydef.h> �κ��� "propkeydef.h" ����
 * 4) Microsoft SDKs/Windows/v6.0A/Include/propkeydef.h, Microsoft SDKs/Windows/v6.0A/Include/structuredquery.h ����
 *
 * 2. PortableDeviceGuids.lib
 * #pragma comment (lib, "PortableDeviceGUIDs")
 * ; ����� �ܺ� ���̺귯�� ��ο� ������ �� (���� Helper/Trunk/Srs/Test/PortableDevice �� ����)
 */
#ifdef _MSC_VER
#include <sdk/base/system/windows/sdk/v6.0A/PortableDevice.h>
#include <sdk/base/system/windows/sdk/v6.0A/PortableDeviceApi.h>
#include <sdk/base/system/windows/sdk/v6.0A/PortableDeviceTypes.h>
#endif

/**
 * WinNT.h (Microsoft SDKs/Windows/v6.0A/Include/WinNT.h)
 * 1) IFACEMETHODIMP
 * 2) IFACEMETHODIMP_
 */
#ifndef IFACEMETHODIMP
#define IFACEMETHODIMP __override STDMETHODIMP
#endif

#ifndef IFACEMETHODIMP_
#define IFACEMETHODIMP_(type) __override STDMETHODIMP_(type)
#endif

/**
 *
 */
#define _In_

/**
 * VC6 shlwapi.h ȥ�뿡 ���� ������ ���� ȸ��
 * - from Microsoft SDKs/Windows/v6.0A/Include/shlwapi.h
 * 1) STATIC_CAST
 * 2) OFFSETOFCLASS, QITAB, QITABENT
 * 3) QISearch GetProcAddress ������� ���
 */
#define STATIC_CAST(typ) static_cast<typ>

#ifndef OFFSETOFCLASS
//***   OFFSETOFCLASS -- (stolen from ATL)
// we use STATIC_CAST not SAFE_CAST because the compiler gets confused
// (it doesn't constant-fold the ,-op in SAFE_CAST so we end up generating
// code for the table!)

#define OFFSETOFCLASS(base, derived) ((DWORD)(DWORD_PTR)(STATIC_CAST(base*)((derived*)8)) - 8)
#endif

typedef struct {
    const IID* piid;
    int dwOffset;
} QITAB, *LPQITAB;
typedef const QITAB* LPCQITAB;

#ifdef __cplusplus

#define QITABENTMULTI(Cthis, Ifoo, Iimpl) {&__uuidof(Ifoo), OFFSETOFCLASS(Iimpl, Cthis)}

#else

#define QITABENTMULTI(Cthis, Ifoo, Iimpl) {(IID*)&IID_##Ifoo, OFFSETOFCLASS(Iimpl, Cthis)}

#endif  // __cplusplus

#define QITABENTMULTI2(Cthis, Ifoo, Iimpl) {(IID*)&Ifoo, OFFSETOFCLASS(Iimpl, Cthis)}

#define QITABENT(Cthis, Ifoo) QITABENTMULTI(Cthis, Ifoo, Ifoo)

/* shlwapi.dll QISearch */

#endif

/* "QISearch" */
#define DECLARE_NAMEOF_API_QISEARCH                \
    CHAR NAMEOF_API_QISEARCH[] = {                 \
        'Q', 'I', 'S', 'e', 'a', 'r', 'c', 'h', 0, \
    };

typedef HRESULT(__stdcall* QISEARCH)(__inout void* that, ___in LPCQITAB pqit, ___in REFIID riid, __deref_out void** ppv);

#endif
