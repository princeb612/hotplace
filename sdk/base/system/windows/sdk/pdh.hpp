/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab textwidth=130 colorcolumn=+1: */
/**
 * @file pdh.h
 * @author Soo Han, Kim (hush@ahnlab.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_PDH__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_PDH__

#define DLLNAME_PDH         TEXT ("pdh.dll")

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_PDHOPENQUERY DECLARE_NAMEOF_API_PDHOPENQUERYA

#define NAMEOF_API_PDHOPENQUERY         NAMEOF_API_PDHOPENQUERYA
#define PDHOPENQUERY                    PDHOPENQUERYA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_PDHOPENQUERY DECLARE_NAMEOF_API_PDHOPENQUERYW

#define NAMEOF_API_PDHOPENQUERY         NAMEOF_API_PDHOPENQUERYW
#define PDHOPENQUERY                    PDHOPENQUERYW
#endif

/* "PdhOpenQueryA" */
#define DECLARE_NAMEOF_API_PDHOPENQUERYA char NAMEOF_API_PDHOPENQUERYA[] = { 'P', 'd', 'h', 'O', 'p', 'e', 'n', 'Q', 'u', 'e', 'r', 'y', 'A', 0, };
/* "PdhOpenQueryW" */
#define DECLARE_NAMEOF_API_PDHOPENQUERYW char NAMEOF_API_PDHOPENQUERYW[] = { 'P', 'd', 'h', 'O', 'p', 'e', 'n', 'Q', 'u', 'e', 'r', 'y', 'W', 0, };

/* @brief
    Creates a new query that is used to manage the collection of performance data.
    To use handles to data sources, use the PdhOpenQueryH function.
 */
typedef PDH_STATUS (__stdcall* PDHOPENQUERYA)(
    ___in LPCSTR szDataSource,
    ___in DWORD_PTR dwUserData,
    ___out PDH_HQUERY *            phQuery
    );

typedef PDH_STATUS (__stdcall* PDHOPENQUERYW)(
    ___in LPCWSTR szDataSource,
    ___in DWORD_PTR dwUserData,
    ___out PDH_HQUERY *            phQuery
    );

/* "PdhCloseQuery" */
#define DECLARE_NAMEOF_API_PDHCLOSEQUERY char NAMEOF_API_PDHCLOSEQUERY[] = { 'P', 'd', 'h', 'C', 'l', 'o', 's', 'e', 'Q', 'u', 'e', 'r', 'y', 0, };

/* @brief
    Closes all counters contained in the specified query, closes all handles related to the query, and frees all memory associated with the query.
 */
typedef PDH_STATUS (__stdcall* PDHCLOSEQUERY)(
    ___in PDH_HQUERY hQuery
    );

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_PDHADDCOUNTER    DECLARE_NAMEOF_API_PDHADDCOUNTERA

#define NAMEOF_API_PDHADDCOUNTER            NAMEOF_API_PDHADDCOUNTERA
#define PDHADDCOUNTER                       PDHADDCOUNTERA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_PDHADDCOUNTER    DECLARE_NAMEOF_API_PDHADDCOUNTERW

#define NAMEOF_API_PDHADDCOUNTER            NAMEOF_API_PDHADDCOUNTERW
#define PDHADDCOUNTER                       PDHADDCOUNTERW
#endif

/* "PdhAddCounterA" */
#define DECLARE_NAMEOF_API_PDHADDCOUNTERA char NAMEOF_API_PDHADDCOUNTERA[] = { 'P', 'd', 'h', 'A', 'd', 'd', 'C', 'o', 'u', 'n', 't', 'e', 'r', 'A', 0, };
/* "PdhAddCounterW" */
#define DECLARE_NAMEOF_API_PDHADDCOUNTERW char NAMEOF_API_PDHADDCOUNTERW[] = { 'P', 'd', 'h', 'A', 'd', 'd', 'C', 'o', 'u', 'n', 't', 'e', 'r', 'W', 0, };

/* @brief
    Adds the specified counter to the query.
 */
typedef PDH_STATUS (__stdcall* PDHADDCOUNTERA)(
    ___in PDH_HQUERY hQuery,
    ___in LPCSTR szFullCounterPath,
    ___in DWORD_PTR dwUserData,
    ___out PDH_HCOUNTER *          phCounter
    );

typedef PDH_STATUS (__stdcall* PDHADDCOUNTERW)(
    ___in PDH_HQUERY hQuery,
    ___in LPCWSTR szFullCounterPath,
    ___in DWORD_PTR dwUserData,
    ___out PDH_HCOUNTER *          phCounter
    );

/* "PdhRemoveCounter" */
#define DECLARE_NAMEOF_API_PDHREMOVECOUNTER char NAMEOF_API_PDHREMOVECOUNTER[] = { 'P', 'd', 'h', 'R', 'e', 'm', 'o', 'v', 'e', 'C', 'o', 'u', 'n', 't', 'e', 'r', 0, };

/* @brief
    Removes a counter from a query.
 */
typedef PDH_STATUS (__stdcall* PDHREMOVECOUNTER)(
    ___in PDH_HCOUNTER hCounter
    );

/* "PdhCollectQueryData" */
#define DECLARE_NAMEOF_API_PDHCOLLECTQUERYDATA char NAMEOF_API_PDHCOLLECTQUERYDATA[] = { 'P', 'd', 'h', 'C', 'o', 'l', 'l', 'e', 'c', 't', 'Q', 'u', 'e', 'r', 'y', 'D', 'a', 't', 'a', 0, };

/* @brief
    Collects the current raw data value for all counters in the specified query and updates the status code of each counter.
 */
typedef PDH_STATUS (__stdcall* PDHCOLLECTQUERYDATA)(
    __inout PDH_HQUERY hQuery
    );

/* "PdhGetFormattedCounterValue" */
#define DECLARE_NAMEOF_API_PDHGETFORMATTEDCOUNTERVALUE char NAMEOF_API_PDHGETFORMATTEDCOUNTERVALUE[] = { 'P', 'd', 'h', 'G', 'e', 't', 'F', 'o', 'r', 'm', 'a', 't', 't', 'e', 'd', 'C', 'o', 'u', 'n', 't', 'e', 'r', 'V', 'a', 'l', 'u', 'e', 0, };

/* @brief
    Computes a displayable value for the specified counter.
 */
typedef PDH_STATUS (__stdcall* PDHGETFORMATTEDCOUNTERVALUE)(
    ___in PDH_HCOUNTER hCounter,
    ___in DWORD dwFormat,
    ___out LPDWORD lpdwType,
    ___out PPDH_FMT_COUNTERVALUE pValue
    );

#endif
