/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_ODBC_TYPES__
#define __HOTPLACE_SDK_ODBC_TYPES__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/system/sdk.hpp>
#define SQL_WCHART_CONVERT
#include <sql.h>
#include <sqlext.h>
#include <sqlucode.h>

#include <string>

#if !defined SQL_TCHAR
#if defined _MBCS || defined MBCS
#define SQL_TCHAR SQL_CHAR
#elif defined _UNICODE || defined UNICODE
#define SQL_TCHAR SQL_WCHAR
#endif
#endif

#ifndef SQL_SUCCEEDED
#define SQL_SUCCEEDED(rc) (rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO)
#endif

namespace hotplace {
namespace odbc {

enum sql_query_mode_t { sync_query = 0, async_query };

}
}  // namespace hotplace

#endif
