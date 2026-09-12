/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_ODBC_TYPES__
#define __HOTPLACE_SDK_ODBC_TYPES__

#include <hotplace/sdk/base/system/error.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <hotplace/sdk/io/types.hpp>
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

struct odbc_category {};

template <typename T>
struct odbc_error_traits;

/* odbc specialization */
template <>
struct error_traits<SQLRETURN, odbc_category> {
    static constexpr SQLRETURN value_success() noexcept { return SQL_SUCCESS; }
    static constexpr SQLRETURN value_exception() noexcept { return SQL_ERROR; }
    static constexpr SQLRETURN value_invalid_parameter() noexcept { return SQL_INVALID_HANDLE; }
    static constexpr SQLRETURN value_internal_error() noexcept { return SQL_ERROR; }

    static constexpr bool is_success(SQLRETURN code) noexcept { return (SQL_SUCCESS == code) || (SQL_SUCCESS_WITH_INFO == code); }
    static constexpr bool is_not_fail(SQLRETURN code) noexcept { return is_success(code); }

    static constexpr bool is_invalid_handle(SQLRETURN code) noexcept { return SQL_INVALID_HANDLE == code; }

    static constexpr return_t to_return_t(SQLRETURN code) noexcept {
        return is_success(code) ? errorcode_t::success : (SQL_INVALID_HANDLE == code ? errorcode_t::invalid_context : errorcode_t::internal_error);
    }
    static constexpr SQLRETURN from_return_t(return_t code) noexcept { return error_traits<return_t>::is_success(code) ? value_success() : value_internal_error(); }

    static constexpr bool compare(SQLRETURN lhs, return_t rhs) noexcept { return to_return_t(lhs) == rhs; }
    static constexpr bool compare(return_t lhs, SQLRETURN rhs) noexcept { return lhs == to_return_t(rhs); }
};

using namespace io;
namespace odbc {

enum sql_query_mode_t { sync_query = 0, async_query };

class odbc_connector;
class odbc_diagnose;
class odbc_field;
class odbc_query;
class odbc_record;

}  // namespace odbc
}  // namespace hotplace

#endif
