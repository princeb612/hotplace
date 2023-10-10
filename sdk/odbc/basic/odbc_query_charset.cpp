/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/stream/string.hpp>
#include <hotplace/sdk/odbc/basic/odbc_diagnose.hpp>
#include <hotplace/sdk/odbc/basic/odbc_query.hpp>

namespace hotplace {
using namespace io;
namespace odbc {

return_t odbc_query::query(LPCTSTR query_string, ...) {
    return_t ret = errorcode_t::success;
    va_list ap;

    __try2 {
        va_start(ap, query_string);

        switch (_sql_mode) {
            case sql_query_mode_t::sync_query:
                ret = execute(query_string, ap);
                build_fieldinfo();
                break;

            case sql_query_mode_t::async_query:
                ret = execute_async(query_string, ap);
                break;
        }

        va_end(ap);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t odbc_query::query(LPCTSTR query_string, va_list ap) {
    return_t ret = errorcode_t::success;

    __try2 {
        switch (_sql_mode) {
            case sql_query_mode_t::sync_query:
                ret = execute(query_string, ap);
                build_fieldinfo();
                break;

            case sql_query_mode_t::async_query:
                ret = execute_async(query_string, ap);
                break;
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t odbc_query::execute(LPCTSTR query_string, ...) {
    return_t ret = errorcode_t::success;
    va_list ap;

    __try2 {
        va_start(ap, query_string);

        ret = execute(query_string, ap);
        if (errorcode_t::success != ret) {
            // do nothing
        }

        va_end(ap);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }
    return ret;
}

return_t odbc_query::execute(LPCTSTR query_string, va_list ap) {
    return_t ret = errorcode_t::success;

#if defined _MBCS || defined MBCS
    ansi_string str;
#elif defined _UNICODE || defined UNICODE
    wide_string str;
#endif

    __try2 {
        close();

        SQLRETURN ret_sql = SQL_SUCCESS;
        ret_sql = SQLAllocHandle(SQL_HANDLE_STMT, _dbc_handle, &_stmt_handle);
        if (!SQL_SUCCEEDED(ret_sql)) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        str.vprintf(query_string, ap);

        if (errorcode_t::success == ret) {
            ret = execute_direct(str.c_str());
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }
    return ret;
}

return_t odbc_query::execute_async(LPCTSTR query_string, va_list ap) {
    return_t ret = errorcode_t::success;

#if defined _MBCS || defined MBCS
    ansi_string str;
#elif defined _UNICODE || defined UNICODE
    wide_string str;
#endif

    __try2 {
        close();

        SQLRETURN ret_sql = SQL_SUCCESS;
        ret_sql = SQLAllocHandle(SQL_HANDLE_STMT, _dbc_handle, &_stmt_handle);
        if (!SQL_SUCCEEDED(ret_sql)) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        str.vprintf(query_string, ap);

        SQLSetStmtAttr(_stmt_handle, SQL_ATTR_ASYNC_ENABLE, (SQLPOINTER)SQL_ASYNC_ENABLE_ON, 0);

        ret = execute_direct(str.c_str());
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }
    return ret;
}

return_t odbc_query::execute_direct(LPCTSTR query_string) {
    return_t ret = errorcode_t::success;
    SQLRETURN ret_sql = SQL_SUCCESS;

    ret_sql = SQLExecDirect(_stmt_handle, reinterpret_cast<SQLTCHAR*>(const_cast<LPTSTR>(query_string)), SQL_NTS);

    switch (ret_sql) {
        case SQL_SUCCESS:
        case SQL_SUCCESS_WITH_INFO:
        case SQL_NO_DATA:
            break;
        case SQL_STILL_EXECUTING:
            ret = errorcode_t::busy;
            break;
        case SQL_ERROR:
            ret = errorcode_t::internal_error;
            break;
        default:
            ret = errorcode_t::internal_error;
            break;
    }

    if (errorcode_t::internal_error == ret) { /* 실패시 로그를 남긴다 */
        odbc_diagnose::get_instance()->diagnose(SQL_HANDLE_STMT, _stmt_handle);
    }

    return ret;
}

return_t odbc_query::prepare_statement(LPCTSTR query_string) {
    return_t ret = errorcode_t::success;

    __try2 {
        close();

        if (nullptr == query_string) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        SQLRETURN ret_sql = SQL_SUCCESS;
        ret_sql = SQLAllocHandle(SQL_HANDLE_STMT, _dbc_handle, &_stmt_handle);
        if (!SQL_SUCCEEDED(ret_sql)) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        ret_sql = SQLPrepare(_stmt_handle, reinterpret_cast<SQLTCHAR*>(const_cast<LPTSTR>(query_string)), SQL_NTS);
        if (SQL_SUCCEEDED(ret_sql)) {
            // do nothing
        } else {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }
    return ret;
}

}  // namespace odbc
}  // namespace hotplace
