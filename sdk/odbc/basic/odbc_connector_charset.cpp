/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/odbc/basic/odbc_connector.hpp>
#include <sdk/odbc/basic/odbc_diagnose.hpp>
#include <sdk/odbc/basic/odbc_query.hpp>

namespace hotplace {
namespace odbc {

return_t odbc_connector::connect(odbc_query** dbquery, LPCTSTR connection_string, uint32 tmo_seconds) {
    return_t ret = errorcode_t::success;
    SQLRETURN ret_sql = SQL_SUCCESS;

    HDBC dbc_handle = SQL_NULL_HANDLE;
    odbc_query* query = nullptr;
    TCHAR out_connection_string[(1 << 10)] = {
        0,
    };
    SQLSMALLINT out_connection_string_len = RTL_NUMBER_OF(out_connection_string);

    __try2 {
        if (nullptr == dbquery) {
            ret_sql = SQL_ERROR;
            __leave2;
        }

        if (nullptr == connection_string) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // Allocate connection handle
        ret_sql = ::SQLAllocHandle(SQL_HANDLE_DBC, _env_handle, &dbc_handle);
        if (!SQL_SUCCEEDED(ret_sql)) {
            __leave2;
        }

        SQLPOINTER tmo_seconds_ptr = reinterpret_cast<SQLPOINTER>(tmo_seconds);
#if (ODBCVER >= 0x0300)
        // Set login timeout to 5 seconds
        ::SQLSetConnectAttr(dbc_handle, SQL_ATTR_CONNECTION_TIMEOUT, tmo_seconds_ptr, 0);
#endif
        ::SQLSetConnectAttr(dbc_handle, SQL_LOGIN_TIMEOUT, tmo_seconds_ptr, 0);

        // SQL_ATTR_AUTOCOMMIT
        SQLPOINTER auto_commit_ptr = reinterpret_cast<SQLPOINTER>(1);
        ::SQLSetConnectAttr(dbc_handle, SQL_ATTR_AUTOCOMMIT, auto_commit_ptr, 0);

        // Connect
        ret_sql = ::SQLDriverConnect(dbc_handle, nullptr, reinterpret_cast<SQLTCHAR*>(const_cast<LPTSTR>(connection_string)), SQL_NTS,
                                     reinterpret_cast<SQLTCHAR*>(out_connection_string), RTL_NUMBER_OF(out_connection_string), &out_connection_string_len,
                                     SQL_DRIVER_NOPROMPT);
        if (!SQL_SUCCEEDED(ret_sql)) {
            odbc_diagnose::get_instance()->diagnose(SQL_HANDLE_DBC, dbc_handle);
            __leave2;
        }

        __try_new_catch(query, new odbc_query(dbc_handle), ret, __leave2);

        *dbquery = query;
    }
    __finally2 {
        if (false == SQL_SUCCEEDED(ret_sql)) {
            if (SQL_NULL_HDBC != dbc_handle) {
                ::SQLFreeHandle(SQL_HANDLE_DBC, dbc_handle);
                dbc_handle = SQL_NULL_HDBC;
            }
            ret = errorcode_t::internal_error;
        }
    }
    return ret;
}

}  // namespace odbc
}  // namespace hotplace
