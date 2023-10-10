/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/odbc/basic/odbc_connector.hpp>
#include <hotplace/sdk/odbc/basic/odbc_diagnose.hpp>
#include <hotplace/sdk/odbc/basic/odbc_query.hpp>

namespace hotplace {
namespace odbc {

odbc_connector::odbc_connector() {
    _shared.addref();

    odbc_startup();
}

odbc_connector::~odbc_connector() { odbc_cleanup(); }

return_t odbc_connector::disconnect(HDBC dbc_handle) {
    return_t ret = errorcode_t::success;

    if (nullptr != dbc_handle) {
        ::SQLDisconnect(dbc_handle);
        ::SQLFreeHandle(SQL_HANDLE_DBC, dbc_handle);
        // dbc_handle = SQL_NULL_HDBC;
    }
    return ret;
}

bool odbc_connector::is_connected(HDBC dbc_handle) {
    SQLRETURN ret_sql = SQL_SUCCESS;
    bool bRet = false;
    SQLINTEGER bValue = 0;
    SQLINTEGER nValue = 0;

    ret_sql = ::SQLGetConnectAttr(dbc_handle, SQL_ATTR_CONNECTION_DEAD, (SQLPOINTER)&bValue, sizeof(bValue), reinterpret_cast<SQLINTEGER*>(&nValue));
    if (SQL_SUCCEEDED(ret_sql)) {
        if (SQL_CD_FALSE == bValue) {
            bRet = true;
        }
    }
    return bRet;
}

return_t odbc_connector::close(odbc_query* dbquery) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == dbquery) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        dbquery->release();
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

bool odbc_connector::is_connection_pooled(void) {
    bool ret = false;
    SQLRETURN ret_sql = SQL_SUCCESS;

    __try2 {
        DWORD value = 0;
        ret_sql = SQLGetEnvAttr(SQL_NULL_HANDLE, SQL_ATTR_CONNECTION_POOLING, &value, 0, nullptr);
        if (false == SQL_SUCCEEDED(ret_sql)) {
            __leave2;
        }
        switch (value) {
            case SQL_CP_ONE_PER_HENV:
            case SQL_CP_ONE_PER_DRIVER:
                ret = true;
                break;
            case SQL_CP_OFF:
                ret = false;
                break;
            default:
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

int odbc_connector::addref() { return _shared.addref(); }

int odbc_connector::release() { return _shared.delref(); }

return_t odbc_connector::odbc_startup() {
    return_t ret = errorcode_t::success;
    SQLRETURN ret_sql = SQL_SUCCESS;

    __try2 {
        // crash occurs in older than Windows 2003 SP1
        ret_sql = ::SQLSetEnvAttr(SQL_NULL_HENV, SQL_ATTR_CONNECTION_POOLING, (SQLPOINTER)SQL_CP_ONE_PER_DRIVER, 0);

        ret_sql = ::SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HENV, &_env_handle);
        if (!SQL_SUCCEEDED(ret_sql)) {
            __leave2;
        }

        // Set the ODBC version environment attribute
        ret_sql = ::SQLSetEnvAttr(_env_handle, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, SQL_IS_INTEGER);
        if (!SQL_SUCCEEDED(ret_sql)) {
            __leave2;
        }
    }
    __finally2 {
        if (!SQL_SUCCEEDED(ret_sql)) {
            if (SQL_NULL_HANDLE != _env_handle) {
                odbc_diagnose::get_instance()->diagnose(SQL_HANDLE_ENV, (void*)_env_handle);

                ::SQLFreeHandle(SQL_HANDLE_ENV, _env_handle);
                _env_handle = SQL_NULL_HENV;
            }

            // do nothing

            ret = ret_sql;
        }
    }
    return ret;
}

return_t odbc_connector::odbc_cleanup() {
    return_t ret = errorcode_t::success;

    __try2 {
        if (SQL_NULL_HENV == _env_handle) {
            __leave2;
        }

        ::SQLFreeHandle(SQL_HANDLE_ENV, _env_handle);
        _env_handle = SQL_NULL_HENV;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace odbc
}  // namespace hotplace
