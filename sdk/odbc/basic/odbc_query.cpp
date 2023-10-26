/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/odbc/basic/odbc_connector.hpp>
#include <sdk/odbc/basic/odbc_diagnose.hpp>
#include <sdk/odbc/basic/odbc_field.hpp>
#include <sdk/odbc/basic/odbc_query.hpp>

namespace hotplace {
namespace odbc {

#define MAX_COLUMN_NAME 1024

odbc_query::odbc_query(HDBC dbc_handle, sql_query_mode_t sql_mode) : _dbc_handle(dbc_handle), _stmt_handle(SQL_NULL_HSTMT), _sql_mode(sql_mode) {
    _shared.make_share(this);
}

odbc_query::~odbc_query() {
    close();

    if (_dbc_handle) {
        odbc_connector::disconnect(_dbc_handle);
    }
}

return_t odbc_query::build_fieldinfo(void) {
    return_t ret = errorcode_t::success;

    unsigned char ColName[MAX_COLUMN_NAME];
    // TBYTE           ucOwner [MAX_COLUMN_NAME];
    short ColNameLength = 0;
    SQLSMALLINT ColType = 0;
    SQLSMALLINT Nullable = 0;
    SQLSMALLINT Scale = 0;

    /*
     * ODBC 64-bit API changes in MDAC 2.7
     * https://support.microsoft.com/en-us/kb/298678
     * unixODBC
     * SQLLEN and SQLULEN data items are 64 bits in a 64-bit ODBC application and 32 bits in a 32-bit ODBC application. SQLINTEGER and SQLUINTEGER data items
     * are 32 bits on all platforms.
     *
     */
#if defined WIN32 || defined WIN64
    SQLULEN ColSize = 0;
    // SQLLEN          ColLen = 0;
#elif defined __linux__
#if SIZEOF_LONG == 8
    SQLUINTEGER ColSize = 0;
#else
    unsigned long ColSize = 0;
#endif
    // long            ColLen = 0;
#endif
    SQLSMALLINT NumResCols = 0;

    SWORD nCol = 1;
    SQLRETURN ret_sql = SQL_SUCCESS;
    odbc_field* dbfield = nullptr;

    __try2 {
        // ret_sql = SQLColAttributes(_stmt_handle, 0, SQL_COLUMN_COUNT, ucOwner, RTL_NUMBER_OF(ucOwner), &Scale, &ColLen ); /* MySQL ODBC 5.3 ANSI Driver
        // return -1 */
        ret_sql = SQLNumResultCols(_stmt_handle, &NumResCols);
        if (SQL_ERROR == ret_sql) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        while (nCol <= NumResCols) {
            ret_sql = SQLDescribeCol(_stmt_handle, nCol, reinterpret_cast<SQLTCHAR*>(ColName), RTL_NUMBER_OF(ColName), &ColNameLength, &ColType, &ColSize,
                                     &Scale, &Nullable);
            if (!SQL_SUCCEEDED(ret_sql)) {
                ret = errorcode_t::internal_error;
                break;
            }

            ColNameLength *= sizeof(TCHAR); /* cch to cb */
            __try_new_catch(dbfield, new odbc_field(nCol++, SQL_TCHAR, ColType, ColNameLength, (unsigned char*)ColName, nullptr), ret, break);

            _field_information << dbfield;
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            clear_fieldinfo();

            // do nothing
        }
    }

    return ret;
}

void odbc_query::clear_fieldinfo(void) { _field_information.clear(); }

return_t odbc_query::bind_statement_parameter(UINT nIndex, DWORD CType, DWORD SQLType, void* pData, size_t sizeData) {
    return_t ret = errorcode_t::success;
    SQLRETURN ret_sql = SQL_SUCCESS;

    __try2 {
        if (nullptr == pData) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret_sql = SQLBindParameter(_stmt_handle, (SQLUSMALLINT)nIndex, SQL_PARAM_INPUT, (SQLSMALLINT)CType, (SQLSMALLINT)SQLType, 0, 0, pData,
                                   (SQLINTEGER)sizeData, nullptr);
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

return_t odbc_query::execute_statement() {
    return_t ret = errorcode_t::success;
    SQLRETURN ret_sql = SQL_SUCCESS;

    __try2 {
        ret_sql = SQLExecute(_stmt_handle);
        switch (ret_sql) {
            case SQL_SUCCESS:
            case SQL_SUCCESS_WITH_INFO:
                build_fieldinfo();
                break;
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
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t odbc_query::close() {
    return_t ret = errorcode_t::success;

    if (nullptr != _stmt_handle) {
        if (sql_query_mode_t::async_query == _sql_mode) {
            SQLCancel(_stmt_handle);
        }
        // SQLFreeStmt (_stmt_handle, SQL_DROP);
        SQLFreeHandle(SQL_HANDLE_STMT, _stmt_handle);
        _stmt_handle = SQL_NULL_HSTMT;
    }

    clear_fieldinfo();
    return ret;
}

odbc_record* odbc_query::get_fieldinfo() { return &_field_information; }

return_t odbc_query::get_resultset(DWORD* column_count, DWORD* row_count) {
    return_t ret = errorcode_t::success;
    SQLSMALLINT nCols = 0;

#if defined WIN32 || defined WIN64
    SQLLEN nRows = 0;
#elif defined __linux__
#if SIZEOF_LONG == 8
    SQLINTEGER nRows = 0;
#else
    long nRows = 0;
#endif
#endif
    __try2 {
        if (nullptr == column_count) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == row_count) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        *column_count = 0;
        *row_count = 0;

        SQLNumResultCols(_stmt_handle, &nCols);
        SQLRowCount(_stmt_handle, &nRows);
        if (-1 == nRows) {  // select
            nRows = 0;
        }

        *column_count = (DWORD)nCols;
        *row_count = (DWORD)nRows;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }
    return ret;
}

return_t odbc_query::more() {
    return_t ret = errorcode_t::success;
    SQLRETURN ret_sql = SQL_SUCCESS;

    __try2 {
        ret_sql = SQLMoreResults(_stmt_handle);
        if (SQL_SUCCEEDED(ret_sql)) {
            clear_fieldinfo();
            build_fieldinfo();
        } else {
            ret = errorcode_t::internal_error;
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

int odbc_query::addref() { return _shared.addref(); }

int odbc_query::release() { return _shared.delref(); }

return_t odbc_query::fetch(odbc_record* odbc_record_ptr) {
    return_t ret = errorcode_t::success;
    odbc_field* odbc_field_ptr = nullptr;
    SQLRETURN ret_sql = SQL_SUCCESS;

    basic_stream bio;

    __try2 {
        if (nullptr == odbc_record_ptr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        odbc_record_ptr->clear();

        /*
         * MSSQLServer issue
         *
         * stored procedure 를 실행했을 때 SQLFetch 가 SQL_ERROR (-1) 리턴
         * - procedure 가 cursor 를 사용할 때 print 를 사용하지 말 것...
         * - 잘못된 커서 사용 오류로 실패한다.
         */
        ret_sql = SQLFetch(_stmt_handle);
#if (ODBCVER >= 0x0300)
        if (SQL_NO_DATA == ret_sql) {
            ret = errorcode_t::no_data;
            __leave2;
        }
#endif
        if (!SQL_SUCCEEDED(ret_sql)) {
            ret = errorcode_t::fetch;
            __leave2;
        }

        int columns = _field_information.count();
        SQLSMALLINT nCol = 1;
#if defined WIN32 || defined WIN64
        SQLLEN nDataLen = 0;
#elif defined __linux__
#if SIZEOF_LONG == 8
        SQLINTEGER nDataLen = 0;
#else
        long nDataLen = 0;
#endif
#endif
        BYTE DataBuf[(1 << 8)];
        int fieldType = SQL_UNKNOWN_TYPE;  ///< SQLGetData
        int nColumnType = SQL_UNKNOWN_TYPE;

        while (nCol <= columns) {
            bio.clear();

            odbc_field* pFieldRef = _field_information.get_field(nCol - 1);
            if (nullptr == pFieldRef) {
                ret = errorcode_t::no_data;
                break;
            }
            nColumnType = pFieldRef->get_type();

            // SQLGetData
            switch (nColumnType) {
                case SQL_NUMERIC: /* 2 */
                case SQL_DECIMAL: /* 3 */
                    fieldType = SQL_C_LONG;
                    break;
                case SQL_CHAR:        /* 1 */
                case SQL_VARCHAR:     /* 12 */
                case SQL_LONGVARCHAR: /* -1 */
                case -370:            /* XML */
                    fieldType = SQL_C_CHAR;
                    break;
                case SQL_WCHAR:        /* -8 */
                case SQL_WVARCHAR:     /* -9 */
                case SQL_WLONGVARCHAR: /* -10 */
#if (ODBCVER <= 0x0300)
                case SQL_UNICODE:             /* -95 */
                case SQL_UNICODE_VARCHAR:     /* -96 */
                case SQL_UNICODE_LONGVARCHAR: /* -97 */
#else
                case -95:
                case -96:
                case -97:
#endif
                    fieldType = SQL_C_WCHAR;
                    break;
                case SQL_BINARY:    /* -2 */
                case SQL_VARBINARY: /* -3 */
                    fieldType = SQL_C_BINARY;
                    break;
                case SQL_LONGVARBINARY: /* -4 */
                    fieldType = SQL_C_BINARY;
                    break;
                case SQL_BIT: /* -7 */
                    fieldType = SQL_C_BIT;
                    break;
                case SQL_TINYINT:  /* -6 */
                case SQL_SMALLINT: /* 5 */
                case SQL_INTEGER:  /* 4 */
                    fieldType = SQL_C_LONG;
                    break;
                case SQL_TYPE_DATE: /* 91 */
                    fieldType = SQL_TYPE_DATE;
                    break;
                case SQL_TIME:      /* 10 */
                case SQL_TYPE_TIME: /* 92 */
                    fieldType = SQL_TYPE_TIME;
                    break;
                case SQL_DATETIME:       /* 9 */
                case SQL_TIMESTAMP:      /* 11 */
                case SQL_TYPE_TIMESTAMP: /* 93 */
                    fieldType = SQL_C_TIMESTAMP;
                    break;
                case SQL_REAL:   /* 7 */
                case SQL_DOUBLE: /* 8 */
                    fieldType = SQL_C_DOUBLE;
                    break;
                case SQL_FLOAT: /* 6 */
                    // case SQL_DECFLOAT :
                    fieldType = SQL_C_FLOAT;
                    break;
                default:
                    fieldType = SQL_C_CHAR;
                    break;
            }

            __try2 {
                /* phase 1 */
                while (true) {
                    memset(DataBuf, 0, sizeof(DataBuf));
                    ret_sql = SQLGetData(_stmt_handle, nCol, (SQLSMALLINT)fieldType, DataBuf, sizeof(DataBuf), &nDataLen);
                    if (SQL_NO_DATA == ret_sql) {
                        ret_sql = errorcode_t::success;
                        break;
                    }

                    if (!SQL_SUCCEEDED(ret_sql)) {
                        ret = errorcode_t::no_data; /* error */
                        break;
                    }

                    if (SQL_NULL_DATA == nDataLen) {
                        nDataLen = 0;
                    }

                    if (nDataLen > sizeof(DataBuf)) {
                        size_t size = sizeof DataBuf;
                        switch (fieldType) {
                            case SQL_C_CHAR:
                                size -= 1;
                                break;
                            case SQL_C_WCHAR:
                                size -= 2;
                                break;
                            default:
                                break;
                        }
                        bio.write(DataBuf, size);
                    } else {
                        size_t dwDataSize = bio.size();
                        if (dwDataSize > 0) {
                            bio.write(DataBuf, nDataLen);
                        }
                        break;
                    }
                }

                if (errorcode_t::success != ret) { /* error while(true) {...} */
                    __leave2;
                }

                /* phase 2 */
                byte_t* pData = bio.data();
                size_t dwDataSize = bio.size();

                if (dwDataSize == 0) { /* 미리 준비한 버퍼를 사용해 데이터를 가져온 경우 */
                    __try_new_catch(odbc_field_ptr,
                                    new odbc_field(nCol, nColumnType, nColumnType, nDataLen > 0 ? (int)nDataLen : 1, (unsigned char*)DataBuf, pFieldRef), ret,
                                    __leave2);
                } else { /* 메모리 스트림을 사용해 큰 데이터를 가져온 경우 */
                    __try_new_catch(odbc_field_ptr,
                                    new odbc_field(nCol, nColumnType, nColumnType, dwDataSize > 0 ? (int)dwDataSize : 1, (unsigned char*)pData, pFieldRef), ret,
                                    __leave2);
                }

                /* phase 3 */
                *odbc_record_ptr << odbc_field_ptr;
            }
            __finally2 {
                if (errorcode_t::success != ret) { /* 실패에 대한 메모리 해제 책임 */
                    odbc_record_ptr->clear();
                }
            }

            nCol++;
        }
    }
    __finally2 {
        if (SQL_ERROR == ret_sql) {
            if (nullptr != _stmt_handle) {
                odbc_diagnose::get_instance()->diagnose(SQL_HANDLE_STMT, _stmt_handle);
            }
        }

        if (errorcode_t::success != ret && errorcode_t::no_data != ret) {
            // do nothing
        }
    }

    return ret;
}

}  // namespace odbc
}  // namespace hotplace
