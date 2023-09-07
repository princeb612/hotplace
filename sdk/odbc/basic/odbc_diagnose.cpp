/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/odbc/basic/odbc_diagnose.hpp>

namespace hotplace {
namespace odbc {

odbc_diagnose odbc_diagnose::_instance;

odbc_diagnose* odbc_diagnose::get_instance ()
{
    return &_instance;
}

odbc_diagnose::odbc_diagnose ()
{
    // do nothing
}

void odbc_diagnose::diagnose (int handle_type, void* handle)
{
    SQLTCHAR SqlState[6 + 200], Msg[SQL_MAX_MESSAGE_LENGTH];
    SQLINTEGER NativeError;
    SQLSMALLINT i = 0, MsgLen = 0;
    SQLRETURN rc;

    while (true) {
        SqlState[0] = 0;
        Msg[0] = 0;
        MsgLen = RTL_NUMBER_OF (Msg);
        rc = SQLGetDiagRec ((SQLSMALLINT) handle_type, handle, i, SqlState, &NativeError, Msg, RTL_NUMBER_OF (Msg), &MsgLen);
        if (SQL_NO_DATA == rc) {
            break;
        }

        if (SQL_INVALID_HANDLE == rc) {
            break;
        }

        run_handlers (NativeError, (const char*) SqlState, (const char*) Msg);

        i++;
    }
}

void odbc_diagnose::run_handlers (DWORD native_error, const char* state, const char* message)
{
    bool control = true;
    database_errorhandler_list_t::iterator it;

    _lock.enter ();
    for (it = _handler_list.begin (); it != _handler_list.end (); it++) {
        errorhandler_item_t& item = *it;
        if (nullptr != item.handler) {
            item.handler (native_error, state, message, &control, item.context);

            if (false == control) {
                break;
            }
        }
    }
    _lock.leave ();
}

void odbc_diagnose::add_handler (DATABASE_ERRORHANDLER error_handler, void* context)
{
    if (nullptr != error_handler) {
        _lock.enter ();
        errorhandler_item_t item;
        item.handler = error_handler;
        item.context = context;
        _handler_list.push_back (item);
        _lock.leave ();
    }
}

}
}  // namespace
