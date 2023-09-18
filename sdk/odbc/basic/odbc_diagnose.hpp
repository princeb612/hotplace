/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2002.10.24   Soo Han, Kim        codename.hush2002
 * 2007.07.01   Soo Han, Kim        asynchronous query
 * 2009.11.06   Soo Han, Kim        unicode
 * 2023.09.07   Soo Han, Kim        refactor
 */

#ifndef __HOTPLACE_SDK_ODBC_DIAGNOSE__
#define __HOTPLACE_SDK_ODBC_DIAGNOSE__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/odbc/types.hpp>

namespace hotplace {
namespace odbc {

typedef return_t (*DATABASE_ERRORHANDLER)(DWORD native_error, const char* state, const char* message, bool* control, void* context);
typedef struct _errorhandler_item_t {
    DATABASE_ERRORHANDLER handler;
    void* context;
} errorhandler_item_t;
typedef std::list<errorhandler_item_t> database_errorhandler_list_t;

class odbc_diagnose
{

public:
    static odbc_diagnose* get_instance ();

    /**
     * @brief
     * @param   INT     handle_type [IN]
     * @param   HANDLE  handle      [IN]
     * @return
     * @sa
     * @remarks
     */
    void diagnose (int handle_type, void* handle);

    /**
     * @brief   add handler
     */
    void add_handler (DATABASE_ERRORHANDLER error_handler, void* context);

protected:
    /**
     * @brief   constructor
     * @param
     * @return
     * @sa
     * @remarks
     */
    odbc_diagnose ();
    /**
     * @brief   핸들러
     */
    void run_handlers (DWORD native_error, const char* state, const char* message);

    critical_section _lock;
    database_errorhandler_list_t _handler_list;
    static odbc_diagnose _instance;
};

}
}  // namespace

#endif
