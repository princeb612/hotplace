/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2002.10.24   Soo Han, Kim        hush project
 * 2007.07.01   Soo Han, Kim        asynchronous query
 * 2009.11.06   Soo Han, Kim        unicode
 * 2023.09.07   Soo Han, Kim        refactor
 */

#ifndef __HOTPLACE_SDK_ODBC_CONNECTOR__
#define __HOTPLACE_SDK_ODBC_CONNECTOR__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/odbc/types.hpp>

namespace hotplace {
namespace odbc {

class odbc_query;
class odbc_connector
{
public:
    /**
     * @brief       constructor
     * @param
     * @return
     * @remarks
     * @sa
     * @remarks
     */
    odbc_connector ();
    /**
     * @brief       destructor
     * @param
     * @return
     * @remarks
     * @sa
     */
    ~odbc_connector ();
    /**
     * @brief       Connect to database
     * @param       odbc_query**    dbquery             [out]
     * @param       LPCTSTR             connection_string   [in]
     * @param       uint32              tmo_seconds         [inopt]
     */
    return_t connect (odbc_query** dbquery, const char* connection_string, uint32 tmo_seconds = -1);
#if defined _UNICODE || defined UNICODE
    return_t connect (odbc_query** dbquery, const wchar_t* connection_string, uint32 tmo_seconds = -1);
#endif
    /**
     * @brief       disconnect
     * @param       HDBC        dbc_handle          [in] HDBC handle
     * @return      SQLRETURN
     * @remarks
     * @sa
     */
    static return_t disconnect (HDBC dbc_handle);
    /**
     * @brief       connection status
     * @param       HDBC        dbc_handle          [in] HDBC handle
     * @return      bool
     * @remarks
     * @sa
     */
    static bool is_connected (HDBC dbc_handle);
    /**
     * @brief       close recordset
     * @param       CDatabaseRecordSet* dbquery     [in] recordset
     * @return      DWORD
     * @remarks
     * @sa
     */
    return_t close (odbc_query* dbquery);

    /**
     * @brief       connection pool
     * @param
     * @return
     * @sa
     * @remarks
     */
    bool is_connection_pooled (void);

    int addref ();
    int release ();

protected:
    return_t odbc_startup ();
    return_t odbc_cleanup ();

private:
    HENV _env_handle;
    t_shared_reference <odbc_connector> _shared;
};

}
}  // namespace

#endif
