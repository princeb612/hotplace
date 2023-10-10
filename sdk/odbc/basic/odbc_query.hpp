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

#ifndef __HOTPLACE_SDK_ODBC_QUERY__
#define __HOTPLACE_SDK_ODBC_QUERY__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/odbc/basic/odbc_record.hpp>
#include <hotplace/sdk/odbc/types.hpp>

namespace hotplace {
namespace odbc {

class odbc_query {
    friend class odbc_connector;

   public:
    /**
     * @brief   destructor
     */
    ~odbc_query();

    /**
     * @brief
     * @param   LPCTSTR query_string    [in] query
     * @return
     * @sa
     * @remarks
     *
     *          rs = connnetor->connect (&rs, connectionstr, tmo);
     *          ret = rs->query("select * from tbTest");
     *          if (errorcode_t::success == ret)
     *          {
     *              odbc_record record;
     *              while (errorcode_t::success == rs->fetch(&record))
     *              {
     *                  std::cout << "------------------------" << std::endl;
     *                  int n = record.count();
     *                  for (int i = 0; i < n; i++)
     *                  {
     *                      odbc_field* pField = record.get_field(i);
     *                      std::string f, d;
     *                      pField->get_field_name(f);
     *                      pField->as_string(d);
     *                      std::cout << "  " << f.c_str() << " : " << d.c_str() << " " << std::endl;
     *                  }
     *              }
     *              rs->release ();
     *          }
     */
    return_t query(const char* query_string, ...);
#if defined _UNICODE || defined UNICODE
    return_t query(const wchar_t* query_string, ...);
#endif
    return_t query(const char* query_string, va_list ap);
#if defined _UNICODE || defined UNICODE
    return_t query(const wchar_t* query_string, va_list ap);
#endif

    /**
     * @brief
     * @param   LPCTSTR         query_string    [in] query
     * @return
     * @sa
     * @remarks SQLExecDirect
     */
    return_t execute(const char* query_string, ...);
#if defined _UNICODE || defined UNICODE
    return_t execute(const wchar_t* query_string, ...);
#endif

    return_t prepare_statement(const char* query_string);
#if defined _UNICODE || defined UNICODE
    return_t prepare_statement(const wchar_t* query_string);
#endif
    /*
     * @brief
     * @param   UINT    index       [IN] starting at 0
     * @param   DWORD   column_type [IN] SQL_C_CHAR, SQL_C_LONG, ...
     * @param   DWORD   sql_type    [IN] SQL_CHAR, SQL_VARCHAR, SQL_INTEGER, ...
     * @param   void*   data        [IN]
     * @param   size_t  data_size   [IN]
     * @remarks
     *          rs->prepare_statement("insert into mytable (name, tag) values (?, ?);
     *          rs->bind_statement_parameter(1, SQL_C_CHAR, SQL_VARCHAR, name.c_str(), name.size());
     *          rs->bind_statement_parameter(2, SQL_C_LONG, SQL_INTEGER, &nValue, sizeof(nValue));
     *          rs->execute_statement();
     */
    return_t bind_statement_parameter(UINT index, DWORD column_type, DWORD sql_type, void* data, size_t data_size);
    return_t execute_statement();

    /**
     * @brief   close(sync)/cancel(async)
     * @param
     * @return
     * @sa
     * @remarks
     */
    return_t close();

    /**
     * @brief
     * @param   odbc_record*    sqlRecord   [out] record
     * @return
     * @sa
     * @remarks
     *  query 수행후 result set 에 대한 row 를 얻는다.
     */
    return_t fetch(odbc_record* sqlRecord);

    /**
     * @brief   필드 정보를 얻는다.
     * @param
     * @return
     * @sa
     * @remarks
     *  query method 를 수행하면 result set 에 대한 필드 정보를 구성한다.
     *  필드 정보들을 얻는다.
     */
    odbc_record* get_fieldinfo(void);
    /**
     * @brief
     * @param   DWORD*      column_count   [out]
     * @param   DWORD*      row_count      [out] affected rows
     * @return
     * @sa
     */
    return_t get_resultset(DWORD* column_count, DWORD* row_count);
    /**
     * @brief
     * @param
     * @return
     * @sa
     * @remarks
     */
    return_t more();

    sql_query_mode_t mode() { return _sql_mode; }

    int addref();
    int release();

   protected:
    /**
     * @brief   constructor
     */
    odbc_query(HDBC dbc_handle, sql_query_mode_t sql_mode = sql_query_mode_t::sync_query);

    /**
     * @brief
     * @param   LPCTSTR     query_string    [in]
     * @param   va_list     ap              [in]
     * @return
     * @sa
     * @remarks
     */
    return_t execute(const char* query_string, va_list ap);
#if defined _UNICODE || defined UNICODE
    return_t execute(const wchar_t* query_string, va_list ap);
#endif
    /**
     * @brief
     * @param   LPCTSTR     query_string    [in]
     * @param   va_list     ap              [in]
     * @return
     * @sa
     * @remarks
     */
    return_t execute_async(const char* query_string, va_list ap);
#if defined _UNICODE || defined UNICODE
    return_t execute_async(const wchar_t* query_string, va_list ap);
#endif
    /**
     * @brief
     * @param   LPCTSTR     query_string    [in]
     * @return
     * @sa
     * @remarks
     *  SQLExecDirect 수행
     */
    return_t execute_direct(const char* query_string);
#if defined _UNICODE || defined UNICODE
    return_t execute_direct(const wchar_t* query_string);
#endif

    /**
     * @brief   field information
     * @param
     * @return
     * @sa
     * @remarks
     */
    return_t build_fieldinfo(void);

    /**
     * @brief   field information
     * @param
     * @return
     * @sa
     * @remarks
     */
    void clear_fieldinfo(void);

    HDBC _dbc_handle;
    HSTMT _stmt_handle;
    odbc_record _field_information;
    sql_query_mode_t _sql_mode;

    t_shared_reference<odbc_query> _shared;
};

/**
 * @desc    sql_query_mode_t::async_query
 *          jobqueue-based (merlin)
 *          leave it to developer (hotplace)
 */
class odbc_sinker {
   public:
    odbc_sinker(odbc_query* dbquery, uint32 timeout);
    ~odbc_sinker();

    /**
     * @return
     *          errorcode_t::success
     *          errorcode_t::busy
     *          errorcode_t::timeout
     */
    return_t ready();

   private:
    odbc_query* _dbquery;
    uint32 _tmo_seconds;
    struct timespec _timestamp;
};

}  // namespace odbc
}  // namespace hotplace

#endif
