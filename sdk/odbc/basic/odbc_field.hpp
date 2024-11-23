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

#ifndef __HOTPLACE_SDK_ODBC_FIELD__
#define __HOTPLACE_SDK_ODBC_FIELD__

#include <sdk/base/system/datetime.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/odbc/types.hpp>

namespace hotplace {
namespace odbc {

class odbc_field {
   public:
    /**
     * @brief
     * @param   int         index           [IN]
     * @param   int         data_type       [IN]
     * @param   int         column_type     [IN]
     * @param   int         column_size     [IN]
     * @param   LPBYTE      column_data     [IN]
     * @param   odbc_field* field_info_ptr  [IN]
     * @return
     * @sa
     * @remarks
     */
    odbc_field(int index, int data_type, int column_type, int column_size, unsigned char* column_data, odbc_field* field_info_ptr = nullptr);
    /**
     * @brief
     * @param
     * @return
     * @sa
     * @remarks
     */
    ~odbc_field();

    /**
     * @brief
     * @param
     * @return
     * @sa
     * @remarks
     */
    int as_integer(void);
    double as_double(void);

    /**
     * @brief
     * @param
     * @return
     * @sa
     * @remarks
     */
    const char* as_string(ansi_string& str, UINT nCodePage = 0);
#if defined _UNICODE || defined UNICODE
    const wchar_t* as_string(wide_string& str, UINT nCodePage = CP_ACP);
#endif

    /**
     * @brief
     * @param
     * @return
     * @sa
     * @remarks
     */
    int get_type(void) { return _column_type; }
    /**
     * @brief
     * @param
     * @return
     * @sa
     * @remarks
     */
    const char* get_field_name(ansi_string& str);
#if defined _UNICODE || defined UNICODE
    const wchar_t* get_field_name(wide_string& str);
#endif

    int addref();
    int release();

   protected:
   private:
    int _index;
    int _data_type;
    int _column_type;
    int _column_size;
    datetime _datetime;  ///< SQL_TIMESTAMP
    odbc_field* _field_info;

    typedef union _field_data_t  // according to _data_type
    {
        int i;     // SQL_BIT, SQL_TINYINT, SQL_INTEGER, SQL_SMALLINT
        float f;   // SQL_FLOAT
        double d;  // SQL_DOUBLE
        void* p;   // ...
    } field_data_t;

    field_data_t _field_data;

    t_shared_reference<odbc_field> _shared;
};

}  // namespace odbc
}  // namespace hotplace

#endif
