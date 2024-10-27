/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/odbc/basic/odbc_field.hpp>
#include <sdk/odbc/basic/odbc_record.hpp>

namespace hotplace {
namespace odbc {

odbc_field* odbc_record::get_field(LPTSTR tszName) {
    odbc_field* field = nullptr;
    odbc_field_vector_t::iterator it;

    for (it = _odbc_columns.begin(); it != _odbc_columns.end(); it++) {
        odbc_field* item = *it;
        bool bRet = false;
#if defined _MBCS || defined MBCS
        ansi_string str;
        item->get_field_name(str);
        bRet = (0 == stricmp(str.c_str(), tszName));
#elif defined _UNICODE || defined UNICODE
        wide_string str;
        item->get_field_name(str);
        bRet = (0 == _wcsicmp(str.c_str(), tszName));
#endif
        if (true == bRet) {
            field = item;
            break;
        }
    }

    return field;
}

}  // namespace odbc
}  // namespace hotplace
