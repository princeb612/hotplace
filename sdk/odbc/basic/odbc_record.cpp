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

odbc_record::odbc_record() { _shared.make_share(this); }

odbc_record::~odbc_record() {
    // do nothing
}

odbc_record& odbc_record::operator<<(odbc_field* pField) {
    _odbc_columns.push_back(pField);
    return *this;
}

return_t odbc_record::clear() {
    return_t ret = errorcode_t::success;
    odbc_field_vector_t::iterator it;

    for (it = _odbc_columns.begin(); it != _odbc_columns.end(); it++) {
        odbc_field* pField = *it;
        pField->release();
    }
    /*
       // in linux following expression makes crash !!
       for(it = _odbc_columns.begin(); it != _odbc_columns.end(); )
       {
        odbc_field* pField = *it;
        STL_ERASE(_odbc_columns, it);
        pField->Release();
       }
     */
    _odbc_columns.clear();
    return ret;
}

odbc_field* odbc_record::get_field(int nIndex) {
    odbc_field* pField = nullptr;

    pField = _odbc_columns.at(nIndex);
    return pField;
}

int odbc_record::count() { return (int)_odbc_columns.size(); }

int odbc_record::addref() { return _shared.addref(); }

int odbc_record::release() { return _shared.delref(); }

}  // namespace odbc
}  // namespace hotplace
