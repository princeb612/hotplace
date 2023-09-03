/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <hotplace/sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace io {

cbor_tstrings::cbor_tstrings () : cbor_object (cbor_type_t::cbor_type_tstrs, cbor_flag_t::cbor_indef)
{
    // do nothing
}

cbor_tstrings::~cbor_tstrings ()
{
    clear ();
}

size_t cbor_tstrings::size ()
{
    return _array.size ();
}

return_t cbor_tstrings::clear ()
{
    return_t ret = errorcode_t::success;

#if __cplusplus >= 201103L    // c++11
    for (auto item : _array) {
#else
    std::list <cbor_data*>::iterator iter;
    for (iter = _array.begin (); iter != _array.end (); iter++) {
        cbor_data* item = *iter;
#endif
        item->release ();
    }
    _array.clear ();

    return ret;
}

return_t cbor_tstrings::join (cbor_object* object, cbor_object* extra)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_type_t::cbor_type_data == object->type ()) {
            cbor_data* inst = (cbor_data*) object;
            if (TYPE_STRING == inst->data ().type) {
                _array.push_back (inst);
            } else {
                ret = errorcode_t::not_available;
            }
        } else {
            ret = errorcode_t::not_available;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

cbor_tstrings& cbor_tstrings::add (const char* str)
{
    return_t ret = errorcode_t::success;
    cbor_data* object = nullptr;

    __try2
    {
        __try_new_catch (object, new cbor_data (str), ret, __leave2);

        _array.push_back (object);
    }
    __finally2
    {
        // do nothing
    }
    return *this;
}

cbor_tstrings& cbor_tstrings::operator << (const char* str)
{
    return add (str);
}

void cbor_tstrings::represent (stream_t* s)
{
    if (s) {
        s->printf ("(");
        if (cbor_flag_t::cbor_indef == (get_flags () & cbor_flag_t::cbor_indef)) {
            s->printf ("_ ");
        }

        size_t i = 0;
        size_t size = _array.size ();
        std::list <cbor_data*>::iterator iter;
        for (i = 0, iter = _array.begin (); iter != _array.end (); i++, iter++) {
            cbor_data* item = *iter;
            item->represent (s);
            if (i + 1 != size) {
                s->printf (",");
            }
        }

        s->printf (")");
    }
}

void cbor_tstrings::represent (binary_t* b)
{
    cbor_encode enc;

    if (b) {
        enc.encode (*b, cbor_major_t::cbor_major_tstr, cbor_control_t::cbor_control_begin, this);

        // for each member
#if __cplusplus >= 201103L    // c++11
        for (auto item : _array) {
#else
        std::list <cbor_data*>::iterator iter;
        for (iter = _array.begin (); iter != _array.end (); iter++) {
            cbor_data* item = *iter;
#endif
            item->represent (b);
        }

        enc.encode (*b, cbor_major_t::cbor_major_tstr, cbor_control_t::cbor_control_end, this);
    }
}

}
}
