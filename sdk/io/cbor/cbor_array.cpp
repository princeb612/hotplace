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

cbor_array::cbor_array () : cbor_object (cbor_type_t::cbor_type_array)
{
    // do nothing
}

cbor_array::cbor_array (uint32 flags) : cbor_object (cbor_type_t::cbor_type_array, flags)
{
    // do nothing
}

cbor_array::~cbor_array ()
{
    clear ();
}

return_t cbor_array::join (cbor_object* object, cbor_object* extra)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        switch (object->type ()) {
            case cbor_type_t::cbor_type_array:
            case cbor_type_t::cbor_type_data:
            case cbor_type_t::cbor_type_map:
                _array.push_back (object);
                break;
            default:
                ret = errorcode_t::not_available;
                break;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

cbor_array& cbor_array::add (cbor_array* object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _array.push_back (object);
    }
    __finally2
    {
        // do nothing
    }
    return *this;
}

cbor_array& cbor_array::add (cbor_data* object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _array.push_back (object);
    }
    __finally2
    {
        // do nothing
    }
    return *this;
}

cbor_array& cbor_array::add (cbor_map* object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _array.push_back (object);
    }
    __finally2
    {
        // do nothing
    }
    return *this;
}

cbor_array& cbor_array::operator << (cbor_array* object)
{
    add (object);
    return *this;
}

cbor_array& cbor_array::operator << (cbor_data* object)
{
    add (object);
    return *this;
}

cbor_array& cbor_array::operator << (cbor_map* object)
{
    add (object);
    return *this;
}

size_t cbor_array::size ()
{
    return _array.size ();
}

cbor_object* cbor_array::operator [] (unsigned index)
{
    cbor_object* item = nullptr;

    if (_array.size () > index) {
        std::list <cbor_object*>::iterator it = _array.begin ();
        std::advance (it, index);
        item = *it;
    }
    return item;
}

void cbor_array::clear ()
{
#if __cplusplus >= 201103L    // c++11
    for (auto item : _array) {
#else
    std::list <cbor_object*>::iterator iter;
    for (iter = _array.begin (); iter != _array.end (); iter++) {
        cbor_object* item = *iter;
#endif
        item->release ();
    }
    _array.clear ();
}

void cbor_array::represent (stream_t* s)
{
    if (s) {
        if (tagged ()) {
            s->printf ("%I64i(", (uint64) tag_value ());
        }

        s->printf ("[");
        if (cbor_flag_t::cbor_indef == (get_flags () & cbor_flag_t::cbor_indef)) {
            s->printf ("_ ");
        }

        size_t i = 0;
        size_t size = _array.size ();
        std::list <cbor_object*>::iterator iter;
        for (i = 0, iter = _array.begin (); iter != _array.end (); i++, iter++) {
            cbor_object* item = *iter;
            item->represent (s);
            if (i + 1 != size) {
                s->printf (",");
            }
        }

        s->printf ("]");

        if (tagged ()) {
            s->printf (")");
        }
    }
}

void cbor_array::represent (binary_t* b)
{
    cbor_encode enc;

    if (b) {
        if (tagged ()) {
            enc.encode (*b, cbor_major_t::cbor_major_tag, (uint64) tag_value ());
        }

        enc.encode (*b, cbor_major_t::cbor_major_array, cbor_control_t::cbor_control_begin, this);

        // for each member
#if __cplusplus >= 201103L    // c++11
        for (auto item : _array) {
#else
        std::list <cbor_object*>::iterator iter;
        for (iter = _array.begin (); iter != _array.end (); iter++) {
            cbor_object* item = *iter;
#endif
            item->represent (b);
        }

        enc.encode (*b, cbor_major_t::cbor_major_array, cbor_control_t::cbor_control_end, this);
    }
}

}
}
