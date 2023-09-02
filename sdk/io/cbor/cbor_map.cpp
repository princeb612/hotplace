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

cbor_map::cbor_map () : cbor_object (cbor_type_t::cbor_type_map)
{
    // do nothing
}

cbor_map::cbor_map (uint32 flags) : cbor_object (cbor_type_t::cbor_type_map, flags)
{
    // do nothing
}

cbor_map::cbor_map (cbor_pair* object, uint32 flags) : cbor_object (cbor_type_t::cbor_type_map, flags)
{
    *this << object;
}

cbor_map::~cbor_map ()
{
    clear ();
}

size_t cbor_map::size ()
{
    return _array.size ();
}

return_t cbor_map::clear ()
{
    return_t ret = errorcode_t::success;

#if __cplusplus >= 201103L    // c++11
    for (auto item : _array) {
#else
    std::list <cbor_pair*>::iterator iter;
    for (iter = _array.begin (); iter != _array.end (); iter++) {
        cbor_pair* item = *iter;
#endif
        item->release ();
    }
    _array.clear ();

    return ret;
}

return_t cbor_map::join (cbor_object* object, cbor_object* extra)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_type_t::cbor_type_pair == object->type ()) {
            cbor_pair* inst = (cbor_pair*) object;
            _array.push_back (inst);
        } else {
            // lhs cbor_data (int series, char* only)
            // rhs cbor_data, cbor_arry_t

            if (nullptr == extra) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }

            bool lhs_ret = false;
            bool rhs_ret = false;

            cbor_type_t lhs_type = object->type ();
            cbor_type_t rhs_type = extra->type ();

            if (cbor_type_t::cbor_type_data == lhs_type) {
                cbor_data* inst = (cbor_data*) object;
                vartype_t lhs_vtype = inst->data ().type;
                switch (lhs_vtype) {
                    case TYPE_INT8:
                    case TYPE_UINT8:
                    case TYPE_INT16:
                    case TYPE_UINT16:
                    case TYPE_INT32:
                    case TYPE_UINT32:
                    case TYPE_INT64:
                    case TYPE_UINT64:
                    case TYPE_INT128:
                    case TYPE_UINT128:
                    case TYPE_STRING:
                        lhs_ret = true;
                        break;
                    default:
                        break;
                }
            }
            switch (rhs_type) {
                case cbor_type_t::cbor_type_data:
                case cbor_type_t::cbor_type_array:
                case cbor_type_t::cbor_type_simple:
                    rhs_ret = true;
                default:
                    break;
            }

            if (lhs_ret && rhs_ret) {
                // do nothing
            } else {
                ret = errorcode_t::not_available;
            }

            if (errorcode_t::success != ret) {
                __leave2;
            }

            cbor_data* inst = (cbor_data*) object;
            cbor_pair* pair = nullptr;
            __try_new_catch (pair, new cbor_pair (inst, extra), ret, __leave2);
            if (pair) {
                _array.push_back (pair);
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

cbor_map& cbor_map::add (cbor_pair* object)
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

cbor_map& cbor_map::operator << (cbor_pair* object)
{
    add (object);
    return *this;
}

void cbor_map::accept (cbor_visitor* v)
{
    if (v) {
        v->visit (this);
    }
}

void cbor_map::represent (stream_t* s)
{
    if (s) {
        s->printf ("{");
        if (cbor_flag_t::cbor_indef == (get_flags () & cbor_flag_t::cbor_indef)) {
            s->printf ("_ ");
        }

        size_t i = 0;
        size_t size = _array.size ();
        std::list <cbor_pair*>::iterator iter;
        for (i = 0, iter = _array.begin (); iter != _array.end (); i++, iter++) {
            cbor_pair* item = *iter;
            item->represent (s);
            if (i + 1 != size) {
                s->printf (",");
            }
        }

        s->printf ("}");
    }
}

void cbor_map::represent (binary_t* b)
{
    cbor_encode enc;

    if (b) {
        enc.encode (*b, cbor_major_t::cbor_major_map, cbor_control_t::cbor_control_begin, this);

        // for each member
#if __cplusplus >= 201103L    // c++11
        for (auto item : _array) {
#else
        std::list <cbor_pair*>::iterator iter;
        for (iter = _array.begin (); iter != _array.end (); iter++) {
            cbor_pair* item = *iter;
#endif
            item->represent (b);
        }

        enc.encode (*b, cbor_major_t::cbor_major_map, cbor_control_t::cbor_control_end, this);
    }
}

}
}
