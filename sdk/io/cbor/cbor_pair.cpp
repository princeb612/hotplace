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

#if defined __SIZEOF_INT128__
cbor_pair::cbor_pair (int128 value, cbor_data* object) : cbor_object (cbor_type_t::cbor_type_pair), _lhs (nullptr), _rhs (nullptr)
#else
cbor_pair::cbor_pair (int64 value, cbor_data * object) : cbor_object (cbor_type_t::cbor_type_pair), _lhs (nullptr), _rhs (nullptr)
#endif
{
    return_t ret = errorcode_t::success;

    __try2
    {
        __try_new_catch (_lhs, new cbor_data (value), ret, __leave2);
        if (object) {
            _rhs = object;
        }
    }
    __finally2
    {
        // do nothing
    }
}

#if defined __SIZEOF_INT128__
cbor_pair::cbor_pair (int128 value, cbor_array* object) : cbor_object (cbor_type_t::cbor_type_pair), _lhs (nullptr), _rhs (nullptr)
#else
cbor_pair::cbor_pair (int64 value, cbor_array * object) : cbor_object (cbor_type_t::cbor_type_pair), _lhs (nullptr), _rhs (nullptr)
#endif
{
    return_t ret = errorcode_t::success;

    __try2
    {
        __try_new_catch (_lhs, new cbor_data (value), ret, __leave2);
        if (object) {
            _rhs = object;
        }
    }
    __finally2
    {
        // do nothing
    }
}

cbor_pair::cbor_pair (const char* key, cbor_data* object) : cbor_object (cbor_type_t::cbor_type_pair), _lhs (nullptr), _rhs (nullptr)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        __try_new_catch (_lhs, new cbor_data (key), ret, __leave2);
        if (object) {
            _rhs = object;
        }
    }
    __finally2
    {
        // do nothing
    }
}

cbor_pair::cbor_pair (const char* key, cbor_array* object) : cbor_object (cbor_type_t::cbor_type_pair), _lhs (nullptr), _rhs (nullptr)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        __try_new_catch (_lhs, new cbor_data (key), ret, __leave2);
        if (object) {
            _rhs = object;
        }
    }
    __finally2
    {
        // do nothing
    }
}

cbor_pair::cbor_pair (cbor_data* key, cbor_object* object) : cbor_object (cbor_type_t::cbor_type_pair), _lhs (key), _rhs (object)
{
    if (nullptr == key || nullptr == object) {
        throw errorcode_t::invalid_parameter;
    }
}

cbor_pair::~cbor_pair ()
{
    clear ();
}

return_t cbor_pair::clear ()
{
    return_t ret = errorcode_t::success;

    if (_lhs) {
        _lhs->release ();
        _lhs = nullptr;
    }
    if (_rhs) {
        _rhs->release ();
        _rhs = nullptr;
    }
    return ret;
}

cbor_object* const cbor_pair::left ()
{
    return _lhs;
}

cbor_object* const cbor_pair::right ()
{
    return _rhs;
}

void cbor_pair::accept (cbor_visitor* v)
{
    if (v) {
        v->visit (this);
    }
}

void cbor_pair::represent (stream_t* s)
{
    if (s) {
        _lhs->represent (s);
        s->printf (":");
        _rhs->represent (s);
    }
}

void cbor_pair::represent (binary_t* b)
{
    cbor_encode enc;

    if (b) {
        _lhs->represent (b);
        _rhs->represent (b);
    }
}

}
}
