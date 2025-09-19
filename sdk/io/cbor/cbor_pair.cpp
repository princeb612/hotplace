/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7049 Concise Binary Object Representation (CBOR)
 *  RFC 8949 Concise Binary Object Representation (CBOR)
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_object.hpp>

namespace hotplace {
namespace io {

#if defined __SIZEOF_INT128__
cbor_pair::cbor_pair(int128 value, cbor_data* object)
    : cbor_object(cbor_type_t::cbor_type_pair),
      _lhs(nullptr),
      _rhs(object)
#else
cbor_pair::cbor_pair(int64 value, cbor_data* object)
    : cbor_object(cbor_type_t::cbor_type_pair),
      _lhs(nullptr),
      _rhs(object)
#endif
{
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            throw exception(errorcode_t::not_specified);
        }
        __try_new_catch(_lhs, new cbor_data(value), ret, __leave2);
    }
    __finally2 {}
}

#if defined __SIZEOF_INT128__
cbor_pair::cbor_pair(int128 value, cbor_map* object)
    : cbor_object(cbor_type_t::cbor_type_pair),
      _lhs(nullptr),
      _rhs(object)
#else
cbor_pair::cbor_pair(int64 value, cbor_map* object)
    : cbor_object(cbor_type_t::cbor_type_pair),
      _lhs(nullptr),
      _rhs(object)
#endif
{
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            throw exception(errorcode_t::not_specified);
        }
        __try_new_catch(_lhs, new cbor_data(value), ret, __leave2);
    }
    __finally2 {}
}

#if defined __SIZEOF_INT128__
cbor_pair::cbor_pair(int128 value, cbor_array* object)
    : cbor_object(cbor_type_t::cbor_type_pair),
      _lhs(nullptr),
      _rhs(object)
#else
cbor_pair::cbor_pair(int64 value, cbor_array* object)
    : cbor_object(cbor_type_t::cbor_type_pair),
      _lhs(nullptr),
      _rhs(object)
#endif
{
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            throw exception(errorcode_t::not_specified);
        }
        __try_new_catch(_lhs, new cbor_data(value), ret, __leave2);
    }
    __finally2 {}
}

cbor_pair::cbor_pair(const char* key, cbor_data* object) : cbor_object(cbor_type_t::cbor_type_pair), _lhs(nullptr), _rhs(object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            throw exception(errorcode_t::not_specified);
        }
        __try_new_catch(_lhs, new cbor_data(key), ret, __leave2);
    }
    __finally2 {}
}

cbor_pair::cbor_pair(const char* key, cbor_map* object) : cbor_object(cbor_type_t::cbor_type_pair), _lhs(nullptr), _rhs(object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            throw exception(errorcode_t::not_specified);
        }
        __try_new_catch(_lhs, new cbor_data(key), ret, __leave2);
    }
    __finally2 {}
}

cbor_pair::cbor_pair(const char* key, cbor_array* object) : cbor_object(cbor_type_t::cbor_type_pair), _lhs(nullptr), _rhs(object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            throw exception(errorcode_t::not_specified);
        }
        __try_new_catch(_lhs, new cbor_data(key), ret, __leave2);
    }
    __finally2 {}
}

cbor_pair::cbor_pair(cbor_data* key, cbor_data* object) : cbor_object(cbor_type_t::cbor_type_pair), _lhs(key), _rhs(object) {
    if (nullptr == key || nullptr == object) {
        throw exception(errorcode_t::not_specified);
    }
}

cbor_pair::cbor_pair(cbor_data* key, cbor_map* object) : cbor_object(cbor_type_t::cbor_type_pair), _lhs(key), _rhs(object) {
    if (nullptr == key || nullptr == object) {
        throw exception(errorcode_t::not_specified);
    }
}

cbor_pair::cbor_pair(cbor_data* key, cbor_array* object) : cbor_object(cbor_type_t::cbor_type_pair), _lhs(key), _rhs(object) {
    if (nullptr == key || nullptr == object) {
        throw exception(errorcode_t::not_specified);
    }
}

cbor_pair::cbor_pair(cbor_data* key, cbor_object* object) : cbor_object(cbor_type_t::cbor_type_pair), _lhs(key), _rhs(object) {
    if (nullptr == key || nullptr == object) {
        throw exception(errorcode_t::not_specified);
    }
}

cbor_pair::~cbor_pair() {}

int cbor_pair::addref() {
    if (_lhs) {
        _lhs->addref();
    }
    if (_rhs) {
        _rhs->addref();
    }
    return _shared.addref();
}

int cbor_pair::release() {
    if (_lhs) {
        _lhs->release();
    }
    if (_rhs) {
        _rhs->release();
    }
    return _shared.delref();
}

cbor_data* cbor_pair::left() { return _lhs; }

cbor_object* cbor_pair::right() { return _rhs; }

void cbor_pair::represent(stream_t* s) {
    if (s) {
        _lhs->represent(s);
        s->printf(":");
        _rhs->represent(s);
    }
}

void cbor_pair::represent(binary_t* b) {
    cbor_encode enc;

    if (b) {
        _lhs->represent(b);
        _rhs->represent(b);
    }
}

}  // namespace io
}  // namespace hotplace
