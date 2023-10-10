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

#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>

namespace hotplace {
namespace io {

cbor_array::cbor_array() : cbor_object(cbor_type_t::cbor_type_array) {
    // do nothing
}

cbor_array::cbor_array(uint32 flags) : cbor_object(cbor_type_t::cbor_type_array, flags) {
    // do nothing
}

cbor_array::~cbor_array() {
    // do nothing
}

return_t cbor_array::join(cbor_object* object, cbor_object* extra) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        switch (object->type()) {
            case cbor_type_t::cbor_type_array:
            case cbor_type_t::cbor_type_data:
            case cbor_type_t::cbor_type_map:
                _array.push_back(object);
                break;
            default:
                ret = errorcode_t::not_available;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

cbor_array& cbor_array::add(cbor_array* object) {
    join(object);
    return *this;
}

cbor_array& cbor_array::add(cbor_data* object) {
    join(object);
    return *this;
}

cbor_array& cbor_array::add(cbor_map* object) {
    join(object);
    return *this;
}

cbor_array& cbor_array::operator<<(cbor_array* object) {
    join(object);
    return *this;
}

cbor_array& cbor_array::operator<<(cbor_data* object) {
    join(object);
    return *this;
}

cbor_array& cbor_array::operator<<(cbor_map* object) {
    join(object);
    return *this;
}

size_t cbor_array::size() { return _array.size(); }

cbor_object* cbor_array::operator[](size_t index) {
    cbor_object* item = nullptr;

    if (_array.size() > index) {
        std::list<cbor_object*>::iterator it = _array.begin();
        std::advance(it, index);
        item = *it;
    }
    return item;
}

std::list<cbor_object*>& cbor_array::accessor() { return _array; }

int cbor_array::addref() {
    std::list<cbor_object*>::iterator iter;

    for (iter = _array.begin(); iter != _array.end(); iter++) {
        cbor_object* item = *iter;
        item->addref();
    }
    return _shared.addref();
}

int cbor_array::release() {
    std::list<cbor_object*>::iterator iter;

    for (iter = _array.begin(); iter != _array.end(); iter++) {
        cbor_object* item = *iter;
        item->release();
    }
    return _shared.delref();
}

void cbor_array::represent(stream_t* s) {
    if (s) {
        if (tagged()) {
            s->printf("%I64i(", (uint64)tag_value());
        }

        s->printf("[");
        if (cbor_flag_t::cbor_indef == (get_flags() & cbor_flag_t::cbor_indef)) {
            s->printf("_ ");
        }

        size_t i = 0;
        size_t size = _array.size();
        std::list<cbor_object*>::iterator iter;
        for (i = 0, iter = _array.begin(); iter != _array.end(); i++, iter++) {
            cbor_object* item = *iter;
            item->represent(s);
            if (i + 1 != size) {
                s->printf(",");
            }
        }

        s->printf("]");

        if (tagged()) {
            s->printf(")");
        }
    }
}

void cbor_array::represent(binary_t* b) {
    cbor_encode enc;

    if (b) {
        if (tagged()) {
            enc.encode(*b, cbor_major_t::cbor_major_tag, (uint64)tag_value());
        }

        enc.encode(*b, cbor_major_t::cbor_major_array, cbor_control_t::cbor_control_begin, this);

        // for each member
#if __cplusplus >= 201103L  // c++11
        for (auto item : _array) {
#else
        std::list<cbor_object*>::iterator iter;
        for (iter = _array.begin(); iter != _array.end(); iter++) {
            cbor_object* item = *iter;
#endif
            item->represent(b);
        }

        enc.encode(*b, cbor_major_t::cbor_major_array, cbor_control_t::cbor_control_end, this);
    }
}

}  // namespace io
}  // namespace hotplace
