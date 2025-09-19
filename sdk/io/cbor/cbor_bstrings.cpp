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

#include <hotplace/sdk/io/cbor/cbor_bstrings.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>

namespace hotplace {
namespace io {

cbor_bstrings::cbor_bstrings() : cbor_object(cbor_type_t::cbor_type_bstrs, cbor_flag_t::cbor_indef) {}

cbor_bstrings::~cbor_bstrings() {}

return_t cbor_bstrings::join(cbor_object* object, cbor_object* extra) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_type_t::cbor_type_data == object->type()) {
            cbor_data* inst = (cbor_data*)object;
            if (TYPE_BINARY == inst->data().type()) {
                _array.push_back(inst);
            } else {
                ret = errorcode_t::not_available;
            }
        } else {
            ret = errorcode_t::not_available;
        }
    }
    __finally2 {}
    return ret;
}

cbor_bstrings& cbor_bstrings::add(cbor_object* object, cbor_object* extra) {
    join(object, extra);
    return *this;
}

cbor_bstrings& cbor_bstrings::add(const byte_t* bstr, size_t size) {
    join(new cbor_data(bstr, size));
    return *this;
}

cbor_bstrings& cbor_bstrings::operator<<(binary_t bin) {
    join(new cbor_data(&bin[0], bin.size()));
    return *this;
}

size_t cbor_bstrings::size() { return _array.size(); }

int cbor_bstrings::addref() {
    for (cbor_data* item : _array) {
        item->addref();
    }
    return _shared.addref();
}

int cbor_bstrings::release() {
    for (cbor_data* item : _array) {
        item->release();
    }

    return _shared.delref();
}

void cbor_bstrings::represent(stream_t* s) {
    if (s) {
        s->printf("(");
        if (cbor_flag_t::cbor_indef == (get_flags() & cbor_flag_t::cbor_indef)) {
            s->printf("_ ");
        }

        size_t i = 0;
        size_t size = _array.size();
        for (cbor_data* item : _array) {
            item->represent(s);
            if (i + 1 != size) {
                s->printf(",");
            }
            i++;
        }

        s->printf(")");
    }
}

void cbor_bstrings::represent(binary_t* b) {
    cbor_encode enc;

    if (b) {
        enc.encode(*b, cbor_major_t::cbor_major_bstr, cbor_control_t::cbor_control_begin, this);

        // for each member
        for (auto item : _array) {
            item->represent(b);
        }

        enc.encode(*b, cbor_major_t::cbor_major_bstr, cbor_control_t::cbor_control_end, this);
    }
}

}  // namespace io
}  // namespace hotplace
