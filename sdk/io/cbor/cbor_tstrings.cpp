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

#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/cbor/cbor_tstrings.hpp>

namespace hotplace {
namespace io {

cbor_tstrings::cbor_tstrings() : cbor_object(cbor_type_t::cbor_type_tstrs, cbor_flag_t::cbor_indef) {}

cbor_tstrings::~cbor_tstrings() {}

return_t cbor_tstrings::join(cbor_object* object, cbor_object* extra) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_type_t::cbor_type_data == object->type()) {
            cbor_data* inst = (cbor_data*)object;
            if (TYPE_STRING == inst->data().type()) {
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

cbor_tstrings& cbor_tstrings::add(cbor_object* object, cbor_object* extra) {
    join(object, extra);
    return *this;
}

cbor_tstrings& cbor_tstrings::add(const char* str) {
    join(new cbor_data(str));
    return *this;
}

cbor_tstrings& cbor_tstrings::operator<<(const char* str) {
    join(new cbor_data(str));
    return *this;
}

size_t cbor_tstrings::size() { return _array.size(); }

int cbor_tstrings::addref() {
    for (cbor_data* item : _array) {
        item->addref();
    }
    return _shared.addref();
}

int cbor_tstrings::release() {
    for (cbor_data* item : _array) {
        item->release();
    }
    return _shared.delref();
}

void cbor_tstrings::represent(stream_t* s) {
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

void cbor_tstrings::represent(binary_t* b) {
    cbor_encode enc;

    if (b) {
        enc.encode(*b, cbor_major_t::cbor_major_tstr, cbor_control_t::cbor_control_begin, this);

        // for each member
        for (auto item : _array) {
            item->represent(b);
        }

        enc.encode(*b, cbor_major_t::cbor_major_tstr, cbor_control_t::cbor_control_end, this);
    }
}

}  // namespace io
}  // namespace hotplace
