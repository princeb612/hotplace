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

#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_encode.hpp>
#include <sdk/io/cbor/cbor_map.hpp>

namespace hotplace {
namespace io {

cbor_map::cbor_map() : cbor_object(cbor_type_t::cbor_type_map) {
    // do nothing
}

cbor_map::cbor_map(uint32 flags) : cbor_object(cbor_type_t::cbor_type_map, flags) {
    // do nothing
}

cbor_map::cbor_map(cbor_pair* object, uint32 flags) : cbor_object(cbor_type_t::cbor_type_map, flags) { *this << object; }

cbor_map::~cbor_map() {
    // do nothing
}

return_t cbor_map::join(cbor_object* object, cbor_object* extra) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (cbor_type_t::cbor_type_pair == object->type()) {
            cbor_pair* inst = (cbor_pair*)object;
            _array.push_back(inst);
        } else {
            // lhs cbor_data (int series, char* only)
            // rhs cbor_data, cbor_arry_t

            if (nullptr == extra) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }

            bool lhs_ret = false;
            bool rhs_ret = false;

            cbor_type_t lhs_type = object->type();
            cbor_type_t rhs_type = extra->type();

            if (cbor_type_t::cbor_type_data == lhs_type) {
                cbor_data* inst = (cbor_data*)object;
                // vartype_t lhs_vtype = inst->data().type;
                uint16 lhs_flag = inst->data().flag;
                lhs_ret = (lhs_flag & (variant_flag_t::flag_int | variant_flag_t::flag_string)) ? true : false;
            }
            switch (rhs_type) {
                case cbor_type_t::cbor_type_data:
                case cbor_type_t::cbor_type_array:
                case cbor_type_t::cbor_type_map:
                case cbor_type_t::cbor_type_simple:
                    rhs_ret = true;
                default:
                    break;
            }

            if (lhs_ret && rhs_ret) {
                // do nothing
            } else {
                ret = errorcode_t::not_available;
                __leave2;
            }

            cbor_data* inst = (cbor_data*)object;
            cbor_pair* pair = nullptr;
            __try_new_catch(pair, new cbor_pair(inst, extra), ret, __leave2);
            if (pair) {
                _array.push_back(pair);

                uint16 lhs_flag = inst->data().flag;
                if (lhs_flag & variant_flag_t::flag_int) {
                    int key = t_variant_to_int<int>(inst->data());
                } else if (lhs_flag & variant_flag_t::flag_string) {
                    std::string key;
                    variant_string(inst->data(), key);
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

cbor_map& cbor_map::add(cbor_object* object, cbor_object* extra) {
    join(object, extra);
    return *this;
}

cbor_map& cbor_map::add(cbor_pair* object) {
    join(object);
    return *this;
}

cbor_map& cbor_map::operator<<(cbor_pair* object) {
    join(object);
    return *this;
}

size_t cbor_map::size() { return _array.size(); }

cbor_pair* cbor_map::operator[](size_t index) {
    cbor_pair* item = nullptr;

    if (_array.size() > index) {
        std::list<cbor_pair*>::iterator it = _array.begin();
        std::advance(it, index);
        item = *it;
    }
    return item;
}

std::list<cbor_pair*>& cbor_map::accessor() { return _array; }

int cbor_map::addref() {
    std::list<cbor_pair*>::iterator iter;

    for (iter = _array.begin(); iter != _array.end(); iter++) {
        cbor_pair* item = *iter;
        item->addref();
    }
    return _shared.addref();
}

int cbor_map::release() {
    return_t ret = errorcode_t::success;

    std::list<cbor_pair*>::iterator iter;

    for (iter = _array.begin(); iter != _array.end(); iter++) {
        cbor_pair* item = *iter;
        item->release();
    }
    return _shared.delref();
}

void cbor_map::represent(stream_t* s) {
    if (s) {
        s->printf("{");
        if (cbor_flag_t::cbor_indef == (get_flags() & cbor_flag_t::cbor_indef)) {
            s->printf("_ ");
        }

        size_t i = 0;
        size_t size = _array.size();
        std::list<cbor_pair*>::iterator iter;
        for (i = 0, iter = _array.begin(); iter != _array.end(); i++, iter++) {
            cbor_pair* item = *iter;
            item->represent(s);
            if (i + 1 != size) {
                s->printf(",");
            }
        }

        s->printf("}");
    }
}

void cbor_map::represent(binary_t* b) {
    cbor_encode enc;

    if (b) {
        enc.encode(*b, cbor_major_t::cbor_major_map, cbor_control_t::cbor_control_begin, this);

        // for each member
#if __cplusplus >= 201103L  // c++11
        for (auto item : _array) {
#else
        std::list<cbor_pair*>::iterator iter;
        for (iter = _array.begin(); iter != _array.end(); iter++) {
            cbor_pair* item = *iter;
#endif
            item->represent(b);
        }

        enc.encode(*b, cbor_major_t::cbor_major_map, cbor_control_t::cbor_control_end, this);
    }
}

}  // namespace io
}  // namespace hotplace
