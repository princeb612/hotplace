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
#include <hotplace/sdk/io/cbor/cbor_pair.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>

namespace hotplace {
namespace io {

cbor_map::cbor_map() : cbor_object(cbor_type_t::cbor_type_map) {}

cbor_map::cbor_map(uint32 flags) : cbor_object(cbor_type_t::cbor_type_map, flags) {}

cbor_map::cbor_map(cbor_pair* object, uint32 flags) : cbor_object(cbor_type_t::cbor_type_map, flags) { *this << object; }

cbor_map::~cbor_map() {}

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
                uint16 lhs_flag = inst->data().flag();
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

                uint16 lhs_flag = inst->data().flag();
                if (lhs_flag & variant_flag_t::flag_int) {
                    int key = inst->data().to_int();
                } else if (lhs_flag & variant_flag_t::flag_string) {
                    std::string key;
                    inst->data().to_string(key);
                }
            }
        }
    }
    __finally2 {}

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
    for (cbor_pair* item : _array) {
        item->addref();
    }
    return _shared.addref();
}

int cbor_map::release() {
    return_t ret = errorcode_t::success;

    for (cbor_pair* item : _array) {
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
        for (cbor_pair* item : _array) {
            item->represent(s);
            if (i + 1 != size) {
                s->printf(",");
            }
            i++;
        }

        s->printf("}");
    }
}

void cbor_map::represent(binary_t* b) {
    cbor_encode enc;

    if (b) {
        enc.encode(*b, cbor_major_t::cbor_major_map, cbor_control_t::cbor_control_begin, this);

        // for each member
        for (auto item : _array) {
            item->represent(b);
        }

        enc.encode(*b, cbor_major_t::cbor_major_map, cbor_control_t::cbor_control_end, this);
    }
}

template <typename K, typename V>
cbor_map& cbor_map::add(K value, std::function<void(V* object)> f, uint32 flags) {
    if (f) {
        auto obj = new V(flags);
        f(obj);
        *this << new cbor_pair(value, obj);
    }
    return *this;
}

#if defined __SIZEOF_INT128__
cbor_map& cbor_map::add(int128 value, cbor_data* object) {
    *this << new cbor_pair(value, object);
    return *this;
}

cbor_map& cbor_map::add(int128 value, cbor_map* object) {
    *this << new cbor_pair(value, object);
    return *this;
}

cbor_map& cbor_map::add(int128 value, cbor_array* object) {
    *this << new cbor_pair(value, object);
    return *this;
}

cbor_map& cbor_map::add(int128 value, std::function<void(cbor_map* object)> f, uint32 flags) { return add<int128, cbor_map>(value, f, flags); }

cbor_map& cbor_map::add(int128 value, std::function<void(cbor_array* object)> f, uint32 flags) { return add<int128, cbor_array>(value, f, flags); }
#else
cbor_map& cbor_map::add(int64 value, cbor_data* object) {
    *this << new cbor_pair(value, object);
    return *this;
}

cbor_map& cbor_map::add(int64 value, cbor_map* object) {
    *this << new cbor_pair(value, object);
    return *this;
}

cbor_map& cbor_map::add(int64 value, cbor_array* object) {
    *this << new cbor_pair(value, object);
    return *this;
}

cbor_map& cbor_map::add(int64 value, std::function<void(cbor_map* object)> f, uint32 flags) { return add<int64, cbor_map>(value, f, flags); }

cbor_map& cbor_map::add(int64 value, std::function<void(cbor_array* object)> f, uint32 flags) { return add<int64, cbor_array>(value, f, flags); }
#endif

cbor_map& cbor_map::add(const char* key, cbor_data* object) {
    *this << new cbor_pair(key, object);
    return *this;
}

cbor_map& cbor_map::add(const char* key, cbor_map* object) {
    *this << new cbor_pair(key, object);
    return *this;
}

cbor_map& cbor_map::add(const char* key, cbor_array* object) {
    *this << new cbor_pair(key, object);
    return *this;
}

cbor_map& cbor_map::add(const char* key, std::function<void(cbor_map*)> f, uint32 flags) { return add<const char*, cbor_map>(key, f, flags); }

cbor_map& cbor_map::add(const char* key, std::function<void(cbor_array*)> f, uint32 flags) { return add<const char*, cbor_array>(key, f, flags); }

cbor_map& cbor_map::add(cbor_data* key, cbor_data* object) {
    *this << new cbor_pair(key, object);
    return *this;
}

cbor_map& cbor_map::add(cbor_data* key, cbor_map* object) {
    *this << new cbor_pair(key, object);
    return *this;
}

cbor_map& cbor_map::add(cbor_data* key, cbor_array* object) {
    *this << new cbor_pair(key, object);
    return *this;
}

cbor_map& cbor_map::add(cbor_data* key, std::function<void(cbor_map*)> f, uint32 flags) { return add<cbor_data*, cbor_map>(key, f, flags); }

cbor_map& cbor_map::add(cbor_data* key, std::function<void(cbor_array*)> f, uint32 flags) { return add<cbor_data*, cbor_array>(key, f, flags); }

}  // namespace io
}  // namespace hotplace
