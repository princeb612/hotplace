/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/basic/payload.hpp>

namespace hotplace {
namespace io {

payload_member::payload_member(uint8 value, const char* name, const char* group) : _change_endian(false), _member_value_of(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint8(value);
}

payload_member::payload_member(uint8 value, uint16 repeat, const char* name, const char* group)
    : _change_endian(false), _member_value_of(nullptr), _reserve(repeat) {
    set_name(name).set_group(group);
    binary_t bin;
    uint16 temp = repeat;
    while (temp--) {
        bin.insert(bin.end(), value);
    }
    get_variant().set_binary_new(bin);
}

payload_member::payload_member(uint16 value, bool change_endian, const char* name, const char* group)
    : _change_endian(change_endian), _member_value_of(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint16(value);
}

payload_member::payload_member(uint32_24_t value, const char* name, const char* group) : _change_endian(true), _member_value_of(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint24(value.get());
}

payload_member::payload_member(uint32 value, bool change_endian, const char* name, const char* group)
    : _change_endian(change_endian), _member_value_of(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint32(value);
}

payload_member::payload_member(uint64 value, bool change_endian, const char* name, const char* group)
    : _change_endian(change_endian), _member_value_of(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint64(value);
}

payload_member::payload_member(uint128 value, bool change_endian, const char* name, const char* group)
    : _change_endian(change_endian), _member_value_of(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint128(value);
}

payload_member::payload_member(const binary_t& value, const char* name, const char* group) : _change_endian(false), _member_value_of(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_binary_new(value);
}

bool payload_member::get_change_endian() { return _change_endian; }

std::string payload_member::get_name() const { return _name; }

std::string payload_member::get_group() const { return _group; }

payload_member& payload_member::set_change_endian(bool enable) {
    _change_endian = enable;
    return *this;
}

payload_member& payload_member::set_name(const char* name) {
    if (name) {
        _name = name;
    }
    return *this;
}

payload_member& payload_member::set_group(const char* group) {
    if (group) {
        _group = group;
    }
    return *this;
}

variant& payload_member::get_variant() { return _vt; }

size_t payload_member::get_space() {
    size_t space = 0;
    payload_member* ref = get_value_of();
    if (_reserve) {
        space = _reserve;
    } else if (variant_flag_t::flag_int == get_variant().flag()) {
        space = get_variant().size();
    } else if (ref) {
        space = t_variant_to_int<size_t>(ref->get_variant().content());
    }
    return space;
}

size_t payload_member::get_capacity() {
    size_t space = 0;
    payload_member* ref = get_value_of();
    if (_reserve) {
        space = _reserve;
    } else if (ref) {
        space = t_variant_to_int<size_t>(ref->get_variant().content());
    } else {
        space = get_variant().size();
    }
    return space;
}

payload_member* payload_member::get_value_of() { return _member_value_of; }

payload_member& payload_member::set_value_of(payload_member* member) {
    _member_value_of = member;
    return *this;
}

payload_member& payload_member::dump(binary_t& bin) {
    get_variant().dump(bin, get_change_endian());
    return *this;
}

payload_member& payload_member::read(byte_t* ptr, size_t size_ptr, size_t* size_read) {
    if (ptr && size_read) {
        size_t read_bytes = 0;
        variant& v = get_variant();
        vartype_t type = v.type();
        if (variant_flag_t::flag_int == v.flag()) {
            uint16 size = v.size();
            if (size_ptr >= size) {
                switch (type) {
                    case TYPE_INT8:
                    case TYPE_UINT8: {
                        v.set_uint8(*(uint8*)ptr);
                        *size_read = size;
                    } break;
                    case TYPE_INT16:
                    case TYPE_UINT16: {
                        uint16 temp = *(uint16*)ptr;
                        if (get_change_endian()) {
                            temp = ntoh16(temp);
                        }
                        v.set_uint16(temp);
                        *size_read = size;
                    } break;
                    case TYPE_INT24:
                    case TYPE_UINT24: {
                        uint32 temp = 0;
                        b24_i32(ptr, size_ptr, temp);
                        v.set_uint24(temp);
                        *size_read = size;
                    } break;
                    case TYPE_INT32:
                    case TYPE_UINT32: {
                        uint32 temp = *(uint32*)ptr;
                        if (get_change_endian()) {
                            temp = ntoh32(temp);
                        }
                        v.set_uint32(temp);
                        *size_read = size;
                    } break;
                    case TYPE_INT64:
                    case TYPE_UINT64: {
                        uint64 temp = *(uint64*)ptr;
                        if (get_change_endian()) {
                            temp = ntoh64(temp);
                        }
                        v.set_uint64(temp);
                        *size_read = size;
                    } break;
                    case TYPE_INT128:
                    case TYPE_UINT128: {
                        uint128 temp = *(uint128*)ptr;
                        if (get_change_endian()) {
                            temp = ntoh128(temp);
                        }
                        v.set_uint64(temp);
                        *size_read = size;
                    } break;
                    default:
                        break;
                }
            }
        } else {
            size_t size = 0;
            payload_member* ref = get_value_of();
            if (_reserve) {
                size = _reserve;
            } else if (ref) {
                size = t_variant_to_int<size_t>(ref->get_variant().content());
            }

            if (size_ptr >= size) {
                switch (type) {
                    case TYPE_STRING:
                        v.reset();
                        v.set_strn_new((char*)ptr, size);
                        *size_read = size;
                        break;
                    case TYPE_BINARY:
                        v.reset();
                        v.set_bstr_new(ptr, size);
                        *size_read = size;
                        break;
                    default:
                        break;
                }
            }
        }
    }
    return *this;
}

payload_member& payload_member::reserve(uint16 size) {
    _reserve = size;
    return *this;
}

payload::payload() {}

payload::~payload() { clear(); }

payload& payload::operator<<(payload_member* member) {
    if (member) {
        // dump
        _members.push_back(member);

        // read(parse)
        if (member->get_name().size()) {
            _members_map.insert(std::make_pair(member->get_name(), member));
        }
    }
    return *this;
}

payload& payload::set_group(const std::string& name, bool optional) {
    _option[name] = optional;
    return *this;
}

bool payload::get_group_condition(const std::string& name) {
    bool ret = true;
    maphint<std::string, bool> hint(_option);
    hint.find(name, &ret);
    return ret;
}

payload& payload::set_reference_value(const std::string& name, const std::string& ref) {
    size_t space = 0;
    if (name.size() && ref.size()) {
        payload_member* member_ref = nullptr;
        payload_member* member = nullptr;
        maphint<std::string, payload_member*> hint(_members_map);
        hint.find(ref, &member_ref);
        hint.find(name, &member);
        if (member && member_ref) {
            if (member_ref->get_space()) {
                member->set_value_of(member_ref);
            }
        }
    }
    return *this;
}

return_t payload::dump(binary_t& bin) {
    return_t ret = errorcode_t::success;
    for (auto item : _members) {
        bool condition = get_group_condition(item->get_group());
        if (condition) {
            item->dump(bin);
        }
    }
    return ret;
}

return_t payload::read(const binary_t& bin) { return read((byte_t*)&bin[0], bin.size()); }

return_t payload::read(byte_t* base, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == base) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_sum = 0;
        std::list<payload_member*> _size_unknown;

        {
            byte_t* p = base;
            size_t len = size;
            size_t pos = 0;
            size_t size_read = 0;
            bool check = true;
            for (auto item : _members) {
                bool condition = get_group_condition(item->get_group());
                if (false == condition) {
                    continue;
                }

                uint16 space = item->get_space();
                size_sum += space;
                if (0 == space) {
                    if (nullptr == item->get_value_of()) {
                        _size_unknown.push_back(item);
                    }
                    check = false;
                } else {
                    if (check) {
                        item->read(p + pos, len, &size_read);
                        p += size_read;
                        len -= size_read;
                    }
                }
            }
        }

        if (_size_unknown.size() > 1) {
            ret = errorcode_t::unknown;
            __leave2;
        }

        if (size > size_sum) {
            if (1 == _size_unknown.size()) {
                size_t remain = size - size_sum;
                payload_member* item = *(_size_unknown.begin());
                item->reserve(remain);
                _size_unknown.clear();
            }
        }

        if (_size_unknown.empty()) {
            byte_t* p = base;
            size_t len = size;
            size_t pos = 0;
            size_t size_read = 0;
            bool check = true;
            for (auto item : _members) {
                bool condition = get_group_condition(item->get_group());
                if (false == condition) {
                    continue;
                }

                uint16 space = item->get_space();
                size_sum += space;

                if (len < space) {
                    ret = errorcode_t::insufficient;
                    break;
                }

                item->read(p + pos, len, &size_read);
                p += size_read;
                len -= size_read;
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

payload& payload::for_each(std::function<void(payload_member*)> func) {
    if (func) {
        for (auto item : _members) {
            func(item);
        }
    }
    return *this;
}

payload_member* payload::select(const std::string& name) {
    payload_member* item = nullptr;
    maphint<std::string, payload_member*> hint(_members_map);
    hint.find(name, &item);
    return item;
}

size_t payload::size_estimated() {
    size_t ret_value = 0;
    for (auto item : _members) {
        bool condition = get_group_condition(item->get_group());
        if (false == condition) {
            continue;
        }

        ret_value += item->get_space();
    }
    return ret_value;
}

size_t payload::size_occupied() {
    size_t ret_value = 0;
    for (auto item : _members) {
        bool condition = get_group_condition(item->get_group());
        if (false == condition) {
            continue;
        }

        ret_value += item->get_capacity();
    }
    return ret_value;
}

payload& payload::clear() {
    for (auto item : _members) {
        delete item;
    }
    return *this;
}

}  // namespace io
}  // namespace hotplace
