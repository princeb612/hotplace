/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/types.hpp>
#include <sdk/io/basic/payload.hpp>

namespace hotplace {
namespace io {

payload_member::payload_member(uint8 value, const char* name, const char* group)
    : _change_endian(false), _ref(nullptr), _refmulti(1), _vl(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint8(value);
}

payload_member::payload_member(uint8 value, uint16 repeat, const char* name, const char* group)
    : _change_endian(false), _ref(nullptr), _refmulti(1), _vl(nullptr), _reserve(repeat) {
    set_name(name).set_group(group);
    binary_t bin;
    uint16 temp = repeat;
    while (temp--) {
        bin.insert(bin.end(), value);
    }
    get_variant().set_binary_new(bin);
}

payload_member::payload_member(uint16 value, bool change_endian, const char* name, const char* group)
    : _change_endian(change_endian), _ref(nullptr), _refmulti(1), _vl(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint16(value);
}

payload_member::payload_member(uint24_t value, const char* name, const char* group)
    : _change_endian(true), _ref(nullptr), _refmulti(1), _vl(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    uint32 ui32 = 0;
    b24_i32((byte_t*)&value, 3, ui32);
    get_variant().set_uint24(ui32);
}

payload_member::payload_member(uint32_24_t value, const char* name, const char* group)
    : _change_endian(true), _ref(nullptr), _refmulti(1), _vl(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint24(value.get());
}

payload_member::payload_member(uint32 value, bool change_endian, const char* name, const char* group)
    : _change_endian(change_endian), _ref(nullptr), _refmulti(1), _vl(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint32(value);
}

payload_member::payload_member(uint64 value, bool change_endian, const char* name, const char* group)
    : _change_endian(change_endian), _ref(nullptr), _refmulti(1), _vl(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint64(value);
}

#if defined __SIZEOF_INT128__
payload_member::payload_member(uint128 value, bool change_endian, const char* name, const char* group)
    : _change_endian(change_endian), _ref(nullptr), _refmulti(1), _vl(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_uint128(value);
}
#endif

payload_member::payload_member(const binary_t& value, const char* name, const char* group)
    : _change_endian(false), _ref(nullptr), _refmulti(1), _vl(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_binary_new(value);
}

payload_member::payload_member(const std::string& value, const char* name, const char* group)
    : _change_endian(false), _ref(nullptr), _refmulti(1), _vl(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_str_new(value);
}

payload_member::payload_member(const stream_t* value, const char* name, const char* group)
    : _change_endian(false), _ref(nullptr), _refmulti(1), _vl(nullptr), _reserve(0) {
    set_name(name).set_group(group);
    get_variant().set_bstr_new(value);
}

payload_member::payload_member(payload_encoded* value, const char* name, const char* group)
    : _change_endian(false), _ref(nullptr), _refmulti(1), _vl(value), _reserve(0) {
    set_name(name).set_group(group);
}

payload_member::~payload_member() {
    if (_vl) {
        _vl->release();
    }
}

bool payload_member::get_change_endian() { return _change_endian; }

std::string payload_member::get_name() const { return _name; }

std::string payload_member::get_group() const { return _group; }

bool payload_member::encoded() const { return nullptr != _vl; }

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
    if (encoded()) {
        space = get_payload_encoded()->lsize();
    } else if (_reserve) {
        space = _reserve;
    } else if (variant_flag_t::flag_int == get_variant().flag()) {
        space = get_variant().size();
    } else if (_ref) {
        space = t_to_int<size_t>(_ref) * _refmulti;
    }
    return space;
}

size_t payload_member::get_capacity() {
    size_t space = 0;
    if (encoded()) {
        space = get_payload_encoded()->lsize();
    } else if (_reserve) {
        space = _reserve;
    } else if (_ref) {
        space = t_to_int<size_t>(_ref) * _refmulti;
    } else {
        space = get_variant().size();
    }
    return space;
}

size_t payload_member::get_reference_value() {
    size_t size = 0;
    if (encoded()) {
        size = get_payload_encoded()->value();
    } else if (_reserve) {
        size = _reserve;
    } else if (_ref) {
        size = t_to_int<size_t>(_ref) * _refmulti;
    } else {
        size = t_to_int<size_t>(this);
    }
    return size;
}

payload_member* payload_member::get_reference_of() { return _ref; }

payload_member& payload_member::set_reference_of(payload_member* member, uint8 multiple) {
    _ref = member;
    _refmulti = multiple ? multiple : 1;
    return *this;
}

payload_member& payload_member::write(binary_t& bin) {
    uint32 flags = 0;
    if (encoded()) {
        get_payload_encoded()->write(bin);
    } else {
        if (get_change_endian()) {
            flags |= variant_convendian;
        }
        get_variant().to_binary(bin, flags);
    }
    return *this;
}

return_t payload_member::doread(const byte_t* ptr, size_t size_ptr, size_t offset, size_t* size_read) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr && nullptr == size_read) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        *size_read = 0;

        if (offset > size_ptr) {
            ret = errorcode_t::bad_data;
            __leave2;
        } else if (offset == size_ptr) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        const byte_t* rebase = ptr + offset;
        size_t limit = size_ptr - offset;

        variant& v = get_variant();
        vartype_t type = v.type();
        if (variant_flag_t::flag_int == v.flag()) {
            uint16 vsize = v.size();
            if (limit >= vsize) {
                switch (type) {
                    case TYPE_INT8:
                    case TYPE_UINT8: {
                        v.clear().set_uint8(*(uint8*)rebase);
                        *size_read = vsize;
                    } break;
                    case TYPE_INT16:
                    case TYPE_UINT16: {
                        uint16 temp = *(uint16*)rebase;
                        if (get_change_endian()) {
                            temp = ntoh16(temp);
                        }
                        v.clear().set_uint16(temp);
                        *size_read = vsize;
                    } break;
                    case TYPE_INT24:
                    case TYPE_UINT24: {
                        uint32 temp = 0;
                        b24_i32(rebase, limit, temp);
                        v.clear().set_uint24(temp);
                        *size_read = vsize;
                    } break;
                    case TYPE_INT32:
                    case TYPE_UINT32: {
                        uint32 temp = *(uint32*)rebase;
                        if (get_change_endian()) {
                            temp = ntoh32(temp);
                        }
                        v.clear().set_uint32(temp);
                        *size_read = vsize;
                    } break;
                    case TYPE_INT64:
                    case TYPE_UINT64: {
                        uint64 temp = *(uint64*)rebase;
                        if (get_change_endian()) {
                            temp = ntoh64(temp);
                        }
                        v.clear().set_uint64(temp);
                        *size_read = vsize;
                    } break;
#if defined __SIZEOF_INT128__
                    case TYPE_INT128:
                    case TYPE_UINT128: {
                        uint128 temp = *(uint128*)rebase;
                        if (get_change_endian()) {
                            temp = ntoh128(temp);
                        }
                        v.clear().set_uint64(temp);
                        *size_read = vsize;
                    } break;
#endif
                    default:
                        break;
                }
            }
        } else {
            size_t size = 0;
            payload_member* ref = get_reference_of();
            if (_reserve) {
                size = _reserve;
            } else if (ref) {
                auto encoded = ref->get_payload_encoded();
                if (encoded) {
                    size = encoded->value();
                } else {
                    size = t_to_int<size_t>(ref);
                }
            }

            if (limit >= size) {
                switch (type) {
                    case TYPE_STRING:
                        v.clear().set_strn_new((char*)rebase, size);
                        *size_read = size;
                        break;
                    case TYPE_BINARY:
                        v.clear().set_bstr_new(rebase, size);
                        *size_read = size;
                        break;
                    default:
                        break;
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t payload_member::doread_encoded(const byte_t* ptr, size_t size_ptr, size_t offset, size_t* size_read) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr && nullptr == size_read) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        *size_read = 0;

        if (offset > size_ptr) {
            ret = errorcode_t::bad_data;
            __leave2;
        } else if (offset == size_ptr) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        size_t pos = 0;
        ret = get_payload_encoded()->read(ptr + offset, size_ptr - offset, pos);  // delegate
        if (errorcode_t::success != ret) {
            __leave2;
        }
        *size_read = pos;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

payload_member& payload_member::read(const byte_t* ptr, size_t size_ptr, size_t offset, size_t* size_read) {
    __try2 {
        if (nullptr == ptr || 0 == size_ptr || nullptr == size_read) {
            __leave2;
        }

        if (get_payload_encoded()) {
            doread_encoded(ptr, size_ptr, offset, size_read);
        } else {
            doread(ptr, size_ptr, offset, size_read);
        }
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

payload_member& payload_member::reserve(uint16 size) {
    _reserve = size;
    return *this;
}

payload_encoded* payload_member::get_payload_encoded() { return _vl; }

}  // namespace io
}  // namespace hotplace
