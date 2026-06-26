/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   cbor_encode.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7049 Concise Binary Object Representation (CBOR)
 *  RFC 8949 Concise Binary Object Representation (CBOR)
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>
#include <hotplace/sdk/base/system/ieee754.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/cbor/cbor_object.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <hotplace/sdk/io/system/types.hpp>

namespace hotplace {
namespace io {

cbor_encode::cbor_encode() {}

return_t cbor_encode::encode(binary_t& bin, variant_t vt) {
    return_t ret = errorcode_t::success;

    __try2 {
        switch (vt.type) {
            case vartype_t::TYPE_BOOL:
                encode(bin, vt.data.b);
                break;
            case vartype_t::TYPE_INT8:
                encode(bin, vt.data.i8);
                break;
            case vartype_t::TYPE_UINT8:
                encode(bin, (vt.flag & vt_flag_negative) ? cbor_major_t::nint : cbor_major_t::uint, vt.data.ui8);
                break;
            case vartype_t::TYPE_INT16:
                encode(bin, vt.data.i16);
                break;
            case vartype_t::TYPE_UINT16:
                encode(bin, (vt.flag & vt_flag_negative) ? cbor_major_t::nint : cbor_major_t::uint, vt.data.ui16);
                break;
            case vartype_t::TYPE_INT32:
                encode(bin, vt.data.i32);
                break;
            case vartype_t::TYPE_UINT32:
                encode(bin, (vt.flag & vt_flag_negative) ? cbor_major_t::nint : cbor_major_t::uint, vt.data.ui32);
                break;
            case vartype_t::TYPE_INT64:
                encode(bin, vt.data.i64);
                break;
            case vartype_t::TYPE_UINT64:
                encode(bin, (vt.flag & vt_flag_negative) ? cbor_major_t::nint : cbor_major_t::uint, vt.data.ui64);
                break;
            case vartype_t::TYPE_FP16:
                encodefp16(bin, vt.data.ui16);
                break;
            case vartype_t::TYPE_FLOAT:
                encode(bin, vt.data.f);
                break;
            case vartype_t::TYPE_DOUBLE:
                encode(bin, vt.data.d);
                break;
            case vartype_t::TYPE_NULL:
            case vartype_t::TYPE_STRING:
                encode(bin, vt.data.str);
                break;
            case vartype_t::TYPE_NSTRING:
                encode(bin, vt.data.str, vt.size);
                break;
            case vartype_t::TYPE_BINARY:
                encode(bin, vt.data.bstr, vt.size);
                break;
            case vartype_t::TYPE_BIGNUMBER: {
                bignumber bn(vt.data.bstr, vt.size);
                binary_t bnbin;
                bn.get(bnbin, true);
                if (bn.capacity() > 2) {
                    // RFC 8949 Concise Binary Object Representation (CBOR)
                    // Appendix A.  Examples of Encoded CBOR Data Items
                    // In the diagnostic notation provided for bignums, their intended numeric value is shown as a decimal number (such as 18446744073709551616)
                    // instead of a tagged byte string (such as 2(h'010000000000000000')).
                    encode(bin, bnbin);
                } else {
                    auto ui64 = bn.t_bntoi<uint64>();
                    encode(bin, (vt.flag & vt_flag_negative) ? cbor_major_t::nint : cbor_major_t::uint, ui64);
                }
            } break;
            default:
                break;
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& bin, bool value) {
    return_t ret = errorcode_t::success;

    __try2 {
        uint8 major = t_underlying(cbor_major_t::simple);
        uint8 simple = 0;
        if (value) {
            simple = 21;
        } else {
            simple = 20;
        }

        bin.push_back((major << 5) | simple);
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& bin, int8 value) {
    // 4.2.1.  Core Deterministic Encoding Requirements
    return_t ret = errorcode_t::success;

    __try2 {
        uint8 major = 0;
        if (value >= 0) {
            major = t_underlying(cbor_major_t::uint);
        } else {
            major = t_underlying(cbor_major_t::nint);
            value += 1;
            value = -value;
        }
        if (value < 24) {
            bin.push_back((major << 5) | value);
        } else {
            bin.push_back((major << 5) | 24);
            bin.push_back(value);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& bin, cbor_major_t major, uint8 value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (value < 24) {
            bin.push_back((t_underlying(major) << 5) | value);
        } else {
            bin.push_back((t_underlying(major) << 5) | 24);
            bin.push_back(value);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& target, int16 value) {
    // 4.2.1.  Core Deterministic Encoding Requirements
    return_t ret = errorcode_t::success;

    __try2 {
        uint8 major = 0;
        if (value >= 0) {
            major = t_underlying(cbor_major_t::uint);
        } else {
            major = t_underlying(cbor_major_t::nint);
            value += 1;
            value = -value;
        }
        if (value < 24) {
            binary_push(target, (major << 5) | value);
        } else if (value < 0x100) {
            binary_push(target, (major << 5) | 24);
            binary_push(target, t_narrow_cast(value));
        } else {
            binary_push(target, (major << 5) | 25);
            binary_append(target, value, hton16);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& target, cbor_major_t major, uint16 value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (value < 24) {
            binary_push(target, (t_underlying(major) << 5) | value);
        } else if (value < 0x100) {
            binary_push(target, (t_underlying(major) << 5) | 24);
            binary_push(target, t_narrow_cast(value));
        } else {
            binary_push(target, (t_underlying(major) << 5) | 25);
            binary_append(target, value, hton16);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& target, int32 value) {
    // 4.2.1.  Core Deterministic Encoding Requirements
    return_t ret = errorcode_t::success;

    __try2 {
        uint8 major = 0;
        if (value >= 0) {
            major = t_underlying(cbor_major_t::uint);
        } else {
            major = t_underlying(cbor_major_t::nint);
            value += 1;
            value = -value;
        }

        if (value < 24) {
            binary_push(target, (major << 5) | value);
        } else if (value < 0x100) {
            binary_push(target, (major << 5) | 24);
            binary_push(target, value);
        } else if (value < 0x10000) {
            binary_push(target, (major << 5) | 25);
            binary_append(target, (uint16)value, hton16);
        } else {
            binary_push(target, (major << 5) | 26);
            binary_append(target, value, hton32);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& target, cbor_major_t major, uint32 value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (value < 24) {
            binary_push(target, (t_underlying(major) << 5) | value);
        } else if (value < 0x100) {
            binary_push(target, (t_underlying(major) << 5) | 24);
            binary_push(target, value);
        } else if (value < 0x10000) {
            binary_push(target, (t_underlying(major) << 5) | 25);
            binary_append(target, (uint16)value, hton16);
        } else {
            binary_push(target, (t_underlying(major) << 5) | 26);
            binary_append(target, value, hton32);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& target, int64 value) {
    // 4.2.1.  Core Deterministic Encoding Requirements
    return_t ret = errorcode_t::success;

    __try2 {
        uint8 major = 0;
        if (value >= 0) {
            major = t_underlying(cbor_major_t::uint);
        } else {
            major = t_underlying(cbor_major_t::nint);
            value += 1;
            value = -value;
        }

        if (value < 24) {
            binary_push(target, t_narrow_cast((major << 5) | value));
        } else if (value < 0x100) {
            binary_push(target, (major << 5) | 24);
            binary_push(target, t_narrow_cast(value));
        } else if (value < 0x10000) {
            binary_push(target, (major << 5) | 25);
            binary_append(target, (uint16)value, hton16);
        } else if (value < 0x100000000) {
            binary_push(target, (major << 5) | 26);
            binary_append(target, (uint32)value, hton32);
        } else {
            binary_push(target, (major << 5) | 27);
            binary_append(target, value, hton64);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& target, cbor_major_t major, uint64 value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (value < 24) {
            binary_push(target, t_narrow_cast((t_underlying(major) << 5) | value));
        } else if (value < 0x100) {
            binary_push(target, (t_underlying(major) << 5) | 24);
            binary_push(target, t_narrow_cast(value));
        } else if (value < 0x10000) {
            binary_push(target, (t_underlying(major) << 5) | 25);
            binary_append(target, (uint16)value, hton16);
        } else if (value < 0x100000000) {
            binary_push(target, (t_underlying(major) << 5) | 26);
            binary_append(target, (uint32)value, hton32);
        } else {
            binary_push(target, (t_underlying(major) << 5) | 27);
            binary_append(target, value, hton64);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encodefp16(binary_t& target, uint16 value) {
    return_t ret = errorcode_t::success;

    __try2 {
        auto major = t_underlying(cbor_major_t::fp);
        binary_push(target, (major << 5) | 25);
        binary_append(target, value, hton16);
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& target, float value) {
    // 4.2.2.  Additional Deterministic Encoding Considerations
    return_t ret = errorcode_t::success;

    __try2 {
        variant var;
        ieee754_as_small_as_possible(var, value);
        auto major = t_underlying(cbor_major_t::fp);

        const variant_t& vt = var.content();
        switch (vt.type) {
            case vartype_t::TYPE_FP16:
                binary_push(target, (major << 5) | 25);
                binary_append(target, vt.data.ui16, hton16);
                break;
            case vartype_t::TYPE_FLOAT:
                binary_push(target, (major << 5) | 26);
                binary_append(target, vt.data.f, hton32);
                break;
            default:
                break;
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& target, double value) {
    // 4.2.2.  Additional Deterministic Encoding Considerations
    return_t ret = errorcode_t::success;

    __try2 {
        variant var;
        ieee754_as_small_as_possible(var, value);
        auto major = t_underlying(cbor_major_t::fp);

        const variant_t& vt = var.content();
        switch (vt.type) {
            case vartype_t::TYPE_FP16:
                binary_push(target, (major << 5) | 25);
                binary_append(target, vt.data.ui16, hton16);
                break;
            case vartype_t::TYPE_FLOAT:
                binary_push(target, (major << 5) | 26);
                binary_append(target, vt.data.f, hton32);
                break;
            case vartype_t::TYPE_DOUBLE:
                binary_push(target, (major << 5) | 27);
                binary_append(target, vt.data.d, hton64);
                break;
            default:
                break;
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& bin, const byte_t* value, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        encode(bin, cbor_major_t::bstr, size);
        binary_append(bin, value, size);
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& bin, const binary_t& value) { return encode(bin, value.data(), value.size()); }

return_t cbor_encode::encode(binary_t& bin, char* value) {
    return_t ret = errorcode_t::success;
    size_t size = 0;

    if (nullptr != value) {
        size = strlen(value);
    }
    ret = encode(bin, value, size);
    return ret;
}

return_t cbor_encode::encode(binary_t& bin, char* value, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == value) {
            uint8 major = t_underlying(cbor_major_t::simple);
            binary_push(bin, (major << 5) | 22);
        } else {
            encode(bin, cbor_major_t::tstr, size);
            binary_append(bin, value, size);
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& bin, cbor_major_t major, cbor_control_t control, cbor_object* object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 indefinite = (cbor_flag_t::cbor_indef & object->get_flags());
        if (cbor_control_t::cbor_control_begin == control) {
            if (indefinite) {
                binary_push(bin, (t_underlying(major) << 5) | 31);  // infinite-length
            } else {
                // 0xa0..0xb7 map
                encode(bin, major, object->size());
            }
        } else if (cbor_control_t::cbor_control_end == control) {
            if (indefinite) {
                binary_push(bin, 0xff);  // break
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t cbor_encode::encode(binary_t& bin, cbor_simple_t type, uint8 value) {
    return_t ret = errorcode_t::success;
    t_enum_type<cbor_simple_t> ettype(type);
    switch (ettype.get()) {
        case cbor_simple_t::half_fp:
        case cbor_simple_t::single_fp:
        case cbor_simple_t::double_fp:
            ret = errorcode_t::bad_request;
            break;
        default: {
            auto major = t_underlying(cbor_major_t::simple);
            if (value < 32) {
                binary_push(bin, (major << 5) | value);
            } else if (value < 0x100) {
                binary_push(bin, (major << 5) | 24);
                binary_push(bin, value);
            }
        } break;
    }
    return ret;
}

return_t cbor_encode::add_tag(binary_t& bin, cbor_object* object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (object->tagged()) {
            // a tag number (an integer in the range 0..2^(64)-1)
            encode(bin, cbor_major_t::tag, (uint64)object->tag_value());
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace io
}  // namespace hotplace
