/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   cbor_simple.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7049 Concise Binary Object Representation (CBOR)
 *  RFC 8949 Concise Binary Object Representation (CBOR)
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/cbor/cbor_simple.hpp>

namespace hotplace {
namespace io {

cbor_simple::cbor_simple(uint8 value) : cbor_object(cbor_type_t::simple), _value(value) { _type = is_kind_of_value(value); }

cbor_simple_t cbor_simple::simple_type() { return is_kind_of_value(_value); }

cbor_simple_t cbor_simple::is_kind_of(uint8 first) {
    cbor_simple_t type = cbor_simple_t::unknown;

    __try2 {
        byte_t lead_type = (first & 0xe0) >> 5;
        byte_t lead_value = (first & 0x1f);

        if (t_underlying(cbor_major_t::simple) != lead_type) {
            __leave2;
        }
        type = is_kind_of_value(lead_value);
    }
    __finally2 {}

    return type;
}

cbor_simple_t cbor_simple::is_kind_of_value(uint8 value) {
    cbor_simple_t type = cbor_simple_t::value;

    if (20 == value) {
        type = cbor_simple_t::_false;
    } else if (21 == value) {
        type = cbor_simple_t::_true;
    } else if (22 == value) {
        type = cbor_simple_t::null;
    } else if (23 == value) {
        type = cbor_simple_t::undef;
    } else if (25 == value) {
        type = cbor_simple_t::half_fp;
    } else if (26 == value) {
        type = cbor_simple_t::single_fp;
    } else if (27 == value) {
        type = cbor_simple_t::double_fp;
    } else if (30 == value) {
        type = cbor_simple_t::reserved;
    } else if (31 == value) {
        type = cbor_simple_t::simple_break;
    } else if (24 >= value) {
        type = cbor_simple_t::value;
    }
    return type;
}

void cbor_simple::represent(stream_t* s) {
    constexpr char constexpr_false[] = "false";
    constexpr char constexpr_null[] = "null";
    constexpr char constexpr_true[] = "true";
    constexpr char constexpr_undefined[] = "undefined";

    if (s) {
        t_enum_type<cbor_simple_t> et_value(_value);
        switch (et_value.get()) {
            case cbor_simple_t::_false:
                s->printf(constexpr_false);
                break;
            case cbor_simple_t::_true:
                s->printf(constexpr_true);
                break;
            case cbor_simple_t::null:
                s->printf(constexpr_null);
                break;
            case cbor_simple_t::undef:
                s->printf(constexpr_undefined);
                break;
            default:
                // Unassigned simple values are given as "simple()" with the appropriate integer in the parentheses.
                s->printf("simple(%i)", et_value);
                break;
        }
    }
}

void cbor_simple::represent(binary_t* b) {
    if (b) {
        cbor_encode enc;

        enc.encode(*b, cbor_major_t::simple, _value);
    }
}

}  // namespace io
}  // namespace hotplace
