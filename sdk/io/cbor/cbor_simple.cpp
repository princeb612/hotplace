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

#include <hotplace/sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace io {

cbor_simple::cbor_simple (uint8 value) : cbor_object (cbor_type_t::cbor_type_simple), _value (value)
{
    _type = is_kind_of_value (value);
}

cbor_simple_t cbor_simple::simple_type ()
{
    return _type;
}

cbor_simple_t cbor_simple::is_kind_of (uint8 first)
{
    cbor_simple_t type = cbor_simple_t::cbor_simple_error;

    __try2
    {
        byte_t lead_type = (first & 0xe0) >> 5;
        byte_t lead_value = (first & 0x1f);

        if (cbor_major_t::cbor_major_simple != lead_type) {
            __leave2;
        }
        type = is_kind_of_value (lead_value);
    }
    __finally2
    {
        // do nothing
    }

    return type;
}

cbor_simple_t cbor_simple::is_kind_of_value (uint8 value)
{
    cbor_simple_t type = cbor_simple_t::cbor_simple_error;

    if (24 >= value) {
        type = cbor_simple_t::cbor_simple_value;
    } else if (25 == value) {
        type = cbor_simple_t::cbor_simple_half_fp;
    } else if (26 == value) {
        type = cbor_simple_t::cbor_simple_single_fp;
    } else if (27 == value) {
        type = cbor_simple_t::cbor_simple_double_fp;
    } else if (31 == value) {
        type = cbor_simple_t::cbor_simple_break;
    } else {
        type = cbor_simple_t::cbor_simple_reserved;
    }
    return type;
}

void cbor_simple::represent (stream_t* s)
{
/* "false" */
#define DECLARE_STRING_FALSE char STRING_FALSE[] = { 'f', 'a', 'l', 's', 'e', 0, \
};
/* "true" */
#define DECLARE_STRING_TRUE char STRING_TRUE[] = { 't', 'r', 'u', 'e', 0, };
/* "null" */
#define DECLARE_STRING_NULL char STRING_NULL[] = { 'n', 'u', 'l', 'l', 0, };
/* "undefined" */
#define DECLARE_STRING_UNDEFINED char STRING_UNDEFINED[] = { 'u', 'n', 'd', 'e', 'f', 'i', 'n', 'e', 'd', 0, };

    DECLARE_STRING_FALSE;
    DECLARE_STRING_TRUE;
    DECLARE_STRING_NULL;
    DECLARE_STRING_UNDEFINED;

    if (s) {
        switch (_value) {
            case cbor_simple_t::cbor_simple_false:
                s->printf (STRING_FALSE);
                break;
            case cbor_simple_t::cbor_simple_true:
                s->printf (STRING_TRUE);
                break;
            case cbor_simple_t::cbor_simple_null:
                s->printf (STRING_NULL);
                break;
            case cbor_simple_t::cbor_simple_undef:
                s->printf (STRING_UNDEFINED);
                break;
        }
    }
}

void cbor_simple::represent (binary_t* b)
{

    if (b) {
        cbor_encode enc;
        binary_t temp;

        enc.encode (temp, _type, _value);
        (*b).insert ((*b).end (), temp.begin (), temp.end ());
    }
}

}
}
