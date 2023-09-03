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

cbor_data::cbor_data () : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_init (_vt);
}

cbor_data::cbor_data (bool value) : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_set_bool (_vt, value);
}

cbor_data::cbor_data (int8 value) : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_set_int8 (_vt, value);
}

cbor_data::cbor_data (int16 value) : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_set_int16 (_vt, value);
}

cbor_data::cbor_data (int32 value) : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_set_int32 (_vt, value);
}

cbor_data::cbor_data (int64 value) : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_set_int64 (_vt, value);
}

#if defined __SIZEOF_INT128__
cbor_data::cbor_data (int128 value) : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_set_int128 (_vt, value);
}
#endif

cbor_data::cbor_data (const byte_t * bstr, size_t size) : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_set_bstr_new (_vt, (byte_t*) bstr, size);
}

cbor_data::cbor_data (const char* tstr) : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_set_str_new (_vt, tstr);
}

cbor_data::cbor_data (const char* tstr, size_t length) : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_set_strn_new (_vt, tstr, length);
}

cbor_data::cbor_data (float value) : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_set_float (_vt, value);
}

cbor_data::cbor_data (double value) : cbor_object (cbor_type_t::cbor_type_data)
{
    variant_set_double (_vt, value);
}

cbor_data::~cbor_data ()
{
    clear ();
}

return_t cbor_data::clear ()
{
    return_t ret = errorcode_t::success;

    variant_free (_vt);
    return ret;
}

const variant_t& cbor_data::data ()
{
    return _vt;
}

void cbor_data::represent (stream_t* s)
{
    if (s) {
        if (tagged ()) {
            // RFC 8949 Concise Binary Object Representation (CBOR)
            // Decoders that understand these tags MUST be able to decode bignums that do have leading zeroes.
            cbor_tag_t tag = tag_value ();
            const variant_t& vt_own = data ();
            if ((TYPE_BINARY == vt_own.type) && (vt_own.data.bstr32.size <= 16)) {
                cbor_bignum_int128 bn;
                int128 temp = bn.load (vt_own.data.bstr32.data, vt_own.data.bstr32.size).value ();
                variant_t vt;
                variant_init (vt);
                if (cbor_tag_t::cbor_tag_positive_bignum == tag) {
                    variant_set_int128 (vt, temp);
                } else if (cbor_tag_t::cbor_tag_negative_bignum == tag) {
                    variant_set_int128 (vt, -(temp + 1));
                }
                vtprintf (s, vt, vtprintf_style_t::vtprintf_style_cbor);

            }
        } else {
            vtprintf (s, data (), vtprintf_style_t::vtprintf_style_cbor);
        }
    }
}

void cbor_data::represent (binary_t* b)
{
    if (b) {
        cbor_encode enc;
        binary_t temp;

        enc.add_tag (temp, this);
        enc.encode (temp, data ());
        (*b).insert ((*b).end (), temp.begin (), temp.end ());
    }
}

}
}
