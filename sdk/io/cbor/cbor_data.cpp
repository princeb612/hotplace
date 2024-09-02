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

namespace hotplace {
namespace io {

cbor_data::cbor_data() : cbor_object(cbor_type_t::cbor_type_data) {}

cbor_data::cbor_data(bool value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_bool(value); }

cbor_data::cbor_data(int8 value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_int8(value); }

cbor_data::cbor_data(int16 value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_int16(value); }

cbor_data::cbor_data(int32 value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_int32(value); }

cbor_data::cbor_data(int64 value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_int64(value); }

#if defined __SIZEOF_INT128__
cbor_data::cbor_data(int128 value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_int128(value); }
#endif

cbor_data::cbor_data(const byte_t* bstr, size_t size) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_bstr_new(bstr, size); }

cbor_data::cbor_data(const binary_t& data) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_binary_new(data); }

cbor_data::cbor_data(const char* tstr) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_str_new(tstr); }

cbor_data::cbor_data(const char* tstr, size_t length) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_strn_new(tstr, length); }

cbor_data::cbor_data(const std::string& data) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_str_new(data.c_str()); }

cbor_data::cbor_data(const fp16_t& value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_fp16(value.storage); }

cbor_data::cbor_data(float value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_float(value); }

cbor_data::cbor_data(double value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_double(value); }

cbor_data::cbor_data(const variant_t& vt) : cbor_object(cbor_type_t::cbor_type_data), _vt(vt) {}

cbor_data::cbor_data(variant_t&& vt) : cbor_object(cbor_type_t::cbor_type_data), _vt(std::move(vt)) {}

cbor_data::cbor_data(const variant& rhs) : _vt(rhs) {}

cbor_data::cbor_data(variant&& rhs) : cbor_object(cbor_type_t::cbor_type_data), _vt(std::move(rhs)) {}

cbor_data::~cbor_data() {}

variant& cbor_data::data() { return _vt; }

void cbor_data::represent(stream_t* s) {
    const variant_t& vt = data().content();
    if (s) {
        if (tagged()) {
            cbor_tag_t tag = tag_value();
            s->printf("%I64i(", (uint64)tag);

            switch (tag) {
                case cbor_tag_t::cbor_tag_positive_bignum:
                case cbor_tag_t::cbor_tag_negative_bignum:
                    // RFC 8949 Concise Binary Object Representation (CBOR)
                    // 3.4.3.  Bignums
                    // Decoders that understand these tags MUST be able to decode bignums that do have leading zeroes.
                    if ((TYPE_BINARY == vt.type) && (vt.size <= 16)) {
                        cbor_bignum_int128 bn;
                        int128 temp = bn.load(vt.data.bstr, vt.size).value();
                        variant vt_bignum;
                        if (cbor_tag_t::cbor_tag_positive_bignum == tag) {
                            vt_bignum.set_int128(temp);
                        } else if (cbor_tag_t::cbor_tag_negative_bignum == tag) {
                            vt_bignum.set_int128(-(temp + 1));
                        }
                        vtprintf(s, vt_bignum.content(), vtprintf_style_t::vtprintf_style_cbor);
                    } else {
                        vtprintf(s, vt, vtprintf_style_t::vtprintf_style_cbor);
                    }
                    break;
                default:
                    vtprintf(s, vt, vtprintf_style_t::vtprintf_style_cbor);
                    break;
            }

            s->printf(")");
        } else {
            vtprintf(s, vt, vtprintf_style_t::vtprintf_style_cbor);
        }
    }
}

void cbor_data::represent(binary_t* b) {
    if (b) {
        cbor_encode enc;
        binary_t temp;

        enc.add_tag(temp, this);
        enc.encode(temp, data().content());
        (*b).insert((*b).end(), temp.begin(), temp.end());
    }
}

}  // namespace io
}  // namespace hotplace
