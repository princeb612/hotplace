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

#include <hotplace/sdk/base/system/bignumber.hpp>
#include <hotplace/sdk/base/template.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>

namespace hotplace {
namespace io {

cbor_data::cbor_data() : cbor_object(cbor_type_t::cbor_type_data) {}

cbor_data::cbor_data(bool value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_bool(value); }

cbor_data::cbor_data(int8 value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_int8(value); }

cbor_data::cbor_data(int16 value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_int16(value); }

cbor_data::cbor_data(int32 value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_int32(value); }

cbor_data::cbor_data(int64 value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_int64(value); }

cbor_data::cbor_data(uint8 value, uint32 flags) : cbor_object(cbor_type_t::cbor_type_data, flags) {
    _vt.set_uint8(value).set_flag((cbor_data_flag_nint & flags) ? flag_negative : 0);
}

cbor_data::cbor_data(uint16 value, uint32 flags) : cbor_object(cbor_type_t::cbor_type_data, flags) {
    _vt.set_uint16(value).set_flag((cbor_data_flag_nint & flags) ? flag_negative : 0);
}

cbor_data::cbor_data(uint32 value, uint32 flags) : cbor_object(cbor_type_t::cbor_type_data, flags) {
    _vt.set_uint32(value).set_flag((cbor_data_flag_nint & flags) ? flag_negative : 0);
}

cbor_data::cbor_data(uint64 value, uint32 flags) : cbor_object(cbor_type_t::cbor_type_data, flags) {
    _vt.set_uint64(value).set_flag((cbor_data_flag_nint & flags) ? flag_negative : 0);
}

cbor_data::cbor_data(const bignumber& value, uint32 flags) : cbor_object(cbor_type_t::cbor_type_data, flags) { set_bn(value, flags); }

cbor_data::cbor_data(const byte_t* bstr, size_t size) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_bstr_new(bstr, size); }

cbor_data::cbor_data(const binary_t& data) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_binary_new(data); }

cbor_data::cbor_data(const char* tstr) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_str_new(tstr); }

cbor_data::cbor_data(const char* tstr, size_t length) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_strn_new(tstr, length); }

cbor_data::cbor_data(const std::string& data) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_str_new(data.c_str()); }

cbor_data::cbor_data(const fp16_t& value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_fp16(value.storage); }

cbor_data::cbor_data(float value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_float(value); }

cbor_data::cbor_data(double value) : cbor_object(cbor_type_t::cbor_type_data) { _vt.set_double(value); }

cbor_data::cbor_data(const variant_t& vt) : cbor_object(cbor_type_t::cbor_type_data), _vt(vt) {
    set_flags((vt.flag & flag_negative) ? cbor_data_flag_nint : 0);
}

cbor_data::cbor_data(variant_t&& vt) : cbor_object(cbor_type_t::cbor_type_data), _vt(std::move(vt)) {
    set_flags((vt.flag & flag_negative) ? cbor_data_flag_nint : 0);
}

cbor_data::cbor_data(const variant& other) : cbor_object(cbor_type_t::cbor_type_data), _vt(other) {
    set_flags((other.flag() & flag_negative) ? cbor_data_flag_nint : 0);
}

cbor_data::cbor_data(variant&& other) : cbor_object(cbor_type_t::cbor_type_data), _vt(std::move(other)) {
    set_flags((other.flag() & flag_negative) ? cbor_data_flag_nint : 0);
}

cbor_data::~cbor_data() {}

variant& cbor_data::data() { return _vt; }

cbor_data& cbor_data::set_bn(const bignumber& value, uint32 flags) {
    bignumber bn(value);
    int sign = 1;
    if (bn < 0) {
        // convert to unsigned
        bn += 1;
        bn.neg();
        sign = -1;
    } else if (cbor_data_flag_nint & flags) {
        // treat unsigned bignumber as negative one
        bn.neg();
        sign = -1;
    }
    if (bn.capacity() > 2) {
        // case greater than uint64
        if (sign > 0) {
            tag(cbor_tag_positive_bignum);
        } else {
            tag(cbor_tag_negative_bignum);
        }
    }

    _vt = bn;
    // bn is unsigned, set variant flags
    if (-1 == sign) {
        _vt.set_flag(flag_negative);
    }

    return *this;
}

void cbor_data::represent(stream_t* s) {
    if (s) {
        const variant_t& vt = data().content();
        if (TYPE_BIGNUMBER == vt.type) {
            vtprintf(s, vt, vtprintf_style_t::vtprintf_style_cbor);
        } else {
            if (tagged()) {
                cbor_tag_t tag = tag_value();

                switch (tag) {
                    case cbor_tag_t::cbor_tag_positive_bignum:
                    case cbor_tag_t::cbor_tag_negative_bignum: {
                        if ((TYPE_BINARY == vt.type) && (vt.size <= 16)) {
                            bignumber bn(vt.data.bstr, vt.size);
                            if (cbor_tag_t::cbor_tag_positive_bignum == tag) {
                                // do nothing
                            } else if (cbor_tag_t::cbor_tag_negative_bignum == tag) {
                                bn += 1;
                                bn.neg();
                            }

                            variant vt_bignum(bn);
                            vtprintf(s, vt_bignum, vtprintf_style_t::vtprintf_style_cbor);
                        } else {
                            vtprintf(s, vt, vtprintf_style_t::vtprintf_style_cbor);
                        }
                    } break;
                    default:
                        s->printf("%I64i(", (uint64)tag);
                        vtprintf(s, vt, vtprintf_style_t::vtprintf_style_cbor);
                        s->printf(")");
                        break;
                }

            } else {
                vtprintf(s, vt, vtprintf_style_t::vtprintf_style_cbor);
            }
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

cbor_data* cbor_data::generate(const char* value) { return new cbor_data(bignumber(value), 0); }

cbor_data* cbor_data::generate(const std::string& value) { return generate(value.c_str()); }

}  // namespace io
}  // namespace hotplace
