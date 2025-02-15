/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      RFC 3279 2.2.2  DSA Signature Algorithm
 *        Dss-Sig-Value  ::=  SEQUENCE  {
 *                r       INTEGER,
 *                s       INTEGER  }
 *      RFC 3279 2.2.3 ECDSA Signature Algorithm
 *        Ecdsa-Sig-Value  ::=  SEQUENCE  {
 *             r     INTEGER,
 *             s     INTEGER  }
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/crypto/crypto_sign.hpp>
#include <sdk/io/asn.1/types.hpp>
#include <sdk/io/basic/payload.hpp>

namespace hotplace {
namespace crypto {

return_t rs2der(const binary_t& r, const binary_t& s, binary_t& asn1der) {
    return_t ret = errorcode_t::success;

    asn1der.clear();

    // ASN.1 DER
    // ASN.1 DER (30 || length || 02 || r_length || r || 02 || s_length || s)
    payload pl;
    pl << new payload_member(uint8(30)) << new payload_member(uint8(r.size() + s.size() + 4)) << new payload_member(uint8(asn1_tag_integer))
       << new payload_member(uint8(r.size())) << new payload_member(r) << new payload_member(uint8(asn1_tag_integer)) << new payload_member(uint8(s.size()))
       << new payload_member(s);
    pl.write(asn1der);
    return ret;
}

return_t der2rs(const binary_t& asn1der, uint16 unitsize, binary_t& r, binary_t& s) {
    return_t ret = errorcode_t::success;
    __try2 {
        // ASN.1 DER
        constexpr char constexpr_sequence[] = "sequence";
        constexpr char constexpr_len[] = "len";
        constexpr char constexpr_rlen[] = "rlen";
        constexpr char constexpr_r[] = "r";
        constexpr char constexpr_slen[] = "slen";
        constexpr char constexpr_s[] = "s";

        payload pl;
        pl << new payload_member(uint8(0), constexpr_sequence) << new payload_member(uint8(0), constexpr_len) << new payload_member(uint8(0))
           << new payload_member(uint8(0), constexpr_rlen) << new payload_member(binary_t(), constexpr_r) << new payload_member(uint8(0))
           << new payload_member(uint8(0), constexpr_slen) << new payload_member(binary_t(), constexpr_s);

        pl.set_reference_value(constexpr_r, constexpr_rlen);
        pl.set_reference_value(constexpr_s, constexpr_slen);

        pl.read(&asn1der[0], asn1der.size());

        uint8 sequence = pl.t_value_of<uint8>(constexpr_sequence);
        if (0x30 != sequence) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        uint8 rlen = pl.t_value_of<uint8>(constexpr_rlen);
        uint8 slen = pl.t_value_of<uint8>(constexpr_slen);
        pl.get_binary(constexpr_r, r);
        pl.get_binary(constexpr_s, s);
    }
    __finally2 {}
    return ret;
}

return_t sig2rs(const binary_t& sig, binary_t& r, binary_t& s) {
    return_t ret = errorcode_t::success;
    __try2 {
        size_t size = sig.size();
        if (size % 2) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        size_t halfsize = size << 1;
        r = binary_t(sig.begin(), sig.begin() + halfsize - 1);
        s = binary_t(sig.begin() + halfsize, sig.end());
    }
    __finally2 {}
    return ret;
}

return_t rs2sig(const binary_t& r, const binary_t& s, uint16 unitsize, binary_t& signature) {
    return_t ret = errorcode_t::success;
    __try2 {
        signature.clear();

        size_t rlen = r.size();
        size_t slen = s.size();
        uint16 r_ltrim = 0;
        uint16 r_lpad = 0;
        uint16 s_ltrim = 0;
        uint16 s_lpad = 0;

        // ASN.1 DER preceding zero
        if (rlen > unitsize) {
            r_ltrim = rlen - unitsize;
        } else if (rlen < unitsize) {
            r_lpad = unitsize - rlen;
        }
        if (slen > unitsize) {
            s_ltrim = slen - unitsize;
        } else if (slen < unitsize) {
            s_lpad = unitsize - slen;
        }

        if (r_ltrim) {
            binary_append(signature, &r[0] + r_ltrim, unitsize);
        } else if (r_lpad) {
            while (r_lpad--) {
                binary_append(signature, uint8(0));
            }
            binary_append(signature, r);
        } else {
            binary_append(signature, r);
        }

        if (s_ltrim) {
            binary_append(signature, &s[0] + s_ltrim, unitsize);
        } else if (s_lpad) {
            while (s_lpad--) {
                binary_append(signature, uint8(0));
            }
            binary_append(signature, s);
        } else {
            binary_append(signature, s);
        }
    }
    __finally2 {}
    return ret;
}

return_t der2sig(const binary_t& asn1der, uint16 unitsize, binary_t& signature) {
    return_t ret = errorcode_t::success;
    __try2 {
        binary_t bin_r;
        binary_t bin_s;
        ret = der2rs(asn1der, unitsize, bin_r, bin_s);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = rs2sig(bin_r, bin_s, unitsize, signature);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t sig2der(const binary_t& signature, binary_t& asn1der) {
    return_t ret = errorcode_t::success;
    __try2 {
        binary_t bin_r;
        binary_t bin_s;

        ret = sig2rs(signature, bin_r, bin_s);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = rs2der(bin_r, bin_s, asn1der);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
