/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/types.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>

#if defined __linux__
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace hotplace {
namespace crypto {

constexpr char constexpr_tls13[] = "tls13 ";
constexpr char constexpr_dtls13[] = "dtls13";

return_t openssl_kdf::hkdf_tls13_label(binary_t& hkdflabel, uint16 length, const char* label, const binary_t& context) {
    return_t ret = errorcode_t::success;
    __try2 {
        hkdflabel.clear();

        if (nullptr == label || context.size() > 255) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        size_t len = strlen(label);
        if (255 < len) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = hkdf_label(hkdflabel, length, str2bin(constexpr_tls13), str2bin(label), context);
    }
    __finally2 {}
    return ret;
}

return_t openssl_kdf::hkdf_dtls13_label(binary_t& hkdflabel, uint16 length, const char* label, const binary_t& context) {
    return_t ret = errorcode_t::success;
    __try2 {
        hkdflabel.clear();

        if (nullptr == label || context.size() > 255) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        size_t len = strlen(label);
        if (255 < len) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = hkdf_label(hkdflabel, length, str2bin(constexpr_dtls13), str2bin(label), context);
    }
    __finally2 {}
    return ret;
}

return_t openssl_kdf::hkdf_expand_tls13_label(binary_t& okm, const char* alg, uint16 length, const binary_t& secret, const char* label,
                                              const binary_t& context) {
    return hkdf_expand_label(okm, alg, length, secret, constexpr_tls13, label, context);
}

return_t openssl_kdf::hkdf_expand_tls13_label(binary_t& okm, hash_algorithm_t alg, uint16 length, const binary_t& secret, const char* label,
                                              const binary_t& context) {
    return hkdf_expand_label(okm, alg, length, secret, constexpr_tls13, label, context);
}

return_t openssl_kdf::hkdf_expand_tls13_label(binary_t& okm, const char* alg, uint16 length, const binary_t& secret, const binary_t& label,
                                              const binary_t& context) {
    return hkdf_expand_label(okm, alg, length, secret, str2bin(constexpr_tls13), label, context);
}

return_t openssl_kdf::hkdf_expand_tls13_label(binary_t& okm, hash_algorithm_t alg, uint16 length, const binary_t& secret, const binary_t& label,
                                              const binary_t& context) {
    return hkdf_expand_label(okm, alg, length, secret, str2bin(constexpr_tls13), label, context);
}

return_t openssl_kdf::hkdf_expand_dtls13_label(binary_t& okm, const char* alg, uint16 length, const binary_t& secret, const char* label,
                                               const binary_t& context) {
    return hkdf_expand_label(okm, alg, length, secret, constexpr_dtls13, label, context);
}

return_t openssl_kdf::hkdf_expand_dtls13_label(binary_t& okm, hash_algorithm_t alg, uint16 length, const binary_t& secret, const char* label,
                                               const binary_t& context) {
    return hkdf_expand_label(okm, alg, length, secret, constexpr_dtls13, label, context);
}

return_t openssl_kdf::hkdf_expand_dtls13_label(binary_t& okm, const char* alg, uint16 length, const binary_t& secret, const binary_t& label,
                                               const binary_t& context) {
    return hkdf_expand_label(okm, alg, length, secret, str2bin(constexpr_dtls13), label, context);
}

return_t openssl_kdf::hkdf_expand_dtls13_label(binary_t& okm, hash_algorithm_t alg, uint16 length, const binary_t& secret, const binary_t& label,
                                               const binary_t& context) {
    return hkdf_expand_label(okm, alg, length, secret, str2bin(constexpr_dtls13), label, context);
}

return_t openssl_kdf::hkdf_label(binary_t& hkdflabel, uint16 length, const binary_t& prefix, const binary_t& label, const binary_t& context) {
    return_t ret = errorcode_t::success;
    __try2 {
        hkdflabel.clear();

        if ((label.size() > 255) || (context.size() > 255)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        /**
         * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
         *  7.  Cryptographic Computations
         *   HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
         *
         * RFC 9001 Using TLS to Secure QUIC
         *  Appendix A.  Sample Packet Protection
         */

        uint8 opaque_len_label = prefix.size() + label.size();  // length including "tls13 " or "dtls13"
        uint8 opaque_len_context = context.size();
#if 0  // tested
        payload pl;
        pl << new payload_member(length, true) //
           << new payload_member(opaque_len_label) //
           << new payload_member(prefix) //
           << new payload_member(label) //
           << new payload_member(opaque_len_context) //
           << new payload_member(context);
        pl.write(hkdflabel);
#else
        binary_append(hkdflabel, length, hton16);
        binary_append(hkdflabel, opaque_len_label);
        binary_append(hkdflabel, prefix);
        binary_append(hkdflabel, label);
        binary_append(hkdflabel, opaque_len_context);
        binary_append(hkdflabel, context);
#endif
    }
    __finally2 {}
    return ret;
}

return_t openssl_kdf::hkdf_expand_label(binary_t& okm, const char* alg, uint16 length, const binary_t& secret, const char* prefix, const char* label,
                                        const binary_t& context) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == alg || nullptr == prefix || nullptr == label) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = hkdf_expand_label(okm, alg, length, secret, str2bin(prefix), str2bin(label), context);
    }
    __finally2 {}
    return ret;
}

return_t openssl_kdf::hkdf_expand_label(binary_t& okm, hash_algorithm_t alg, uint16 length, const binary_t& secret, const char* prefix, const char* label,
                                        const binary_t& context) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == prefix || nullptr == label) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = hkdf_expand_label(okm, alg, length, secret, str2bin(prefix), str2bin(label), context);
    }
    __finally2 {}
    return ret;
}

return_t openssl_kdf::hkdf_expand_label(binary_t& okm, const char* alg, uint16 length, const binary_t& secret, const binary_t& prefix, const binary_t& label,
                                        const binary_t& context) {
    return_t ret = errorcode_t::success;
    __try2 {
        okm.clear();

        if (nullptr == alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (context.size() > 255) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_hkdflabel;
        ret = hkdf_label(bin_hkdflabel, length, prefix, label, context);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        /**
         * RFC 5869
         * HKDF-Expand(PRK, info, L) -> OKM
         */
        openssl_kdf kdf;
        ret = kdf.hkdf_expand(okm, alg, length, secret, bin_hkdflabel);
    }
    __finally2 {}
    return ret;
}

return_t openssl_kdf::hkdf_expand_label(binary_t& okm, hash_algorithm_t alg, uint16 length, const binary_t& secret, const binary_t& prefix,
                                        const binary_t& label, const binary_t& context) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    return hkdf_expand_label(okm, advisor->nameof_md(alg), length, secret, prefix, label, context);
}

}  // namespace crypto
}  // namespace hotplace
