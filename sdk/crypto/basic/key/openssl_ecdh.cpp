/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_ecdh.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_ecdh.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#if defined __linux__
#include <arpa/inet.h>
#endif

namespace hotplace {
namespace crypto {

const EVP_PKEY* get_public_key(const EVP_PKEY* pkey) {
    const EVP_PKEY* peer = nullptr;

    __try2 {
        if (nullptr == pkey) {
            __leave2;
        }

        int len = i2d_PUBKEY((EVP_PKEY*)pkey, nullptr);
        byte_t* buf = (unsigned char*)OPENSSL_malloc(len);
        if (buf) {
            byte_t* p = buf;
            len = i2d_PUBKEY((EVP_PKEY*)pkey, &p);

            const byte_t* p2 = buf;
            peer = d2i_PUBKEY(nullptr, &p2, len);

            OPENSSL_free(buf);
        }
    }
    __finally2 {}

    return peer;
}

return_t dh_key_agreement(const EVP_PKEY* pkey, const EVP_PKEY* pkey_pub, binary_t& secret) {
    secret.clear();

    EVP_PKEY_CTX_ptr pkey_context;
    size_t size_secret = 0;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey && nullptr != pkey_pub); })
        .run_pipe([&]() -> int {
            bool is_private = false;
            auto rc = is_private_key(pkey, is_private);
            return (success == rc || is_private) ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            pkey_context = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new((EVP_PKEY*)pkey, nullptr)));
            return pkey_context.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_derive_init(pkey_context.get()); })
        .run_pipe([&]() -> int { return EVP_PKEY_derive_set_peer(pkey_context.get(), (EVP_PKEY*)pkey_pub); })
        .run_pipe([&]() -> int { return EVP_PKEY_derive(pkey_context.get(), nullptr, &size_secret); })
        .run_pipe([&]() -> int {
            secret.resize(size_secret);
            return EVP_PKEY_derive(pkey_context.get(), secret.data(), &size_secret);
        });
    return pipeline.result_to_return_t();
}

binary_t kdf_parameter_int(uint32 source) {
    binary_t value;
    uint32 be_source = hton32(source);
    value.insert(value.end(), (byte_t*)&be_source, (byte_t*)&be_source + sizeof(be_source));
    return value;
}

binary_t kdf_parameter_string(const char* source) {
    binary_t value;
    size_t len = 0;
    if (source) {
        len = strlen(source);
    }
    value.reserve(sizeof(uint32) + len);
    uint32 be_len = hton32(t_narrow_cast(len));
    value.insert(value.end(), (byte_t*)&be_len, (byte_t*)&be_len + sizeof(be_len));
    if (len) {
        value.insert(value.end(), (byte_t*)source, (byte_t*)source + len);
    }
    return value;
}

binary_t kdf_parameter_string(const byte_t* source, uint32 sourcelen) {
    binary_t value;
    uint32 be_len = hton32(sourcelen);
    value.reserve(sizeof(uint32) + sourcelen);
    value.insert(value.end(), (byte_t*)&be_len, (byte_t*)&be_len + sizeof(be_len));
    if (sourcelen) {
        value.insert(value.end(), source, source + sourcelen);
    }
    return value;
}

return_t ecdh_es(const EVP_PKEY* pkey, const EVP_PKEY* peer, const char* algid, const char* apu, const char* apv, uint32 keylen, binary_t& derived) {
    derived.clear();

    binary_t dh_secret;
    binary_t otherinfo;

    function_pipeline<return_t> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey && nullptr != peer); })
        .run_pipe([&]() -> return_t { return dh_key_agreement(pkey, peer, dh_secret); })
        .run_pipe([&]() -> return_t { return compose_otherinfo(algid, apu, apv, keylen << 3, otherinfo); })
        .run_pipe([&]() -> return_t { return concat_kdf(dh_secret, otherinfo, keylen, derived); });

    return pipeline.result();
}

return_t compose_otherinfo(const char* algid, const char* apu, const char* apv, uint32 keybits, binary_t& otherinfo) {
    return_t ret = errorcode_t::success;

    otherinfo.clear();
    otherinfo << kdf_parameter_string(algid) << kdf_parameter_string(apu) << kdf_parameter_string(apv) << kdf_parameter_int(keybits);
    return ret;
}

return_t concat_kdf(binary_t dh_secret, binary_t otherinfo, unsigned int keylen, binary_t& derived) {
    return_t ret = errorcode_t::success;

    __try2 {
        derived.resize(keylen);

        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_create());
        if (nullptr == ctx.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        const EVP_MD* dgst = EVP_sha256();
        const size_t hashlen = EVP_MD_size(dgst);
        const size_t N = (keylen + hashlen - 1) / hashlen;
        size_t offset = 0;
        size_t amt = keylen;

        for (uint32 idx = 1; N >= idx; idx++) {
            binary_t counter = kdf_parameter_int(idx);
            binary_t hash;
            hash.resize(hashlen);

            unsigned int alloca_size = t_narrow_cast(hashlen);
            function_pipeline<int> pipeline;
            pipeline  //
                .set_tracer(pipeline_trace_dbg_openssl_print)
                .run_pipe([&]() -> int { return EVP_DigestInit_ex(ctx.get(), dgst, nullptr); })
                .run_pipe([&]() -> int { return EVP_DigestUpdate(ctx.get(), counter.data(), counter.size()); })
                .run_pipe([&]() -> int { return EVP_DigestUpdate(ctx.get(), dh_secret.data(), dh_secret.size()); })
                .run_pipe([&]() -> int { return EVP_DigestUpdate(ctx.get(), otherinfo.data(), otherinfo.size()); })
                .run_pipe([&]() -> int { return EVP_DigestFinal_ex(ctx.get(), hash.data(), &alloca_size); });
            if (pipeline.failed()) {
                ret = pipeline.result_to_return_t();
                break;
            }

            memcpy(&derived[offset], hash.data(), std::min(hashlen, amt));
            offset += hashlen;
            amt -= hashlen;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
