/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/openssl_ecdh.hpp>
#if defined __linux__
#include <arpa/inet.h>
#endif

namespace hotplace {
namespace crypto {

EVP_PKEY* get_peer_key (EVP_PKEY* pkey)
{
    EVP_PKEY* peer = nullptr;

    __try2
    {
        if (nullptr == pkey) {
            __leave2;
        }

        int len = i2d_PUBKEY ((EVP_PKEY*) pkey, nullptr);
        byte_t* buf = (unsigned char*) OPENSSL_malloc (len);
        if (buf) {
            byte_t* p = buf;
            len = i2d_PUBKEY ((EVP_PKEY*) pkey, &p);

            const byte_t* p2 = buf;
            peer = d2i_PUBKEY (nullptr, &p2, len);

            OPENSSL_free (buf);
        }
    }
    __finally2
    {
        // do nothing
    }

    return (EVP_PKEY*) peer;
}

return_t dh_key_agreement (EVP_PKEY* pkey, EVP_PKEY* peer, binary_t& secret)
{
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX* pkey_context = nullptr;
    int ret_test = 0;

    __try2
    {
        secret.clear ();

        if (nullptr == pkey || nullptr == peer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey_context = EVP_PKEY_CTX_new ((EVP_PKEY*) pkey, nullptr);
        if (nullptr == pkey_context) {
            ret = errorcode_t::internal_error;
            __leave2_trace (ret);
        }

        size_t size_secret = 0;
        EVP_PKEY* pkey_peer = (EVP_PKEY*) get_peer_key (peer);
        if (pkey_peer) {
            __try2
            {
                ret_test = EVP_PKEY_derive_init (pkey_context);
                if (1 > ret_test) {
                    ret = errorcode_t::internal_error;
                    __leave2_trace (ret);
                }
                ret_test = EVP_PKEY_derive_set_peer (pkey_context, pkey_peer);
                if (1 > ret_test) {
                    ret = errorcode_t::internal_error;
                    __leave2_trace (ret);
                }
                ret_test = EVP_PKEY_derive (pkey_context, nullptr, &size_secret);
                if (1 > ret_test) {
                    ret = errorcode_t::internal_error;
                    __leave2_trace (ret);
                }
                secret.resize (size_secret);
                ret_test = EVP_PKEY_derive (pkey_context, &secret[0], &size_secret);
                if (1 > ret_test) {
                    ret = errorcode_t::internal_error;
                    __leave2_trace (ret);
                }
            }
            __finally2
            {
                EVP_PKEY_free (pkey_peer);
            }
        } else {
            ret = errorcode_t::internal_error;
            __leave2_trace (ret);
        }
    }
    __finally2
    {
        if (nullptr != pkey_context) {
            EVP_PKEY_CTX_free (pkey_context);
        }
        // do nothing
    }
    return ret;
}

binary_t kdf_parameter_int (uint32 source)
{
    binary_t value;
    uint32 be_source = htonl (source);

    value.insert (value.end (), (byte_t*) &be_source, (byte_t*) &be_source + sizeof (be_source));
    return value;
}

binary_t kdf_parameter_string (const char* source)
{
    binary_t value;
    uint32 len = 0;

    if (source) {
        len = strlen (source);
    }
    uint32 be_len = htonl (len);

    value.insert (value.end (), (byte_t*) &be_len, (byte_t*) &be_len + sizeof (be_len));
    value.insert (value.end (), (byte_t*) source, (byte_t*) source + len);
    return value;
}

binary_t kdf_parameter_string (const byte_t* source, uint32 sourcelen)
{
    binary_t value;
    uint32 be_len = htonl (sourcelen);

    value.insert (value.end (), (byte_t*) &be_len, (byte_t*) &be_len + sizeof (be_len));
    value.insert (value.end (), source, source + sourcelen);
    return value;
}

return_t ecdh_es (EVP_PKEY* pkey, EVP_PKEY* peer,
                  const char* algid, const char* apu, const char* apv, uint32 keylen,
                  binary_t& derived)
{
    return_t ret = errorcode_t::success;
    binary_t dh_secret;
    binary_t otherinfo;

    __try2
    {
        derived.clear ();

        ret = dh_key_agreement (pkey, peer, dh_secret);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }
        ret = compose_otherinfo (algid, apu, apv, keylen << 3, otherinfo);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }
        ret = concat_kdf (dh_secret, otherinfo, keylen, derived);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t compose_otherinfo (const char* algid, const char* apu, const char* apv, uint32 keybits,
                            binary_t& otherinfo)
{
    return_t ret = errorcode_t::success;

    otherinfo.clear ();
    otherinfo   << kdf_parameter_string (algid)
                << kdf_parameter_string (apu)
                << kdf_parameter_string (apv)
                << kdf_parameter_int (keybits);
    return ret;
}

return_t concat_kdf (binary_t dh_secret, binary_t otherinfo, unsigned int keylen, binary_t& derived)
{
    return_t ret = errorcode_t::success;
    EVP_MD_CTX *ctx = nullptr;

    __try2
    {
        derived.resize (keylen);

        ctx = EVP_MD_CTX_create ();
        if (errorcode_t::success != ret) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        const EVP_MD *dgst = EVP_sha256 ();
        const size_t hashlen = EVP_MD_size (dgst);
        const size_t N = (keylen + hashlen - 1) / hashlen;
        size_t offset = 0;
        size_t amt = keylen;

        for (uint32 idx = 1; N >= idx; idx++) {
            binary_t counter = kdf_parameter_int (idx);
            binary_t hash;
            hash.resize (hashlen);

            unsigned int alloca_size = hashlen;
            if (1 != EVP_DigestInit_ex (ctx, dgst, nullptr) ||
                1 != EVP_DigestUpdate (ctx, &counter[0], counter.size ()) ||
                1 != EVP_DigestUpdate (ctx, &dh_secret[0], dh_secret.size ()) ||
                1 != EVP_DigestUpdate (ctx, &otherinfo[0], otherinfo.size ()) ||
                1 != EVP_DigestFinal_ex (ctx, &hash[0], &alloca_size)) {
                ret = errorcode_t::internal_error;
                break;
            }

            memcpy (&derived[offset], &hash[0], std::min (hashlen, amt));
            offset += hashlen;
            amt -= hashlen;
        }
    }
    __finally2
    {
        if (ctx) {
            EVP_MD_CTX_destroy (ctx);
        }
    }
    return ret;
}

}
}  // namespace
