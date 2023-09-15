/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_json_key.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/io/basic/base64.hpp>
#include <hotplace/sdk/io/basic/json.hpp>
#include <fstream>

namespace hotplace {
using namespace io;
namespace crypto {

crypto_json_key::crypto_json_key ()
{
    // do nothing
}

crypto_json_key::~crypto_json_key ()
{
    // do nothing
}

return_t crypto_json_key::load (crypto_key* crypto_key, const char* buffer, int flags)
{
    return_t ret = errorcode_t::success;

    return ret;
}

return_t crypto_json_key::write (crypto_key* crypto_key, char* buf, size_t* buflen, int flags)
{
    return_t ret = errorcode_t::success;

    return ret;
}

return_t crypto_json_key::add_rsa (crypto_key* crypto_key, const char* kid, const char* alg,
                                   const char* n_value, const char* e_value, const char* d_value,
                                   const char* p_value, const char* q_value,
                                   const char* dp_value, const char* dq_value, const char* qi_value,
                                   crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == n_value || nullptr == e_value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string n_decoded;
        std::string e_decoded;
        std::string d_decoded;

        n_decoded = base64_decode_careful (n_value, strlen (n_value), base64_encoding_t::base64url_encoding);
        e_decoded = base64_decode_careful (e_value, strlen (e_value), base64_encoding_t::base64url_encoding);
        if (nullptr != d_value) {
            d_decoded = base64_decode_careful (d_value, strlen (d_value), base64_encoding_t::base64url_encoding);
        }

        std::string p_decoded;
        std::string q_decoded;
        std::string dp_decoded;
        std::string dq_decoded;
        std::string qi_decoded;

        if (p_value && q_value && dp_value && dq_value && qi_value) {
            p_decoded = base64_decode_careful (p_value, strlen (p_value), base64_encoding_t::base64url_encoding);
            q_decoded = base64_decode_careful (q_value, strlen (q_value), base64_encoding_t::base64url_encoding);
            dp_decoded = base64_decode_careful (dp_value, strlen (dp_value), base64_encoding_t::base64url_encoding);
            dq_decoded = base64_decode_careful (dq_value, strlen (dq_value), base64_encoding_t::base64url_encoding);
            qi_decoded = base64_decode_careful (qi_value, strlen (qi_value), base64_encoding_t::base64url_encoding);
        }

        binary_t n;
        binary_t e;
        binary_t d;
        n.insert (n.end (), n_decoded.begin (), n_decoded.end ());
        e.insert (e.end (), e_decoded.begin (), e_decoded.end ());
        d.insert (d.end (), d_decoded.begin (), d_decoded.end ());

        crypto_keychain keyset;
        if (p_value && q_value && dp_value && dq_value && qi_value) {
            binary_t p;
            binary_t q;
            binary_t dp;
            binary_t dq;
            binary_t qi;
            p.insert (p.end (), p_decoded.begin (), p_decoded.end ());
            q.insert (q.end (), q_decoded.begin (), q_decoded.end ());
            dp.insert (dp.end (), dp_decoded.begin (), dp_decoded.end ());
            dq.insert (dq.end (), dq_decoded.begin (), dq_decoded.end ());
            qi.insert (qi.end (), qi_decoded.begin (), qi_decoded.end ());
            keyset.add_rsa (crypto_key, kid, alg, n, e, d, p, q, dp, dq, qi, use);
        } else {
            keyset.add_rsa (crypto_key, kid, alg, n, e, d, use);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::add_ec (crypto_key* crypto_key, const char* kid, const char* alg, const char* curve,
                                  const char* x_value, const char* y_value, const char* d_value, crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        if (nullptr == crypto_key || nullptr == curve || nullptr == x_value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string x_decoded;
        std::string y_decoded;
        std::string d_decoded;
        uint32 nid = 0;
        ret = advisor->nidof_ec_curve (curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        x_decoded = base64_decode_careful (x_value, strlen (x_value), base64_encoding_t::base64url_encoding);
        if (y_value) {
            /* kty EC */
            y_decoded = base64_decode_careful (y_value, strlen (y_value), base64_encoding_t::base64url_encoding);
        }
        if (d_value) {
            /* private key */
            d_decoded = base64_decode_careful (d_value, strlen (d_value), base64_encoding_t::base64url_encoding);
        }

        binary_t x;
        binary_t y;
        binary_t d;
        x.insert (x.end (), x_decoded.begin (), x_decoded.end ());
        y.insert (y.end (), y_decoded.begin (), y_decoded.end ());
        d.insert (d.end (), d_decoded.begin (), d_decoded.end ());

        crypto_keychain keyset;
        keyset.add_ec (crypto_key, kid, alg, nid, x, y, d, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::add_oct (crypto_key* crypto_key, const char* kid, const char* alg, const char* k_value, crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == k_value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string k_decoded = base64_decode_careful (k_value, strlen (k_value), base64_encoding_t::base64url_encoding);

        binary_t k;
        k.insert (k.end (), k_decoded.begin (), k_decoded.end ());

        crypto_keychain keyset;
        keyset.add_oct (crypto_key, kid, alg, k, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::load_file (crypto_key* crypto_key, const char* file, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string buffer;
        std::ifstream fs (file);
        if (fs.is_open ()) {
            std::getline (fs, buffer, (char) fs.eof ());

            ret = load (crypto_key, buffer.c_str (), flags);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::load_pem (crypto_key* cryptokey, const char* buffer, int flags, crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = cryptokey->load_pem (buffer, flags, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::load_pem_file (crypto_key* cryptokey, const char* file, int flags, crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = cryptokey->load_pem_file (file, flags, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::write_pem_file (crypto_key* cryptokey, const char* file, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = cryptokey->write_pem_file (file, flags);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}  // namespace
