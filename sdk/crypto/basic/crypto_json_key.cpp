/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/base64.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_json_key.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
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

return_t crypto_json_key::add_rsa_b64u (crypto_key* crypto_key, const char* kid, const char* alg,
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

        binary_t n_decoded;
        binary_t e_decoded;
        binary_t d_decoded;

        n_decoded = base64_decode (n_value, strlen (n_value), base64_encoding_t::base64url_encoding);
        e_decoded = base64_decode (e_value, strlen (e_value), base64_encoding_t::base64url_encoding);
        if (nullptr != d_value) {
            d_decoded = base64_decode (d_value, strlen (d_value), base64_encoding_t::base64url_encoding);
        }

        binary_t p_decoded;
        binary_t q_decoded;
        binary_t dp_decoded;
        binary_t dq_decoded;
        binary_t qi_decoded;

        if (p_value && q_value && dp_value && dq_value && qi_value) {
            p_decoded = base64_decode (p_value, strlen (p_value), base64_encoding_t::base64url_encoding);
            q_decoded = base64_decode (q_value, strlen (q_value), base64_encoding_t::base64url_encoding);
            dp_decoded = base64_decode (dp_value, strlen (dp_value), base64_encoding_t::base64url_encoding);
            dq_decoded = base64_decode (dq_value, strlen (dq_value), base64_encoding_t::base64url_encoding);
            qi_decoded = base64_decode (qi_value, strlen (qi_value), base64_encoding_t::base64url_encoding);
        }

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;
        bin_n.insert (bin_n.end (), n_decoded.begin (), n_decoded.end ());
        bin_e.insert (bin_e.end (), e_decoded.begin (), e_decoded.end ());
        bin_d.insert (bin_d.end (), d_decoded.begin (), d_decoded.end ());

        crypto_keychain keyset;
        if (p_value && q_value && dp_value && dq_value && qi_value) {
            binary_t bin_p;
            binary_t bin_q;
            binary_t bin_dp;
            binary_t bin_dq;
            binary_t bin_qi;
            bin_p.insert (bin_p.end (), p_decoded.begin (), p_decoded.end ());
            bin_q.insert (bin_q.end (), q_decoded.begin (), q_decoded.end ());
            bin_dp.insert (bin_dp.end (), dp_decoded.begin (), dp_decoded.end ());
            bin_dq.insert (bin_dq.end (), dq_decoded.begin (), dq_decoded.end ());
            bin_qi.insert (bin_qi.end (), qi_decoded.begin (), qi_decoded.end ());
            keyset.add_rsa (crypto_key, kid, alg, bin_n, bin_e, bin_d, bin_p, bin_q, bin_dp, bin_dq, bin_qi, use);
        } else {
            keyset.add_rsa (crypto_key, kid, alg, bin_n, bin_e, bin_d, use);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::add_rsa (crypto_key* crypto_key, const char* kid, const char* alg, const byte_t* n, size_t size_n, const byte_t* e, size_t size_e, const byte_t* d, size_t size_d, crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == n || nullptr == e) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;

        bin_n.insert (bin_n.end (), n, n + size_n);
        bin_e.insert (bin_e.end (), e, e + size_e);
        if (d) {
            bin_d.insert (bin_d.end (), d, d + size_d);
        }

        ret = add_rsa (crypto_key, kid, alg, bin_n, bin_e, bin_d, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::add_rsa (crypto_key* crypto_key, const char* kid, const char* alg,
                                   binary_t const& n, binary_t const& e, binary_t const& d, crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    crypto_keychain keyset;

    ret = keyset.add_rsa (crypto_key, kid, alg, n, e, d, use);
    return ret;
}

return_t crypto_json_key::add_ec_b64u (crypto_key* crypto_key, const char* kid, const char* alg, const char* curve,
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

        binary_t x_decoded;
        binary_t y_decoded;
        binary_t d_decoded;
        uint32 nid = 0;
        ret = advisor->nidof_ec_curve (curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        x_decoded = base64_decode (x_value, strlen (x_value), base64_encoding_t::base64url_encoding);
        if (y_value) {
            /* kty EC */
            y_decoded = base64_decode (y_value, strlen (y_value), base64_encoding_t::base64url_encoding);
        }
        if (d_value) {
            /* private key */
            d_decoded = base64_decode (d_value, strlen (d_value), base64_encoding_t::base64url_encoding);
        }

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;
        bin_x.insert (bin_x.end (), x_decoded.begin (), x_decoded.end ());
        bin_y.insert (bin_y.end (), y_decoded.begin (), y_decoded.end ());
        bin_d.insert (bin_d.end (), d_decoded.begin (), d_decoded.end ());

        crypto_keychain keyset;
        ret = keyset.add_ec (crypto_key, kid, alg, nid, bin_x, bin_y, bin_d, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::add_ec (crypto_key* crypto_key, const char* kid, const char* alg, const char* curve,
                                  const byte_t* x, size_t size_x, const byte_t* y, size_t size_y, const byte_t* d, size_t size_d, crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        bin_x.insert (bin_x.end (), x, x + size_x);
        if (y) {
            bin_y.insert (bin_y.end (), y, y + size_y);
        }
        if (d) {
            bin_d.insert (bin_d.end (), d, d + size_d);
        }

        ret = add_ec (crypto_key, kid, alg, curve, bin_x, bin_y, bin_d, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::add_ec (crypto_key* crypto_key, const char* kid, const char* alg, const char* curve,
                                  binary_t const& x, binary_t const& y, binary_t const& d, crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance ();
        uint32 nid = 0;
        ret = advisor->nidof_ec_curve (curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        crypto_keychain keyset;
        keyset.add_ec (crypto_key, kid, alg, nid, x, y, d, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::add_ec (crypto_key* crypto_key, const char* kid, const char* alg, uint32 nid,
                                  binary_t const& x, binary_t const& y, binary_t const& d, crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_keychain keyset;
        keyset.add_ec (crypto_key, kid, alg, nid, x, y, d, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::add_oct_b64u (crypto_key* crypto_key, const char* kid, const char* alg, const char* k_value, crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == k_value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t k_decoded = base64_decode (k_value, strlen (k_value), base64_encoding_t::base64url_encoding);

        binary_t bin_k;
        bin_k.insert (bin_k.end (), k_decoded.begin (), k_decoded.end ());

        crypto_keychain keyset;
        keyset.add_oct (crypto_key, kid, alg, bin_k, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::add_oct (crypto_key* crypto_key, const char* kid, const char* alg, const byte_t* k, size_t size_k,
                                   crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_k;
        bin_k.insert (bin_k.end (), k, k + size_k);

        crypto_keychain keyset;
        keyset.add_oct (crypto_key, kid, alg, bin_k, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t crypto_json_key::add_oct (crypto_key* crypto_key, const char* kid, const char* alg, binary_t const& k,
                                   crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    crypto_keychain keyset;

    keyset.add_oct (crypto_key, kid, alg, k, use);
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
