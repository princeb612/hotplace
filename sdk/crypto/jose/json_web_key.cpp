/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/jose/json_web_key.hpp>
#include <hotplace/sdk/io/encoder/base64.hpp>
#include <jansson.h>
#include <fstream>

namespace hotplace {
using namespace io;
namespace crypto {

json_web_key::json_web_key ()
{
    // do nothing
}

json_web_key::~json_web_key ()
{
    // do nothing
}

return_t json_web_key::add_rsa (crypto_key* crypto_key, const char* kid, const char* alg,
                                const char* n_value, const char* e_value, const char* d_value,
                                const char* p_value, const char* q_value,
                                const char* dp_value, const char* dq_value, const char* qi_value,
                                CRYPTO_USE_FLAG use)
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

        n_decoded = base64_decode_becareful (n_value, strlen (n_value), BASE64URL_ENCODING);
        e_decoded = base64_decode_becareful (e_value, strlen (e_value), BASE64URL_ENCODING);
        if (nullptr != d_value) {
            d_decoded = base64_decode_becareful (d_value, strlen (d_value), BASE64URL_ENCODING);
        }

        std::string p_decoded;
        std::string q_decoded;
        std::string dp_decoded;
        std::string dq_decoded;
        std::string qi_decoded;

        if (p_value && q_value && dp_value && dq_value && qi_value) {
            p_decoded = base64_decode_becareful (p_value, strlen (p_value), BASE64URL_ENCODING);
            q_decoded = base64_decode_becareful (q_value, strlen (q_value), BASE64URL_ENCODING);
            dp_decoded = base64_decode_becareful (dp_value, strlen (dp_value), BASE64URL_ENCODING);
            dq_decoded = base64_decode_becareful (dq_value, strlen (dq_value), BASE64URL_ENCODING);
            qi_decoded = base64_decode_becareful (qi_value, strlen (qi_value), BASE64URL_ENCODING);
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

return_t json_web_key::add_ec (crypto_key* crypto_key, const char* kid, const char* alg, const char* curve,
                               const char* x_value, const char* y_value, const char* d_value, CRYPTO_USE_FLAG use)
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
            __leave2_trace (ret);
        }

        x_decoded = base64_decode_becareful (x_value, strlen (x_value), BASE64URL_ENCODING);
        if (y_value) {
            /* kty EC */
            y_decoded = base64_decode_becareful (y_value, strlen (y_value), BASE64URL_ENCODING);
        }
        if (d_value) {
            /* private key */
            d_decoded = base64_decode_becareful (d_value, strlen (d_value), BASE64URL_ENCODING);
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

return_t json_web_key::add_oct (crypto_key* crypto_key, const char* kid, const char* alg, const char* k_value, CRYPTO_USE_FLAG use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == k_value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string k_decoded = base64_decode_becareful (k_value, strlen (k_value), BASE64URL_ENCODING);

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

return_t json_web_key::read_json_item (crypto_key* crypto_key, void* json)
{
    return_t ret = errorcode_t::success;
    json_t* temp = (json_t*) json;
    crypto_keychain keyset;

    __try2
    {
        if (nullptr == crypto_key || nullptr == temp) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const char* kty = nullptr;
        const char* kid = nullptr;
        const char* use = nullptr;
        const char* alg = nullptr;
        json_unpack (temp, "{s:s}", "kty", &kty);
        json_unpack (temp, "{s:s}", "kid", &kid);
        json_unpack (temp, "{s:s}", "use", &use);
        json_unpack (temp, "{s:s}", "alg", &alg);

        CRYPTO_USE_FLAG usage = CRYPTO_USE_ANY;
        if (nullptr != use) {
            if (0 == strcmp (use, "sig")) {
                usage = CRYPTO_USE_SIG;
            } else if (0 == strcmp (use, "enc")) {
                usage = CRYPTO_USE_ENC;
            }
        }

        if (nullptr != kty) {
            if (0 == strcmp (kty, "oct")) {
                const char* k_value = nullptr;
                json_unpack (temp, "{s:s}", "k", &k_value);

                add_oct (crypto_key, kid, alg, k_value, usage);
            } else if (0 == strcmp (kty, "RSA")) {
                const char* n_value = nullptr;
                const char* e_value = nullptr;
                const char* d_value = nullptr;
                json_unpack (temp, "{s:s,s:s,s:s}", "n", &n_value, "e", &e_value, "d", &d_value);

                const char* p_value = nullptr;
                const char* q_value = nullptr;
                const char* dp_value = nullptr;
                const char* dq_value = nullptr;
                const char* qi_value = nullptr;
                json_unpack (temp, "{s:s,s:s,s:s,s:s,s:s}",
                             "p", &p_value, "q", &q_value, "dp", &dp_value, "dq", &dq_value, "qi", &qi_value);

                add_rsa (crypto_key, kid, alg, n_value, e_value, d_value, p_value, q_value, dp_value, dq_value, qi_value, usage);
            } else if (0 == strcmp (kty, "EC")) {
                const char* crv_value = nullptr;
                const char* x_value = nullptr;
                const char* y_value = nullptr;
                const char* d_value = nullptr;
                json_unpack (temp, "{s:s,s:s,s:s,s:s}", "crv", &crv_value, "x", &x_value, "y", &y_value, "d", &d_value);

                add_ec (crypto_key, kid, alg, crv_value, x_value, y_value, d_value, usage);
            } else if (0 == strcmp (kty, "OKP")) {
                const char* crv_value = nullptr;
                const char* x_value = nullptr;
                const char* d_value = nullptr;
                json_unpack (temp, "{s:s,s:s,s:s}", "crv", &crv_value, "x", &x_value, "d", &d_value);

                add_ec (crypto_key, kid, alg, crv_value, x_value, nullptr, d_value, usage);
            } else {
                // do nothing
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_web_key::load (crypto_key* crypto_key, const char* buffer, int flags)
{
    UNREFERENCED_PARAMETER (flags);
    return_t ret = errorcode_t::success;
    json_t* root = nullptr;

    __try2
    {
        if (nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = json_open_stream (&root, buffer);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        json_t* keys_node = json_object_get (root, "keys");
        if (nullptr != keys_node) {
            if (JSON_ARRAY != json_typeof (keys_node)) {
                ret = ERROR_BAD_FORMAT;
                __leave2;
            }

            size_t size = json_array_size (keys_node);
            for (size_t i = 0; i < size; i++) {
                json_t* temp = json_array_get (keys_node, i);
                read_json_item (crypto_key, temp);
            } // json_array_size
        } else {
            read_json_item (crypto_key, root);
        }
    }
    __finally2
    {
        if (root) {
            json_decref (root);
        }
    }
    return ret;
}

return_t json_web_key::load_file (crypto_key* crypto_key, const char* file, int flags)
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

return_t json_web_key::load_pem (crypto_key* cryptokey, const char* buffer, int flags, CRYPTO_USE_FLAG use)
{
    return_t ret = errorcode_t::success;
    BIO* bio_pub = BIO_new (BIO_s_mem ());
    BIO* bio_priv = BIO_new (BIO_s_mem ());

    __try2
    {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t len = strlen (buffer);
        BIO_write (bio_pub, buffer, len);
        BIO_write (bio_priv, buffer, len);

        while (1) {
            EVP_PKEY* pkey_pub = nullptr;
            pkey_pub = PEM_read_bio_PUBKEY (bio_pub, nullptr, nullptr, nullptr);
            if (pkey_pub) {
                crypto_key_object_t key;
                key.pkey = pkey_pub;
                key.use = use;
                cryptokey->add (key);
            } else {
                break;
            }
        }

        while (1) {
            EVP_PKEY* pkey_priv = nullptr;
            pkey_priv = PEM_read_bio_PrivateKey (bio_priv, nullptr, nullptr, nullptr);
            if (pkey_priv) {
                crypto_key_object_t key;
                key.pkey = pkey_priv;
                key.use = use;
                cryptokey->add (key);
            } else {
                break;
            }
        }
    }
    __finally2
    {
        BIO_free_all (bio_pub);
        BIO_free_all (bio_priv);
    }
    return ret;
}

return_t json_web_key::load_pem_file (crypto_key* cryptokey, const char* file, int flags, CRYPTO_USE_FLAG use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == cryptokey || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string buffer;
        std::ifstream fs (file);
        if (fs.is_open ()) {
            std::getline (fs, buffer, (char) fs.eof ());
        } else {
            ret = ERROR_OPEN_FAILED;
            __leave2_trace (ret);
        }

        ret = load_pem (cryptokey, buffer.c_str (), flags, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

typedef struct _json_mapper_item_t {
    EVP_PKEY* pkey;
    crypto_key_t type;
    std::string kid;
    int use; // CRYPTO_USE_FLAG
    std::string alg;
    binary_t pub1;
    binary_t pub2;
    binary_t priv;
} json_mapper_item_t;

typedef std::list <json_mapper_item_t> json_mapper_items_t;

typedef struct _json_mapper_t {
    int flag;
    json_mapper_items_t items;
} json_mapper_t;

static void jwk_serialize_item (int flag, json_mapper_item_t item, json_t* json_item)
{
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    /* kty */
    json_object_set_new (json_item, "kty", json_string (nameof_key_type (item.type)));

    /* kid */
    if (item.kid.size ()) {
        json_object_set_new (json_item, "kid", json_string (item.kid.c_str ()));
    }

    /* use */
    if (CRYPTO_USE_SIG == item.use) {
        json_object_set_new (json_item, "use", json_string ("sig"));
    }
    if (CRYPTO_USE_ENC == item.use) {
        json_object_set_new (json_item, "use", json_string ("enc"));
    }

    if (item.alg.size ()) {
        json_object_set_new (json_item, "alg", json_string (item.alg.c_str ()));
    }

    std::string curve_name;

    if (kindof_ecc (item.type)) {
        advisor->nameof_ec_curve (item.pkey, curve_name);
    }

    /* param */
    if (CRYPTO_KEY_HMAC == item.type) {
        json_object_set_new (json_item, "k", json_string (base64_encode (item.priv, BASE64URL_ENCODING).c_str ()));
    } else if (CRYPTO_KEY_RSA == item.type) {
        json_object_set_new (json_item, "n", json_string (base64_encode (item.pub1, BASE64URL_ENCODING).c_str ()));
        json_object_set_new (json_item, "e", json_string (base64_encode (item.pub2, BASE64URL_ENCODING).c_str ()));
        if (flag) {
            json_object_set_new (json_item, "d", json_string (base64_encode (item.priv, BASE64URL_ENCODING).c_str ()));
        }
    } else if (CRYPTO_KEY_EC == item.type) {
        json_object_set_new (json_item, "crv", json_string (curve_name.c_str ()));
        json_object_set_new (json_item, "x", json_string (base64_encode (item.pub1, BASE64URL_ENCODING).c_str ()));
        json_object_set_new (json_item, "y", json_string (base64_encode (item.pub2, BASE64URL_ENCODING).c_str ()));
        if (flag) {
            json_object_set_new (json_item, "d", json_string (base64_encode (item.priv, BASE64URL_ENCODING).c_str ()));
        }
    } else if (CRYPTO_KEY_OKP == item.type) {
        json_object_set_new (json_item, "crv", json_string (curve_name.c_str ()));
        json_object_set_new (json_item, "x", json_string (base64_encode (item.pub1, BASE64URL_ENCODING).c_str ()));
        if (flag) {
            json_object_set_new (json_item, "d", json_string (base64_encode (item.priv, BASE64URL_ENCODING).c_str ()));
        }
    }
}

static return_t jwk_serialize (json_mapper_t mapper, std::string& buffer)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        buffer.clear ();

        size_t size = mapper.items.size ();
        if (0 == size) {
            ret = ERROR_NO_DATA;
            __leave2;
        }

        json_t* json_root = json_object ();
        if (json_root) {
            if (1 == size) {
                json_mapper_item_t& item = mapper.items.front ();
                jwk_serialize_item (mapper.flag, item, json_root);
            } else {
                json_t* json_keys = json_array ();
                if (json_keys) {
                    for (json_mapper_items_t::iterator iter = mapper.items.begin (); iter != mapper.items.end (); iter++) {
                        json_mapper_item_t item = *iter;

                        json_t* json_key = json_object ();

                        if (json_key) {
                            jwk_serialize_item (mapper.flag, item, json_key);
                            json_array_append_new (json_keys, json_key);
                        }
                    }
                    json_object_set_new (json_root, "keys", json_keys);
                }
            }
            char* contents = json_dumps (json_root, JOSE_JSON_FORMAT);
            if (contents) {
                buffer = contents;
                free (contents);
            }
            json_decref (json_root);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

static void pem_writer (crypto_key_object_t* key, void* param)
{
    __try2
    {
        if (nullptr == key || nullptr == param) {
            __leave2;
        }

        BIO* out = (BIO*) param;
        EVP_PKEY* pkey = (EVP_PKEY *) key->pkey;
        int type = EVP_PKEY_id (pkey);

        if (EVP_PKEY_HMAC == type) {
            PEM_write_bio_PrivateKey (out, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        } else if (EVP_PKEY_RSA == type) {
            if (RSA_get0_d (EVP_PKEY_get0_RSA (pkey))) {
                PEM_write_bio_RSAPrivateKey (out, EVP_PKEY_get0_RSA (pkey), nullptr, nullptr, 0, nullptr, nullptr);
            } else {
                PEM_write_bio_RSAPublicKey (out, EVP_PKEY_get0_RSA (pkey));
            }
        } else if (kindof_ecc (key->pkey)) {
            const BIGNUM* bn = EC_KEY_get0_private_key (EVP_PKEY_get0_EC_KEY (pkey));
            if (bn) {
                PEM_write_bio_ECPrivateKey (out, EVP_PKEY_get0_EC_KEY (pkey), nullptr, nullptr, 0, nullptr, nullptr);
            } else {
                PEM_write_bio_EC_PUBKEY (out, EVP_PKEY_get0_EC_KEY (pkey));     // same PEM_write_bio_PUBKEY
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    // do not return
}

static void json_writer (crypto_key_object_t* key, void* param)
{
    json_mapper_t* mapper = (json_mapper_t*) param;

    __try2
    {
        if (nullptr == key || nullptr == param) {
            __leave2;
        }

        json_mapper_item_t item;
        item.pkey = key->pkey;
        item.kid = key->kid;
        item.use = key->use;
        item.alg = key->alg;
        crypto_key::get_key (key->pkey, mapper->flag, item.type, item.pub1, item.pub2, item.priv);
        mapper->items.push_back (item);
    }
    __finally2
    {
        // do nothing
    }
    // do not return
}

return_t json_web_key::write_pem_file (crypto_key* cryptokey, const char* file, int flags)
{
    return_t ret = errorcode_t::success;
    BIO* out = nullptr;

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        out = BIO_new (BIO_s_mem ());
        if (nullptr == out) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        cryptokey->for_each (pem_writer, out);

        binary_t buf;
        buf.resize (64);
        FILE* fp = fopen (file, "wt");
        if (fp) {
            int len = 0;
            while (1) {
                len = BIO_read (out, &buf[0], buf.size ());
                if (0 >= len) {
                    break;
                }
                fwrite (&buf[0], 1, len, fp);
            }
            fclose (fp);
        } else {
            ret = ERROR_OPEN_FAILED;
            __leave2;
        }
    }
    __finally2
    {
        if (out) {
            BIO_free_all (out);
        }
    }
    return ret;
}

return_t json_web_key::write_json (crypto_key* crypto_key, const char* file, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string buffer;
        json_mapper_t mapper;
        mapper.flag = flags;
        crypto_key->for_each (json_writer, &mapper);

        jwk_serialize (mapper, buffer);

        FILE* fp = fopen (file, "wt");
        if (fp) {
            fwrite (buffer.c_str (), 1, buffer.size (), fp);
            fclose (fp);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_web_key::write (crypto_key* crypto_key, char* buf, size_t* buflen, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == buflen) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_request = *buflen;
        std::string buffer;
        json_mapper_t mapper;

        mapper.flag = flags;
        crypto_key->for_each (json_writer, &mapper);

        jwk_serialize (mapper, buffer);

        *buflen = buffer.size () + 1;
        if (buffer.size () + 1 > size_request) {
            ret = errorcode_t::insufficient_buffer;
            __leave2;
        } else {
            if (buf) {
                memcpy (buf, buffer.c_str (), buffer.size ());
                *(buf + buffer.size ()) = 0;
            } else {
                ret = errorcode_t::invalid_parameter;
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

}
}  // namespace
