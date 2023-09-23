/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/base/basic/base64.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/crypto/jose/json_object_encryption.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing_encryption.hpp>
#include <hotplace/sdk/crypto/jose/json_web_key.hpp>
#include <hotplace/sdk/io/basic/json.hpp>
#include <hotplace/sdk/io/string/string.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

json_object_signing_encryption::json_object_signing_encryption ()
{
    // do nothing
}

json_object_signing_encryption::~json_object_signing_encryption ()
{
    // do nothing
}

return_t json_object_signing_encryption::open (jose_context_t** context, crypto_key* crypto_key)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = nullptr;

    __try2
    {
        if (nullptr == context || nullptr == crypto_key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch (handle, new jose_context_t, ret, __leave2);

        handle->key = crypto_key;

        crypto_key->addref ();

        *context = handle;
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (handle) {
                delete handle;
            }
        }
    }
    return ret;
}

return_t json_object_signing_encryption::close (jose_context_t* context)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);

    __try2
    {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        clear_context (context);

        if (handle->key) {
            handle->key->release ();
        }
        delete handle;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing_encryption::encrypt (jose_context_t* context, jwe_t enc, jwa_t alg, binary_t const& input, std::string& output, jose_serialization_t type)
{
    return_t ret = errorcode_t::success;
    json_object_encryption encryption;

    __try2
    {
        output.clear ();

        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list <jwa_t> algs;
        algs.push_back (alg);
        prepare_encryption (context, enc, algs);

        binary_t encrypted;
        ret = encryption.encrypt (context, enc, alg, input, encrypted);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = write_encryption (context, output, type);

        clear_context (context);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing_encryption::encrypt (jose_context_t* context, jwe_t enc, std::list <jwa_t> algs, binary_t const& input, std::string& output, jose_serialization_t type)
{
    return_t ret = errorcode_t::success;
    json_object_encryption encryption;

    __try2
    {
        output.clear ();

        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        for (std::list <jwa_t>::iterator it = algs.begin (); it != algs.end (); ) {
            if (jwa_t::jwa_dir == *it || jwa_t::jwa_ecdh_es == *it) {
                // support "dir" for decryption only ...
                it = algs.erase (it);
            } else {
                it++;
            }
        }

        binary_t encrypted;

        prepare_encryption (context, enc, algs);

        for (std::list <jwa_t>::iterator iter = algs.begin (); iter != algs.end (); iter++) {
            jwa_t alg = *iter;

            return_t check = encryption.encrypt (context, enc, alg, input, encrypted);

            switch (check) {
                case errorcode_t::success:
                case errorcode_t::not_supported:
                    break;
                default:
                    ret = check;
            }
            if (errorcode_t::success != ret) {
                break;
            }
        }

        write_encryption (context, output, type);

        clear_context (context);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing_encryption::decrypt (jose_context_t* context, std::string const& input, binary_t& output, bool& result)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);
    json_object_encryption encryption;

    __try2
    {
        output.clear ();
        result = false;

        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        prepare_decryption (context, input.c_str ());

        return_t ret_test = errorcode_t::success;
        std::list <bool> results;
        for (jose_encryptions_map_t::iterator eit = handle->encryptions.begin (); eit != handle->encryptions.end (); eit++) {
            jwe_t enc = eit->first;
            jose_encryption_t& item = eit->second;

            for (jose_recipients_t::iterator rit = item.recipients.begin (); rit != item.recipients.end (); rit++) {
                jwa_t alg = rit->first;

                bool run = true;

                if (run) {
                    jose_recipient_t& recipient = rit->second;

                    std::string kid;

                    if (false == recipient.kid.empty ()) {
                        kid = recipient.kid;
                    } else if (false == item.kid.empty ()) {
                        kid = item.kid;
                    }

                    if (kid.empty ()) {
                        ret_test = encryption.decrypt (context, enc, alg, item.datamap[crypt_item_t::item_ciphertext], output);
                    } else {
                        ret_test = encryption.decrypt (context, enc, alg, kid.c_str (), item.datamap[crypt_item_t::item_ciphertext], output);
                    }

                    results.push_back ((bool) (errorcode_t::success == ret_test));
                }
            }
        }

        if (results.empty ()) {
            ret = errorcode_t::not_supported;
        } else {
            results.unique ();
            if (1 == results.size () && true == results.front ()) {
                //
            } else {
                ret = errorcode_t::verify;
            }
        }

        clear_context (context);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing_encryption::sign (jose_context_t* context, jws_t sig, std::string const& input, std::string& output, jose_serialization_t type)
{
    std::list <jws_t> methods;

    methods.push_back (sig);
    return sign (context, methods, input, output, type);
}

return_t json_object_signing_encryption::sign (jose_context_t* context, std::list <jws_t> const& methods, std::string const& input, std::string& output, jose_serialization_t type)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    output.clear ();
    std::list<std::string> headers;

    for (std::list <jws_t>::const_iterator method_iter = methods.begin (); method_iter != methods.end (); method_iter++) {
        jws_t sig = *method_iter;

        const hint_signature_t* hint = advisor->hintof_jose_signature (sig);

        if (hint) {
            json_t* json = json_object ();
            if (json) {
                json_object_set_new (json, "alg", json_string (hint->jws_name));

                char* contents = json_dumps (json, JOSE_JSON_FORMAT);
                if (contents) {
                    headers.push_back (contents);
                    free (contents);
                }

                json_decref (json);
            }
        }
    }
    ret = sign (context, headers, input, output, type);
    return ret;
}

return_t json_object_signing_encryption::sign (jose_context_t* context, std::string const& protected_header, std::string const& input, std::string& output, jose_serialization_t type)
{
    std::list <std::string> headers;

    headers.push_back (protected_header);
    return sign (context, headers, input, output, type);
}

return_t json_object_signing_encryption::sign (jose_context_t* context, std::list<std::string> const& headers, std::string const& input, std::string& output, jose_serialization_t type)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);
    json_object_signing sign;

    __try2
    {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->signs.clear ();

        for (std::list<std::string>::const_iterator iter = headers.begin (); iter != headers.end (); iter++) {
            std::string header = *iter;

            jws_t sig = jws_t::jws_unknown;
            std::string kid;

            parse_signature_header (context, header.c_str (), sig, kid);
            if (jws_t::jws_unknown == sig) {
                size_t header_size = headers.size ();
                if (header_size > 1) {
                    continue;
                } else if (header_size == 1) {
                    ret = errorcode_t::low_security;
                    break;
                }
            }

            std::string header_encoded = base64_encode ((byte_t*) header.c_str (), header.size (), base64_encoding_t::base64url_encoding);
            std::string claims_encoded = base64_encode ((byte_t*) input.c_str (), input.size (), base64_encoding_t::base64url_encoding);

            binary_t header_claims;

            header_claims.insert (header_claims.end (), header_encoded.begin (), header_encoded.end ());
            header_claims.insert (header_claims.end (), '.');
            header_claims.insert (header_claims.end (), claims_encoded.begin (), claims_encoded.end ());

            binary_t signature;

            return_t check = sign.sign (handle->key, sig, header_claims, signature, kid);
            if (errorcode_t::success != check) {
                continue;
            }

            jose_sign_t item;

            item.header = header_encoded;
            item.payload = claims_encoded;
            item.signature = base64_encode (&signature[0], signature.size (), base64_encoding_t::base64url_encoding);

            item.kid = kid;
            item.sig = sig;
            handle->signs.push_back (item);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = write_signature (context, output, type);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing_encryption::verify (jose_context_t* context, std::string const& input, bool& result)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);
    json_object_signing sign;

    __try2
    {
        result = false;
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = read_signature (context, input.c_str ());
        if (errorcode_t::success != ret) {
            __leave2;
        }

        std::list <bool> list_result;
        for (jose_signs_t::iterator iter = handle->signs.begin (); iter != handle->signs.end (); iter++) {
            jose_sign_t item = *iter;

            bool result_per_signature = false;

            std::string protected_header = base64_decode_careful (item.header, base64_encoding_t::base64url_encoding);
            jws_t sig;
            std::string header_kid;

            parse_signature_header (context, protected_header.c_str (), sig, header_kid);
            if (jws_t::jws_unknown == sig) {
                // RFC 7520 4.7. Protecting Content Only
                if (jws_t::jws_unknown == item.sig) {
                    continue;
                } else {
                    sig = item.sig;
                }
            }

            binary_t header_claims;

            header_claims.insert (header_claims.end (), item.header.begin (), item.header.end ());
            header_claims.insert (header_claims.end (), '.');
            header_claims.insert (header_claims.end (), item.payload.begin (), item.payload.end ());

            const char* kid = nullptr;         // use the key named kid

            if (item.kid.size ()) {
                kid = item.kid.c_str ();    // per-signature header kid
            } else if (header_kid.size ()) {
                kid = header_kid.c_str ();  // protected_header shared kid

            }
            binary_t signature_decoded;

            base64_decode (item.signature, signature_decoded, base64_encoding_t::base64url_encoding);
            ret = sign.verify (handle->key, kid, sig, header_claims, signature_decoded, result_per_signature);
            if (errorcode_t::success != ret) {
                break;
            }
            list_result.push_back (result_per_signature);
        }

        if (handle->signs.size () == list_result.size ()) {
            list_result.unique ();
            if (1 == list_result.size ()) {
                if (true == list_result.front ()) {
                    result = true;
                }
            }
        }

        if (false == result) {
            ret = errorcode_t::verify;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing_encryption::prepare_encryption (jose_context_t* context, jwe_t enc, std::list <jwa_t> const& algs)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);
    openssl_prng rand;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        clear_context (context);

        if (algs.empty ()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        jose_encryptions_map_t::iterator iter = handle->encryptions.find (enc);
        if (handle->encryptions.end () == iter) {
            const hint_jose_encryption_t* enc_info = advisor->hintof_jose_encryption (enc); // content encryption
            if (nullptr == enc_info) {
                ret = errorcode_t::not_supported;
                __leave2;
            }

            const EVP_CIPHER* enc_evp_cipher = (const EVP_CIPHER*) advisor->find_evp_cipher (enc_info->crypt_alg, enc_info->crypt_mode);
            if (nullptr == enc_evp_cipher) {
                ret = errorcode_t::internal_error;
                __leave2;
            }

            uint32 enc_type = CRYPT_ENC_TYPE (enc_info->type);
            int keysize = EVP_CIPHER_key_length (enc_evp_cipher);
            int ivsize = EVP_CIPHER_iv_length (enc_evp_cipher);
            /* EVP_CIPHER_CTX_key_length, EVP_CIPHER_CTX_iv_length
             * [openssl 3.0.3] compatibility problem
             * EVP_CIPHER_..._length return EVP_CTRL_RET_UNSUPPORTED(-1)
             */
            adjust_range (keysize, 0, EVP_MAX_KEY_LENGTH);
            adjust_range (ivsize, 0, EVP_MAX_IV_LENGTH);
            if (jwe_type_t::jwe_type_aescbc_hs == enc_type) {
                keysize *= 2;
            }

            jose_encryption_t item;

            item.enc_info = enc_info;
            /* generate cek if not included "dir", "ECDH-ES" */
            rand.random (item.datamap[crypt_item_t::item_cek], keysize);
            rand.random (item.datamap[crypt_item_t::item_iv], ivsize);

            binary_t protected_header;

            if (1 == algs.size ()) {
                jwa_t alg = algs.front ();

                //const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm (alg);  // key management
                std::string kid;
                EVP_PKEY* pkey = handle->key->select (kid, alg, crypto_use_t::use_enc);
                if (nullptr == pkey) {
                    ret = errorcode_t::not_found;
                    __leave2;
                }

                crypt_datamap_t datamap;
                crypt_variantmap_t variantmap;
                jose_recipient_t recipient;
                prepare_encryption_recipient (alg, pkey, recipient, datamap, variantmap);

                binary_t header;
                compose_encryption_header (enc, alg, jose_compose_t::jose_enc_alg, kid, datamap, variantmap, protected_header);
                compose_encryption_header (jwe_t::jwe_unknown, alg, jose_compose_t::jose_alg_only, kid, datamap, variantmap, header);

                item.header.assign ((char*) &protected_header[0], protected_header.size ());
                base64_encode (&protected_header[0], protected_header.size (), item.datamap[crypt_item_t::item_aad], base64_encoding_t::base64url_encoding);

                recipient.header = std::string ((char*) &header[0], header.size ());
                recipient.kid = kid;
                item.recipients.insert (std::make_pair (alg, recipient));
            } else if (algs.size () > 1) {
                compose_encryption_header (enc, jwa_t::jwa_unknown, jose_compose_t::jose_enc_only, "", protected_header);
                item.header.assign ((char*) &protected_header[0], protected_header.size ());
                base64_encode (&protected_header[0], protected_header.size (), item.datamap[crypt_item_t::item_aad], base64_encoding_t::base64url_encoding);

                for (std::list <jwa_t>::const_iterator iter = algs.begin (); iter != algs.end (); iter++) {
                    jwa_t alg = *iter;

                    //const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm (alg);  // key management
                    std::string kid;
                    EVP_PKEY* pkey = handle->key->select (kid, alg, crypto_use_t::use_enc);

                    crypt_datamap_t datamap;
                    crypt_variantmap_t variantmap;
                    jose_recipient_t recipient;

                    recipient.kid = kid;
                    prepare_encryption_recipient (alg, pkey, recipient, datamap, variantmap);

                    binary_t header;
                    compose_encryption_header (jwe_t::jwe_unknown, alg, jose_compose_t::jose_alg_only, kid, datamap, variantmap, header);
                    recipient.header = std::string ((char*) &header[0], header.size ());
                    item.recipients.insert (std::make_pair (alg, recipient));
                }
            }

            handle->protected_header = protected_header;
            handle->encryptions.insert (std::make_pair (enc, item));
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing_encryption::prepare_encryption_recipient (jwa_t alg, EVP_PKEY* pkey, jose_recipient_t& recipient, crypt_datamap_t& datamap, crypt_variantmap_t& variantmap)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm (alg);  // key management
    uint32 alg_type = CRYPT_ALG_TYPE (alg);

    recipient.alg_info = alg_info;
    if ((jwa_type_t::jwa_type_ecdh == alg_type) || (jwa_type_t::jwa_type_ecdh_aeskw == alg_type)) {
        // epk, apu, apv
        uint32 nid = 0;
        crypto_key key;
        crypto_keychain keyset;
        std::string kid;
        nidof_evp_pkey (pkey, nid);                                 // "crv" of key
        keyset.add_ec (&key, nid);                                  // same "crv"
        recipient.epk = key.select (crypto_use_t::use_enc, true);   // EVP_PKEY_up_ref
        variant_t vt;
        variant_set_pointer (vt, recipient.epk);
        variantmap[crypt_item_t::item_epk] = vt;
    } else if (jwa_type_t::jwa_type_aesgcmkw == alg_type) {
        // iv, tag
        const EVP_CIPHER* alg_evp_cipher = (const EVP_CIPHER*) advisor->find_evp_cipher (alg_info->crypt_alg, alg_info->crypt_mode);
        int ivsize = EVP_CIPHER_iv_length (alg_evp_cipher);
        openssl_prng rand;
        rand.random (recipient.datamap[crypt_item_t::item_iv], ivsize);
        datamap[crypt_item_t::item_iv] = recipient.datamap[crypt_item_t::item_iv];
        datamap[crypt_item_t::item_tag] = recipient.datamap[crypt_item_t::item_tag];
    } else if (jwa_type_t::jwa_type_pbes_hs_aeskw == alg_type) {
        // p2s, p2c
        openssl_prng rand;
        rand.random (recipient.datamap[crypt_item_t::item_p2s], 64);
        rand.random (recipient.p2c, 0xffff);
        variant_t vt;
        variant_set_int32 (vt, recipient.p2c);
        datamap[crypt_item_t::item_p2s] = recipient.datamap[crypt_item_t::item_p2s];
        variantmap[crypt_item_t::item_p2c] = vt;
    }
    return ret;
}

return_t json_object_signing_encryption::compose_encryption_header (jwe_t enc, jwa_t alg, jose_compose_t flag, std::string const& kid, binary_t& header)
{
    return_t ret = errorcode_t::success;
    crypt_datamap_t datamap;
    crypt_variantmap_t variantmap;

    ret = compose_encryption_header (enc, alg, flag, kid, datamap, variantmap, header);
    return ret;
}

return_t json_object_signing_encryption::compose_encryption_header (jwe_t enc, jwa_t alg, jose_compose_t flag, std::string const& kid, crypt_datamap_t& datamap, crypt_variantmap_t& variantmap, binary_t& header)
{
    return_t ret = errorcode_t::success;
    json_t* json_header = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        header.clear ();

        if (0 == (jose_compose_t::jose_enc_alg & flag)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const char* enc_value = advisor->nameof_jose_encryption (enc);
        const char* alg_value = advisor->nameof_jose_algorithm (alg);

        json_header = json_object ();

        if (jose_compose_t::jose_enc_only & flag) {
            if (nullptr == enc_value) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            json_object_set_new (json_header, "enc", json_string (enc_value));
        }
        if (jose_compose_t::jose_alg_only & flag) {
            if (nullptr == alg_value) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            json_object_set_new (json_header, "alg", json_string (alg_value));
            if (kid.size ()) {
                json_object_set_new (json_header, "kid", json_string (kid.c_str ()));
            }
            uint32 alg_type = CRYPT_ALG_TYPE (alg);
            if ((jwa_type_t::jwa_type_ecdh == alg_type) || (jwa_type_t::jwa_type_ecdh_aeskw == alg_type)) {
                // epk, apu, apv
                binary_t pub1;
                binary_t pub2;
                EVP_PKEY* epk = (EVP_PKEY*) variantmap[crypt_item_t::item_epk].data.p;
                crypto_key::get_public_key (epk, pub1, pub2);
                json_t* json_epk = json_object ();
                if (json_epk) {
                    std::string kty;
                    std::string curve_name;
                    advisor->ktyof_ec_curve (epk, kty);
                    advisor->nameof_ec_curve (epk, curve_name);

                    json_object_set_new (json_epk, "kty", json_string (kty.c_str ()));
                    json_object_set_new (json_epk, "crv", json_string (curve_name.c_str ()));
                    json_object_set_new (json_epk, "x", json_string (base64_encode (&pub1[0], pub1.size (), base64_encoding_t::base64url_encoding).c_str ()));
                    if (pub2.size ()) {
                        json_object_set_new (json_epk, "y", json_string (base64_encode (&pub2[0], pub2.size (), base64_encoding_t::base64url_encoding).c_str ()));
                    }
                    json_object_set_new (json_header, "epk", json_epk);
                }
            } else if (jwa_type_t::jwa_type_aesgcmkw == alg_type) {
                // iv, tag
                binary_t iv1 = datamap[crypt_item_t::item_iv];
                binary_t tag1 = datamap[crypt_item_t::item_tag];
                json_object_set_new (json_header, "iv", json_string (base64_encode (&iv1[0], iv1.size (), base64_encoding_t::base64url_encoding).c_str ()));
                json_object_set_new (json_header, "tag", json_string (base64_encode (&tag1[0], tag1.size (), base64_encoding_t::base64url_encoding).c_str ()));
            } else if (jwa_type_t::jwa_type_pbes_hs_aeskw == alg_type) {
                // p2s, p2c
                binary_t p2s = datamap[crypt_item_t::item_p2s];
                uint32 p2c = variantmap[crypt_item_t::item_p2c].data.i32;
                json_object_set_new (json_header, "p2s", json_string (base64_encode (&p2s[0], p2s.size (), base64_encoding_t::base64url_encoding).c_str ()));
                json_object_set_new (json_header, "p2c", json_integer (p2c));
            }
        }

        char* contents = json_dumps (json_header, JOSE_JSON_FORMAT);
        if (nullptr != contents) {
            header.insert (header.end (), (byte_t*) contents, (byte_t*) contents + strlen (contents));
            free (contents);
        } else {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2
    {
        if (json_header) {
            json_decref (json_header);
        }
    }

    return ret;
}

return_t json_object_signing_encryption::prepare_decryption_item (jose_context_t* context,
                                                                  const char* protected_header, const char* encrypted_key, const char* iv, const char* ciphertext, const char* tag,
                                                                  void* json, jwe_t& type, jose_encryption_t& item)
{
    return_t ret = errorcode_t::success;
    json_t* json_protected = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        type = jwe_t::jwe_unknown;

        std::string protected_header_decoded = base64_decode_careful (protected_header, strlen (protected_header), base64_encoding_t::base64url_encoding);
        ret = json_open_stream (&json_protected, protected_header_decoded.c_str ());
        if (errorcode_t::success != ret) {
            __leave2;
        }
        const char* enc = nullptr;
        json_unpack (json_protected, "{s:s}", "enc", &enc);

        const hint_jose_encryption_t* hintof_enc = advisor->hintof_jose_encryption (enc);
        if (nullptr == hintof_enc) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        type = (jwe_t) hintof_enc->type;

        item.enc_info = hintof_enc;
        item.datamap[crypt_item_t::item_aad] = convert (protected_header); // base64url encoded
        item.header = protected_header_decoded;
        base64_decode (iv, strlen (iv), item.datamap[crypt_item_t::item_iv], base64_encoding_t::base64url_encoding);
        base64_decode (tag, strlen (tag), item.datamap[crypt_item_t::item_tag], base64_encoding_t::base64url_encoding);
        base64_decode (ciphertext, strlen (ciphertext), item.datamap[crypt_item_t::item_ciphertext], base64_encoding_t::base64url_encoding);
    }
    __finally2
    {
        if (json_protected) {
            json_decref (json_protected);
        }
    }
    return ret;
}

return_t json_object_signing_encryption::prepare_decryption_recipient (jose_context_t* context,
                                                                       const char* protected_header, const char* encrypted_key, void* json, jwa_t& type, jose_recipient_t& recipient)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    json_t* json_header = nullptr;
    json_t* json_protected = nullptr;

    __try2
    {
        recipient.datamap[crypt_item_t::item_encryptedkey].clear ();

        type = jwa_t::jwa_unknown;

        const char* enc = nullptr;
        return_t ret_test = errorcode_t::success;
        std::string protected_header_decoded = base64_decode_careful (protected_header, strlen (protected_header), base64_encoding_t::base64url_encoding);
        ret_test = json_open_stream (&json_protected, protected_header_decoded.c_str ());
        if (errorcode_t::success != ret_test) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        json_unpack (json_protected, "{s:s}", "enc", &enc);

        const hint_jose_encryption_t* hintof_enc = advisor->hintof_jose_encryption (enc);
        if (nullptr == hintof_enc) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (json) {
            json_header = (json_t*) json;
        } else {
            json_header = json_protected;
        }

        const char* enckey = nullptr;
        if (nullptr == encrypted_key) {
            json_unpack (json_header, "{s:s}", "encrypted_key", &enckey);
        } else {
            enckey = encrypted_key;
        }
        if (enckey) {
            base64_decode (enckey, strlen (enckey), recipient.datamap[crypt_item_t::item_encryptedkey], base64_encoding_t::base64url_encoding);
        }

        const char* alg = nullptr;
        const char* kid = nullptr;
        json_unpack (json_header, "{s:s}", "alg", &alg);
        json_unpack (json_header, "{s:s}", "kid", &kid);
        const hint_jose_encryption_t* hintof_alg = advisor->hintof_jose_algorithm (alg);
        if (nullptr == hintof_alg) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        recipient.alg_info = hintof_alg;
        if (kid) {
            recipient.kid = kid;
        }

        type = (jwa_t) hintof_alg->type;
        uint32 alg_type = CRYPT_ALG_TYPE ((jwa_t) hintof_alg->type);
        if ((jwa_type_t::jwa_type_ecdh == alg_type) || (jwa_type_t::jwa_type_ecdh_aeskw == alg_type)) { // epk
            json_t* epk = nullptr;
            const char* kty_value = nullptr;
            const char* crv_value = nullptr;
            const char* x_value = nullptr;
            const char* y_value = nullptr;
            const char* apu_value = nullptr;
            const char* apv_value = nullptr;
            if (json_header) {
                json_unpack (json_header, "{s:o}", "epk", &epk);
                json_unpack (json_header, "{s:s}", "apu", &apu_value);
                json_unpack (json_header, "{s:s}", "apv", &apv_value);
            }
            if (nullptr == epk) {
                json_unpack (json_protected, "{s:o}", "epk", &epk);
                json_unpack (json_protected, "{s:s}", "apu", &apu_value);
                json_unpack (json_protected, "{s:s}", "apv", &apv_value);
            }
            if (epk) {
                json_unpack (epk, "{s:s,s:s,s:s,s:s}", "kty", &kty_value, "crv", &crv_value, "x", &x_value, "y", &y_value);
                if (nullptr == kty_value || nullptr == crv_value || nullptr == x_value) {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
            } else {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            json_web_key jwk;
            crypto_key key;
            jwk.add_ec_b64u (&key, nullptr, nullptr, crv_value, x_value, y_value, nullptr);
            recipient.epk = key.select (crypto_use_t::use_enc, true); // EVP_PKEY_up_ref
            if (apu_value) {
                base64_decode (apu_value, strlen (apu_value), recipient.datamap[crypt_item_t::item_apu], base64_encoding_t::base64url_encoding);
            }
            if (apv_value) {
                base64_decode (apv_value, strlen (apv_value), recipient.datamap[crypt_item_t::item_apv], base64_encoding_t::base64url_encoding);
            }
        } else if (jwa_type_t::jwa_type_aesgcmkw == alg_type) { // iv, tag
            const char* iv_value = nullptr;
            const char* tag_value = nullptr;
            if (json_header) {
                json_unpack (json_header, "{s:s}", "iv", &iv_value);
                json_unpack (json_header, "{s:s}", "tag", &tag_value);
            }
            if (nullptr == iv_value || nullptr == tag_value) {
                json_unpack (json_protected, "{s:s}", "iv", &iv_value);
                json_unpack (json_protected, "{s:s}", "tag", &tag_value);
                if (nullptr == iv_value || nullptr == tag_value) {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
            }
            base64_decode (iv_value, strlen (iv_value), recipient.datamap[crypt_item_t::item_iv], base64_encoding_t::base64url_encoding);
            base64_decode (tag_value, strlen (tag_value), recipient.datamap[crypt_item_t::item_tag], base64_encoding_t::base64url_encoding);
        } else if (jwa_type_t::jwa_type_pbes_hs_aeskw == alg_type) { // p2s, p2c
            const char* p2s = nullptr;
            int p2c = -1;
            if (json_header) {
                json_unpack (json_header, "{s:s}", "p2s", &p2s);
                json_unpack (json_header, "{s:i}", "p2c", &p2c);
            }
            if (nullptr == p2s || -1 == p2c) {
                json_unpack (json_protected, "{s:s}", "p2s", &p2s);
                json_unpack (json_protected, "{s:i}", "p2c", &p2c);
                if (nullptr == p2s || -1 == p2c) {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
            }
            base64_decode (p2s, strlen (p2s), recipient.datamap[crypt_item_t::item_p2s], base64_encoding_t::base64url_encoding);
            recipient.p2c = p2c;
        }
    }
    __finally2
    {
        if (json_protected) {
            json_decref (json_protected);
        }
    }

    return ret;
}

return_t json_object_signing_encryption::prepare_decryption (jose_context_t* context, const char* input)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);
    json_t* json_root = nullptr;
    split_context_t* split_handle = nullptr;

    __try2
    {
        if (nullptr == context || nullptr == input) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        clear_context (context);

        return_t ret_test = json_open_stream (&json_root, input, true);
        if (errorcode_t::success == ret_test) {
            json_t* json_recipients = nullptr;
            json_unpack (json_root, "{s:o}", "recipients", &json_recipients);
            if (json_recipients) {
                if (json_is_array (json_recipients)) {  // jose_serialization_t::jose_json
                    const char* protected_header = nullptr;
                    const char* iv = nullptr;
                    const char* ciphertext = nullptr;
                    const char* tag = nullptr;

                    json_unpack (json_root, "{s:s,s:s,s:s,s:s}",
                                 "protected", &protected_header, "iv", &iv, "ciphertext", &ciphertext, "tag", &tag);

                    jose_encryption_t item;
                    jwe_t enc_type = jwe_t::jwe_unknown;
                    prepare_decryption_item (context, protected_header, nullptr, iv, ciphertext, tag, nullptr, enc_type, item);

                    size_t array_size = json_array_size (json_recipients);
                    for (size_t index = 0; index < array_size; index++) {
                        json_t* json_recipient = json_array_get (json_recipients, index);
                        json_t* json_header = nullptr;
                        jose_recipient_t recipient;
                        jwa_t alg_type = jwa_t::jwa_unknown;

                        const char* encrypted_key = nullptr;
                        //char* header = nullptr;

                        json_unpack (json_recipient, "{s:o}", "header", &json_header);
                        json_unpack (json_recipient, "{s:s}", "encrypted_key", &encrypted_key);

                        prepare_decryption_recipient (context, protected_header, encrypted_key, json_header, alg_type, recipient);
                        item.recipients.insert (std::make_pair (alg_type, recipient));
                    }
                    handle->encryptions.insert (std::make_pair (enc_type, item));
                } else {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
            } else {                                    // jose_serialization_t::jose_flatjson
                const char* protected_header = nullptr;
                const char* encrypted_key = nullptr;
                const char* iv = nullptr;
                const char* ciphertext = nullptr;
                const char* tag = nullptr;

                json_unpack (json_root, "{s:s,s:s,s:s,s:s}",
                             "protected", &protected_header, "iv", &iv, "ciphertext", &ciphertext, "tag", &tag);
                json_unpack (json_root, "{s:s}", "encrypted_key", &encrypted_key); // not exist in case of "dir", "ECDH-ES"

                jose_encryption_t item;
                jose_recipient_t recipient;
                jwe_t enc_type = jwe_t::jwe_unknown;
                jwa_t alg_type = jwa_t::jwa_unknown;
                prepare_decryption_item (context, protected_header, encrypted_key, iv, ciphertext, tag, nullptr, enc_type, item);
                prepare_decryption_recipient (context, protected_header, encrypted_key, nullptr, alg_type, recipient);

                item.recipients.insert (std::make_pair (alg_type, recipient));
                handle->encryptions.insert (std::make_pair (enc_type, item));
            }
        } else { // jose_serialization_t::jose_compact
            size_t count = 0;
            split_begin (&split_handle, input, ".");
            split_count (split_handle, count);
            if (5 != count) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            std::string protected_header;
            std::string encrypted_key;
            std::string iv;
            std::string ciphertext;
            std::string tag;

            /* base64url encoded */
            split_get (split_handle, 0, protected_header);
            split_get (split_handle, 1, encrypted_key);
            split_get (split_handle, 2, iv);
            split_get (split_handle, 3, ciphertext);
            split_get (split_handle, 4, tag);

            jose_encryption_t item;
            jose_recipient_t recipient;
            jwe_t enc_type = jwe_t::jwe_unknown;
            jwa_t alg_type = jwa_t::jwa_unknown;
            prepare_decryption_item (context, protected_header.c_str (), encrypted_key.c_str (), iv.c_str (), ciphertext.c_str (), tag.c_str (), nullptr, enc_type, item);
            prepare_decryption_recipient (context, protected_header.c_str (), encrypted_key.c_str (), nullptr, alg_type, recipient);

            item.recipients.insert (std::make_pair (alg_type, recipient));
            handle->encryptions.insert (std::make_pair (enc_type, item));
        }
    }
    __finally2
    {
        if (split_handle) {
            split_end (split_handle);
        }
        if (json_root) {
            json_decref (json_root);
        }
    }
    return ret;
}

return_t json_object_signing_encryption::clear_context (jose_context_t* context)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);

    __try2
    {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        for (jose_encryptions_map_t::iterator iter = handle->encryptions.begin (); iter != handle->encryptions.end (); iter++) {
            jose_encryption_t& item = iter->second;

            for (jose_recipients_t::iterator rit = item.recipients.begin (); rit != item.recipients.end (); rit++) {
                jose_recipient_t& recipient = rit->second;

                EVP_PKEY_free (recipient.epk);
            }
        }

        handle->protected_header.clear ();
        handle->encryptions.clear ();
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing_encryption::write_encryption (jose_context_t* context, std::string& output, jose_serialization_t type)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        output.clear ();

        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (handle->encryptions.empty ()) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        jose_encryptions_map_t::iterator eit = handle->encryptions.begin ();
        jose_encryption_t& encryption = eit->second;
        if (encryption.recipients.empty ()) {
            __leave2;
        }

        jose_recipients_t::iterator rit = encryption.recipients.begin ();
        jose_recipient_t& recipient = rit->second;

        std::string b64_header;
        std::string b64_iv;
        std::string b64_tag;
        std::string b64_ciphertext;
        std::string b64_encryptedkey;

        b64_header = base64_encode ((byte_t*) encryption.header.c_str (), encryption.header.size (), base64_encoding_t::base64url_encoding);
        b64_iv = base64_encode (&encryption.datamap[crypt_item_t::item_iv][0], encryption.datamap[crypt_item_t::item_iv].size (), base64_encoding_t::base64url_encoding);
        b64_tag = base64_encode (&encryption.datamap[crypt_item_t::item_tag][0], encryption.datamap[crypt_item_t::item_tag].size (), base64_encoding_t::base64url_encoding);
        b64_ciphertext = base64_encode (&encryption.datamap[crypt_item_t::item_ciphertext][0], encryption.datamap[crypt_item_t::item_ciphertext].size (), base64_encoding_t::base64url_encoding);

        if (jose_serialization_t::jose_compact == type) {
            b64_encryptedkey = base64_encode (&recipient.datamap[crypt_item_t::item_encryptedkey][0], recipient.datamap[crypt_item_t::item_encryptedkey].size (), base64_encoding_t::base64url_encoding);

            output += b64_header; //std::string ((char*) &encryption.datamap[crypt_item_t::item_aad][0], encryption.datamap[crypt_item_t::item_aad].size ());
            output += ".";
            output += b64_encryptedkey;
            output += ".";
            output += b64_iv;
            output += ".";
            output += b64_ciphertext;
            output += ".";
            output += b64_tag;
        } else if (jose_serialization_t::jose_flatjson == type) {
            b64_encryptedkey = base64_encode (&recipient.datamap[crypt_item_t::item_encryptedkey][0], recipient.datamap[crypt_item_t::item_encryptedkey].size (), base64_encoding_t::base64url_encoding);

            json_t* json_serialization = nullptr;
            __try2
            {
                json_serialization = json_object ();
                if (nullptr == json_serialization) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_object_set_new (json_serialization, "protected", json_string (b64_header.c_str ()));
                json_object_set_new (json_serialization, "encrypted_key", json_string (b64_encryptedkey.c_str ()));
                json_object_set_new (json_serialization, "iv", json_string (b64_iv.c_str ()));
                json_object_set_new (json_serialization, "ciphertext", json_string (b64_ciphertext.c_str ()));
                json_object_set_new (json_serialization, "tag", json_string (b64_tag.c_str ()));

                char* contents = json_dumps (json_serialization, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    output = contents;
                    free (contents);
                } else {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
            }
            __finally2
            {
                if (json_serialization) {
                    json_decref (json_serialization);
                }
            }
        } else if (jose_serialization_t::jose_json == type) {
            json_t* json_serialization = nullptr;
            json_t* json_recipients = nullptr;
            json_t* json_recipient = nullptr;
            __try2
            {
                json_serialization = json_object ();
                if (nullptr == json_serialization) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_recipients = json_array ();
                if (nullptr == json_recipients) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_object_set_new (json_serialization, "protected", json_string (b64_header.c_str ()));
                for (jose_recipients_t::iterator rit = encryption.recipients.begin (); rit != encryption.recipients.end (); rit++) {
                    jwa_t alg = rit->first;

                    jose_recipient_t& recipient = rit->second;

                    json_recipient = json_object ();
                    if (json_recipient) {
                        json_t* header = json_object ();
                        if (header) {
                            const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm (alg);
                            json_object_set_new (header, "alg", json_string (hint->alg_name));
                            if (recipient.kid.size ()) {
                                json_object_set_new (header, "kid", json_string (recipient.kid.c_str ()));
                            }

                            uint32 alg_type = CRYPT_ALG_TYPE (alg);
                            if ((jwa_type_t::jwa_type_ecdh == alg_type) || (jwa_type_t::jwa_type_ecdh_aeskw == alg_type)) {
                                binary_t pub1;
                                binary_t pub2;
                                EVP_PKEY* epk = recipient.epk;
                                crypto_key::get_public_key (epk, pub1, pub2);
                                json_t* json_epk = json_object ();
                                if (json_epk) {
                                    std::string kty;
                                    std::string curve_name;
                                    advisor->ktyof_ec_curve (epk, kty);
                                    advisor->nameof_ec_curve (epk, curve_name);

                                    json_object_set_new (json_epk, "kty", json_string (kty.c_str ()));
                                    json_object_set_new (json_epk, "crv", json_string (curve_name.c_str ()));
                                    json_object_set_new (json_epk, "x", json_string (base64_encode (&pub1[0], pub1.size (), base64_encoding_t::base64url_encoding).c_str ()));
                                    if (pub2.size ()) {
                                        json_object_set_new (json_epk, "y", json_string (base64_encode (&pub2[0], pub2.size (), base64_encoding_t::base64url_encoding).c_str ()));
                                    }
                                    json_object_set_new (header, "epk", json_epk);
                                }
                            } else if (jwa_type_t::jwa_type_aesgcmkw == alg_type) {
                                std::string b64_iv = base64_encode (&recipient.datamap[crypt_item_t::item_iv][0], recipient.datamap[crypt_item_t::item_iv].size (), base64_encoding_t::base64url_encoding);
                                std::string b64_tag = base64_encode (&recipient.datamap[crypt_item_t::item_tag][0], recipient.datamap[crypt_item_t::item_tag].size (), base64_encoding_t::base64url_encoding);
                                json_object_set_new (header, "iv", json_string (b64_iv.c_str ()));
                                json_object_set_new (header, "tag", json_string (b64_tag.c_str ()));
                            } else if (jwa_type_t::jwa_type_pbes_hs_aeskw == alg_type) {
                                std::string b64_p2s = base64_encode (&recipient.datamap[crypt_item_t::item_p2s][0], recipient.datamap[crypt_item_t::item_p2s].size (), base64_encoding_t::base64url_encoding);
                                json_object_set_new (header, "p2s", json_string (b64_p2s.c_str ()));
                                json_object_set_new (header, "p2c", json_integer (recipient.p2c));
                            }

                            json_object_set_new (json_recipient, "header", header);
                        }

                        b64_encryptedkey = base64_encode (&recipient.datamap[crypt_item_t::item_encryptedkey][0], recipient.datamap[crypt_item_t::item_encryptedkey].size (), base64_encoding_t::base64url_encoding);
                        json_object_set_new (json_recipient, "encrypted_key", json_string (b64_encryptedkey.c_str ()));

                        json_array_append_new (json_recipients, json_recipient);
                    }
                }
                json_object_set_new (json_serialization, "recipients", json_recipients);
                json_object_set_new (json_serialization, "iv", json_string (b64_iv.c_str ()));
                json_object_set_new (json_serialization, "ciphertext", json_string (b64_ciphertext.c_str ()));
                json_object_set_new (json_serialization, "tag", json_string (b64_tag.c_str ()));

                char* contents = json_dumps (json_serialization, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    output = contents;
                    free (contents);
                } else {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
            }
            __finally2
            {
                if (json_serialization) {
                    json_decref (json_serialization);
                }
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing_encryption::update_header (std::string const& source_encoded, binary_t const& tag, binary_t& aad, std::string& output_encoded)
{
    return_t ret = errorcode_t::success;
    json_t* json_header = nullptr;

    output_encoded.clear ();

    /* compact, flattened */
    // protected_header
    json_open_stream (&json_header, source_encoded.c_str ());
    if (json_header) {
        const char* alg_value = nullptr;
        const char* tag_value = nullptr;
        json_unpack (json_header, "{s:s}", "alg", &alg_value);
        json_unpack (json_header, "{s:s}", "tag", &tag_value);
        if (alg_value) {
            if ((nullptr == tag_value) || (tag_value && (0 == strlen (tag_value)))) {
                std::string tag_encoded;
                tag_encoded = base64_encode (&tag[0], tag.size (), base64_encoding_t::base64url_encoding);

                json_object_set_new (json_header, "tag", json_string (tag_encoded.c_str ()));
                char* contents = json_dumps (json_header, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    std::string header = contents;
                    base64_encode ((byte_t*) header.c_str (), header.size (), aad, base64_encoding_t::base64url_encoding);  // update for encryption
                    output_encoded = header;                                                                                // update for JWE.output
                    free (contents);
                }
            }
        }
        json_decref (json_header);
    }
    return ret;
}

return_t json_object_signing_encryption::parse_signature_header (jose_context_t* context, const char* header, jws_t& sig, std::string& keyid)
{
    return_t ret = errorcode_t::success;
    //jose_context_t* handle = static_cast <jose_context_t*> (context);
    json_t* json_root = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        sig = jws_t::jws_unknown;
        keyid.clear ();

        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = json_open_stream (&json_root, header, true);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        const char* alg = nullptr;
        const char* kid = nullptr;
        json_unpack (json_root, "{s:s}", "alg", &alg);
        json_unpack (json_root, "{s:s}", "kid", &kid);

        advisor->typeof_jose_signature (alg, sig);
        if (kid) {
            keyid = kid;
        }
    }
    __finally2
    {
        if (json_root) {
            json_decref (json_root);
        }
    }
    return ret;
}

return_t json_object_signing_encryption::read_signature (jose_context_t* context, const char* signature)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);
    json_t* json_root = nullptr;
    split_context_t* split_handle = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == signature) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->signs.clear ();

        return_t ret_test = json_open_stream (&json_root, signature, true);
        if (errorcode_t::success == ret_test) {
            const char* payload_value = nullptr; /* payload:base64_url_encode(claims) */
            json_unpack (json_root, "{s:s}", "payload", &payload_value);
            if (nullptr == payload_value) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            json_t* json_signatures = nullptr;
            json_unpack (json_root, "{s:o}", "signatures", &json_signatures);
            if (json_signatures) {
                // 7.2.1.  General JWS JSON Serialization Syntax

                if (json_is_array (json_signatures)) {
                    size_t array_size = json_array_size (json_signatures);
                    if (0 == array_size) {
                        ret = errorcode_t::bad_data;
                        __leave2;
                    }

                    for (size_t index = 0; index < array_size; index++) {
                        json_t* json_signature = json_array_get (json_signatures, index);

                        jws_t sig = jws_t::jws_unknown;
                        const char* protected_value = nullptr;  /* protected:base64_url_encode(header) */
                        const char* kid_value = nullptr;        /* header:{kid:kid_value} */
                        const char* alg_value = nullptr;        /* header:{alg:alg_value} */
                        const char* signature_value = nullptr;  /* signature:base64_url_encode(signature) */
                        json_unpack (json_signature, "{s:s}", "protected", &protected_value);
                        json_unpack (json_signature, "{s:s}", "signature", &signature_value);
                        json_unpack (json_signature, "{s:{s:s}}", "header", "kid", &kid_value);
                        if (nullptr == signature_value) {
                            ret = errorcode_t::bad_data;
                            break;
                        }
                        if (nullptr == protected_value) {
                            // RFC 7520 4.7. Protecting Content Only
                            json_unpack (json_signature, "{s:{s:s}}", "header", "alg", &alg_value);
                            if (nullptr == alg_value) {
                                ret = errorcode_t::bad_data;
                                break;
                            } else {
                                advisor->typeof_jose_signature (alg_value, sig);
                            }
                        }

                        jose_sign_t item;
                        if (protected_value) {
                            item.header = protected_value;
                        }
                        item.payload = payload_value;
                        item.signature = signature_value;
                        if (kid_value) {
                            item.kid = kid_value;
                        }
                        item.sig = sig;
                        handle->signs.push_back (item);

                    }
                } else {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
            } else {
                // 7.2.2.  Flattened JWS JSON Serialization Syntax

                jws_t sig = jws_t::jws_unknown;
                const char* protected_value = nullptr;  /* protected:base64_url_encode(header) */
                const char* kid_value = nullptr;        /* header:{kid:kid_value} */
                const char* alg_value = nullptr;        /* header:{alg:alg_value} */
                const char* signature_value = nullptr;  /* signature:base64_url_encode(signature) */
                json_unpack (json_root, "{s:s}", "protected", &protected_value);
                json_unpack (json_root, "{s:s}", "signature", &signature_value);
                json_unpack (json_root, "{s:{s:s}}", "header", "kid", &kid_value);
                if (nullptr == signature_value) {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
                if (nullptr == protected_value) {
                    json_unpack (json_root, "{s:{s:s}}", "header", "alg", &alg_value);
                    if (nullptr == kid_value) {
                        ret = errorcode_t::bad_data;
                        break;
                    } else {
                        advisor->typeof_jose_signature (alg_value, sig);
                    }
                }

                jose_sign_t item;
                if (protected_value) {
                    item.header = protected_value;
                }
                item.payload = payload_value;
                item.signature = signature_value;
                if (kid_value) {
                    item.kid = kid_value;
                }
                item.sig = sig;
                handle->signs.push_back (item);

            }
        } else {
            size_t count = 0;
            split_begin (&split_handle, signature, ".");
            split_count (split_handle, count);
            switch (count) {
                case 3: break;
                case 2: ret = errorcode_t::low_security; break;  // not support low security reason - "alg":"none"
                default: ret = errorcode_t::bad_data; break;
            }
            jose_sign_t item;
            split_get (split_handle, 0, item.header);
            split_get (split_handle, 1, item.payload);
            split_get (split_handle, 2, item.signature);
            handle->signs.push_back (item);
        }

        if (handle->signs.empty ()) {
            ret = errorcode_t::bad_data;
            __leave2;
        }
    }
    __finally2
    {
        if (json_root) {
            json_decref (json_root);
        }
        if (split_handle) {
            split_end (split_handle);
        }
    }
    return ret;
}

return_t json_object_signing_encryption::write_signature (jose_context_t* context, std::string& signature, jose_serialization_t type)
{
    return_t ret = errorcode_t::success;
    jose_context_t* handle = static_cast <jose_context_t*> (context);

    __try2
    {
        signature.clear ();

        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (handle->signs.empty ()) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        jose_sign_t item = handle->signs.front ();

        if (jose_serialization_t::jose_compact == type) {
            signature = format ("%s.%s.%s", item.header.c_str (), item.payload.c_str (), item.signature.c_str ());
        } else if (jose_serialization_t::jose_flatjson == type) {
            json_t* json_serialization = nullptr;
            __try2
            {
                json_serialization = json_object ();
                if (nullptr == json_serialization) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_object_set_new (json_serialization, "payload", json_string (item.payload.c_str ()));
                json_object_set_new (json_serialization, "protected", json_string (item.header.c_str ()));
                if (false == item.kid.empty ()) {
                    json_object_set_new (json_serialization, "header", json_pack ("{s,s}", "kid", item.kid.c_str ()));
                }
                json_object_set_new (json_serialization, "signature", json_string (item.signature.c_str ()));
                char* contents = json_dumps (json_serialization, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    signature = contents;
                    free (contents);
                } else {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
            }
            __finally2
            {
                if (json_serialization) {
                    json_decref (json_serialization);
                }
            }
        } else if (jose_serialization_t::jose_json == type) {
            json_t* json_serialization = nullptr;
            json_t* json_signatures = nullptr;
            json_t* json_signature = nullptr;
            __try2
            {
                json_serialization = json_object ();
                if (nullptr == json_serialization) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_signatures = json_array ();
                if (nullptr == json_signatures) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }

                json_object_set_new (json_serialization, "payload", json_string (item.payload.c_str ()));
                for (jose_signs_t::iterator iter = handle->signs.begin (); iter != handle->signs.end (); iter++) {
                    jose_sign_t item = *iter;

                    json_signature = json_object ();
                    if (json_signature) {
                        json_object_set_new (json_signature, "protected", json_string (item.header.c_str ()));
                        if (false == item.kid.empty ()) {
                            json_object_set_new (json_signature, "header", json_pack ("{s,s}", "kid", item.kid.c_str ()));
                        }
                        json_object_set_new (json_signature, "signature", json_string (item.signature.c_str ()));
                        json_array_append_new (json_signatures, json_signature);
                    }
                }
                json_object_set_new (json_serialization, "signatures", json_signatures);
                char* contents = json_dumps (json_serialization, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    signature = contents;
                    free (contents);
                } else {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
            }
            __finally2
            {
                if (json_serialization) {
                    json_decref (json_serialization);
                }
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
