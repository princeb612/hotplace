/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 8152 CBOR Object Signing and Encryption (COSE)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/cose/cbor_object_signing.hpp>
#include <sdk/crypto/cose/cbor_object_signing_encryption.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>

namespace hotplace {
namespace crypto {

cose_composer::cose_composer() : _cbor_tag(cbor_tag_t::cbor_tag_unknown) { get_layer().set_composer(this); }

return_t cose_composer::compose(cbor_array** object, bool tagged) {
    return_t ret = errorcode_t::success;

    // implementation sketch

    // read algorithm from protected or unprotected
    // sizeof_recipients = get_recipients().size()
    // switch(cose_group_t)
    //   case cose_group_sign_ecdsa:
    //   case cose_group_sign_eddsa:
    //   case cose_group_sign_rsassa_pss:
    //   case cose_group_sign_rsassa_pkcs15:
    //      if(sizeof_recipients) tag = cose_tag_sign;
    //      else tag = cose_tag_sign1;
    //   case cose_group_enc_aesgcm:
    //   case cose_group_enc_aesccm:
    //   case cose_group_enc_chacha20_poly1305:
    //      if(sizeof_recipients) tag = cose_tag_encrypt
    //      else tag = cose_tag_encrypt0;
    //   case cose_group_mac_hmac:
    //   case cose_group_mac_aes:
    //      if(sizeof_recipients) tag = cose_tag_mac
    //      else tag = cose_tag_mac0;

    //   then call compose(tag, object);

    cbor_array* root = nullptr;
    cbor_tag_t cbor_tag = cbor_tag_t::cbor_tag_unknown;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(root, new cbor_array, ret, __leave2);

        if (cbor_tag_t::cbor_tag_unknown != _cbor_tag) {
            cbor_tag = _cbor_tag;
        } else {
            crypto_advisor* advisor = crypto_advisor::get_instance();
            int alg = 0;
            get_layer().finditem(cose_key_t::cose_alg, alg, cose_scope_protected | cose_scope_unprotected | cose_scope_children);
            crypt_category_t category = advisor->categoryof((cose_alg_t)alg);
            size_t size_recipients = get_recipients().size();
            switch (category) {
                case crypt_category_t::crypt_category_crypt:
                    cbor_tag = size_recipients ? cose_tag_encrypt : cose_tag_encrypt0;
                    break;
                case crypt_category_t::crypt_category_mac:
                    cbor_tag = size_recipients ? cose_tag_mac : cose_tag_mac0;
                    break;
                case crypt_category_t::crypt_category_sign:
                    cbor_tag = size_recipients ? cose_tag_sign : cose_tag_sign1;
                    break;
                default:
                    break;
            }
        }

        *root << get_protected().cbor() << get_unprotected().cbor() << get_payload().cbor();
        if (tagged) {
            root->tag(cbor_tag);
        }

        if ((cbor_tag_t::cose_tag_mac == cbor_tag) || (cbor_tag_t::cose_tag_mac0 == cbor_tag) || (cbor_tag_t::cose_tag_sign1 == cbor_tag)) {
            *root << get_singleitem().cbor();
        }
        if ((cbor_tag_t::cose_tag_encrypt == cbor_tag) || (cbor_tag_t::cose_tag_sign == cbor_tag) || (cbor_tag_t::cose_tag_mac == cbor_tag)) {
            if (get_recipients().size()) {
                *root << get_recipients().cbor();
            }
        }

        *object = root;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t cose_composer::compose(cbor_array** object, binary_t& cbor, bool tagged) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = compose(object, tagged);
        if (errorcode_t::success == ret) {
            cbor_publisher publisher;
            publisher.publish(*object, &cbor);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_composer::diagnose(cbor_array** object, basic_stream& stream, bool tagged) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = compose(object, tagged);
        if (errorcode_t::success == ret) {
            cbor_publisher publisher;
            publisher.publish(*object, &stream);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cose_composer::parse(const binary_t& input) {
    return_t ret = errorcode_t::success;
    cbor_object* root = nullptr;
    cbor_array* cbor_message = nullptr;

    __try2 {
        clear();

        if (0 == input.size()) {
            __leave2;
        }

        // parse cbor
        ret = cbor_parse(&root, input);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // check
        cbor_array* cbor_message = cbor_typeof<cbor_array>(root, cbor_type_t::cbor_type_array);
        if (nullptr == cbor_message) {
            ret = errorcode_t::bad_format;
            __leave2;
        }
        if (cbor_message->tagged()) {
            _cbor_tag = cbor_message->tag_value();
        }

        // parse cose
        ret = get_layer().parse(cbor_message);
    }
    __finally2 {
        if (root) {
            root->release();
        }
    }
    return ret;
}

void cose_composer::clear() {
    get_protected().clear();
    get_unprotected().clear();
    get_payload().clear();
    get_singleitem().clear();
    get_recipients().clear();
}

cose_protected& cose_composer::get_protected() { return get_layer().get_protected(); }

cose_unprotected& cose_composer::get_unprotected() { return get_layer().get_unprotected(); }

cose_binary& cose_composer::get_payload() { return get_layer().get_payload(); }

cose_binary& cose_composer::get_tag() { return get_layer().get_singleitem(); }

cose_binary& cose_composer::get_signature() { return get_layer().get_singleitem(); }

cose_binary& cose_composer::get_singleitem() { return get_layer().get_singleitem(); }

cose_recipients& cose_composer::get_recipients() { return get_layer().get_recipients(); }

cose_layer& cose_composer::get_layer() { return _layer; }

cose_unsent& cose_composer::get_unsent() { return _unsent; }

cbor_tag_t cose_composer::get_cbor_tag() { return _cbor_tag; }

}  // namespace crypto
}  // namespace hotplace
