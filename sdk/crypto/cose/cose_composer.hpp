/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_COSECOMPOSER__
#define __HOTPLACE_SDK_CRYPTO_COSE_COSECOMPOSER__

#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/cose/cose_binary.hpp>
#include <sdk/crypto/cose/cose_protected.hpp>
#include <sdk/crypto/cose/cose_recipient.hpp>
#include <sdk/crypto/cose/cose_recipients.hpp>
#include <sdk/crypto/cose/cose_unprotected.hpp>
#include <sdk/crypto/cose/cose_unsent.hpp>
#include <sdk/crypto/cose/types.hpp>
#include <sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief composer
 */
class cose_composer {
    friend class cbor_object_signing_encryption;

   public:
    cose_composer();

    /**
     * @brief   compose
     * @desc
     *          // interface sketch
     *          cbor_array* root = nullptr;
     *          cose_composer composer;
     *          composer.get_payload().set("This is the content.");
     *
     *          cose_recipient& signature = composer.get_recipients().add(new cose_recipient);
     *          signature.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
     *          signature.get_unprotected().add(cose_key_t::cose_kid, "11");
     *          signature.get_payload().set_b16("e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a");
     *          composer.compose(&root, true); // true for tagged message , false for untagged message
     *          // ...
     *          root->release();
     */
    return_t compose(cbor_array** object, bool tagged = true);
    return_t compose(cbor_array** object, binary_t& cbor, bool tagged = true);
    return_t diagnose(cbor_array** object, basic_stream& stream, bool tagged = true);
    /**
     * @brief   parse
     * @desc
     *          // interface sketch
     *          cose_composer composer;
     *          composer.parse(cbor);
     *          composer.compose(&root);
     */
    return_t parse(const binary_t& input);
    /**
     * @brief get
     * @desc
     *                      protected  unprotected      payload     singleitem/multiitems
     *                      [0]        [1]              [2]         [3]             [4]
     * cose_tag_encrypt     protected, unprotected_map, ciphertext, [+recipient]
     * cose_tag_encrypt0    protected, unprotected_map, ciphertext
     * cose_tag_mac         protected, unprotected_map, payload,    tag,            [+recipient]
     * cose_tag_mac0        protected, unprotected_map, payload,    tag
     * cose_tag_sign        protected, unprotected_map, payload,    [+signature]
     * cose_tag_sign1       protected, unprotected_map, payload,    signature
     */
    cose_protected& get_protected();
    cose_unprotected& get_unprotected();
    cose_binary& get_payload();
    /**
     * @brief tag/signature
     * @desc syn. get_singleitem
     */
    cose_binary& get_tag();
    cose_binary& get_signature();
    cose_binary& get_singleitem();
    /**
     * @brief signatures/recipients
     */
    cose_recipients& get_recipients();

    cose_layer& get_layer();
    cose_unsent& get_unsent();
    cbor_tag_t get_cbor_tag();

   protected:
    void clear();
    // return_t compose_enc_structure(binary_t& authenticated_data);

   private:
    cbor_tag_t _cbor_tag;

    // cose_protected _protected;
    // cose_unprotected _unprotected;
    // cose_binary _payload;
    // cose_binary _singleitem;
    // cose_recipients _recipients;
    cose_layer _layer;
    cose_unsent _unsent;
};

}  // namespace crypto
}  // namespace hotplace

#endif
