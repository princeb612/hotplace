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

#include <sdk/base.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/cose/cbor_object_signing_encryption.hpp>
#include <sdk/crypto/cose/types.hpp>
#include <sdk/crypto/types.hpp>
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_encode.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>
#include <sdk/io/cbor/concise_binary_object_representation.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief protected
 */
class cose_protected {
   public:
    cose_protected();
    ~cose_protected();

    /**
     * @brief add
     */
    cose_protected& add(cose_key_t key, uint16 value);
    /**
     * @brief set
     */
    cose_protected& set(binary_t const& bin);
    /**
     * @brief cbor
     */
    cbor_data* cbor();

   private:
    cose_variantmap_t _protected_map;
    binary_t _bin;
};

/**
 * @brief unprotected
 */
class cose_unprotected {
   public:
    cose_unprotected();
    ~cose_unprotected();

    /**
     * @brief add
     */
    cose_unprotected& add(cose_key_t key, uint16 value);
    cose_unprotected& add(cose_key_t key, const char* value);
    cose_unprotected& add(cose_key_t key, std::string const& value);
    cose_unprotected& add(cose_key_t key, binary_t const& value);
    /**
     * @brief ephemeral key
     */
    cose_unprotected& add(cose_key_t key, uint16 curve, binary_t const& x, binary_t const& y);
    cose_unprotected& add(cose_key_t key, uint16 curve, binary_t const& x, bool ysign);
    /**
     * @brief counter signature
     */
    cose_unprotected& add(cose_alg_t alg, const char* kid, binary_t const& signature);
    /**
     * @brief cbor
     */
    cbor_map* cbor();
    cose_orderlist_t& get_order();

   private:
    cose_variantmap_t _unprotected_map;
    cose_orderlist_t _order;
};

/**
 * @brief signature, ciphertext, tag
 */
class cose_binary {
   public:
    cose_binary();

    /**
     * @brief set
     */
    cose_binary& set_b16(const char* value);
    cose_binary& set_b16(std::string const& value);
    cose_binary& set(std::string const& value);
    cose_binary& set(binary_t const& value);
    /**
     * @brief cbor
     */
    cbor_data* cbor();

   private:
    binary_t payload;
};

/**
 * @brief recipient, signature
 */
class cose_recipient {
   public:
    cose_recipient();

    /**
     * @brief get
     */
    cose_protected& get_protected();
    cose_unprotected& get_unprotected();
    cose_binary& get_payload();
    /**
     * @brief cbor
     */
    cbor_array* cbor();

   private:
    cose_protected _protected;
    cose_unprotected _unprotected;
    cose_binary _payload;
};

/**
 * @brief recipients, signatures
 */
class cose_recipients {
   public:
    cose_recipients();

    cose_recipient& add(cose_recipient* recipient);
    bool empty();
    cbor_array* cbor();

   private:
    std::list<cose_recipient*> recipients;
};

/**
 * @brief composer
 */
class cbor_object_signing_encryption_composer {
   public:
    cbor_object_signing_encryption_composer();

    class composer {
       public:
        composer();
        /**
         * @brief   cbor_data for protected
         * @return  error code (see error.hpp)
         */
        return_t build_protected(cbor_data** object);
        return_t build_protected(cbor_data** object, cose_variantmap_t& input);
        return_t build_protected(cbor_data** object, cose_variantmap_t& input, cose_orderlist_t& order);
        return_t build_protected(cbor_data** object, cbor_map* input);
        /**
         * @brief   cbor_map for unprotected
         * @return  error code (see error.hpp)
         */
        return_t build_unprotected(cbor_map** object);
        return_t build_unprotected(cbor_map** object, cose_variantmap_t& input);
        return_t build_unprotected(cbor_map** object, cose_variantmap_t& input, cose_orderlist_t& order);
        /**
         * @brief   cbor_data for payload
         * @return  error code (see error.hpp)
         */
        return_t build_data(cbor_data** object, const char* payload);
        return_t build_data(cbor_data** object, const byte_t* payload, size_t size);
        return_t build_data(cbor_data** object, binary_t const& payload);
        return_t build_data_b16(cbor_data** object, const char* str);
    };

    /**
     * @brief   compose
     * @desc
     *          // interface sketch
     *          cbor_array* root = nullptr;
     *          cose_structure_t builder;
     *          builder.get_payload().set("This is the content.");
     *
     *          cose_recipient& signature = builder.get_recipients().add(new cose_recipient);
     *          signature.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
     *          signature.get_unprotected().add(cose_key_t::cose_kid, "11");
     *          signature.get_payload().set_b16("e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a");
     *          builder.compose(cbor_tag_t::cose_tag_sign, &root);
     *          // ...
     *          root->release();
     */
    return_t compose(cbor_tag_t cbor_tag, cbor_array** node);

    /**
     * @brief get
     */
    cose_protected& get_protected();
    cose_unprotected& get_unprotected();
    cose_binary& get_payload();
    cose_binary& get_tag();
    cose_binary& get_singleitem();
    cose_recipients& get_recipients();

   private:
    cose_protected _protected;
    cose_unprotected _unprotected;
    cose_binary _payload;
    cose_binary _tag;
    cose_binary _singleitem;
    cose_recipients _recipients;
};

}  // namespace crypto
}  // namespace hotplace

#endif
