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

#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/cose/types.hpp>
#include <sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace crypto {

enum cose_message_type_t {
    cose_message_unknown = 0,
    cose_message_protected = 1,
    cose_message_unprotected = 2,
    cose_message_payload = 3,
    cose_message_singleitem = 4,
    cose_message_layered = 5,  // recipients, signatures
};

enum cose_scope {
    cose_scope_protected = (1 << 0),
    cose_scope_unprotected = (1 << 1),
    cose_scope_unsent = (1 << 2),
    cose_scope_params = (1 << 3),
    cose_scope_layer = 0x1111,
    cose_scope_children = (1 << 4),
    cose_scope_all = 0x11111111,
};

class cose_data {
    friend class cose_protected;
    friend class cose_unprotected;
    friend class cose_binary;
    friend class cose_recipient;
    friend class cose_recipients;

   public:
    cose_data();
    ~cose_data();

    /**
     * @brief key/value
     */
    cose_data& add_bool(int key, bool value);
    cose_data& add(int key, int32 value);
    cose_data& add(int key, const char* value);
    cose_data& add(int key, const unsigned char* value, size_t size);
    cose_data& add(int key, std::string& value);
    cose_data& add(int key, const std::string& value);
    cose_data& add(int key, binary_t& value);
    cose_data& add(int key, const binary_t& value);
    cose_data& add(int key, variant& value);

    cose_data& replace(int key, const unsigned char* value, size_t size);
    cose_data& replace(int key, const binary_t& value);

    /**
     * @brief ephemeral/static key
     */
    cose_data& add(int key, uint16 curve, const binary_t& x, const binary_t& y);
    cose_data& add(int key, uint16 curve, const binary_t& x, bool ysign);
    cose_data& add(int key, uint16 curve, const binary_t& x, const binary_t& y, std::list<int>& order);
    cose_data& add(int key, uint16 curve, const binary_t& x, bool ysign, std::list<int>& order);
    /**
     * @brief counter signature
     */
    cose_data& add(cose_alg_t alg, const char* kid, const binary_t& signature);
    cose_data& add(cose_recipient* countersig);
    cose_data& add(int key, vartype_t vty, void* p);
    /**
     * @brief payload (binary/base16)
     */
    cose_data& set(const binary_t& value);
    cose_data& set(const std::string& value);
    cose_data& set_b16(std::string const value);
    cose_data& set_b16(const char* value);
    /**
     * @brief clear
     */
    cose_data& clear();

    /**
     * @brief   find
     */
    bool exist(int key);
    /**
     * @brief   find
     * @return  error code (see error.hpp)
     */
    return_t finditem(int key, int& value);
    /**
     * @brief   find
     * @return  error code (see error.hpp)
     */
    return_t finditem(int key, std::string& value);
    /**
     * @brief   find
     * @return  error code (see error.hpp)
     */
    return_t finditem(int key, binary_t& value);

   protected:
    cose_data& set_owner(cose_recipient* layer);
    cose_recipient* get_owner();

    /**
     * @brief   cbor_data for protected
     * @return  error code (see error.hpp)
     * @desc    cose_variantmap_t to cbor_data* and _payload
     */
    return_t build_protected(cbor_data** object);
    return_t build_protected(cbor_data** object, cose_variantmap_t& unsent);
    /**
     * @brief   cbor_map for unprotected
     * @return  error code (see error.hpp)
     */
    return_t build_unprotected(cbor_map** object);
    return_t build_unprotected(cbor_map** object, cose_variantmap_t& unsent);
    /**
     * @brief   cbor_data for payload
     * @return  error code (see error.hpp)
     */
    return_t build_data(cbor_data** object);
    /**
     * @brief   parse
     */
    return_t parse_protected(cbor_data* object);
    return_t parse_unprotected(cbor_map* object);
    return_t parse_payload(cbor_data* object);
    return_t parse(cbor_map* object);
    /**
     * @brief ephemeral-static, static-static
     */
    return_t parse_static_key(cbor_map* object, int keyid);
    return_t parse_counter_signs(cbor_array* object, int keyid);

    bool empty_binary();
    size_t size_binary();
    void get_binary(binary_t& bin);

    class cose_key {
       public:
        cose_key();
        void set(crypto_key* key, uint16 curve, const binary_t& x, const binary_t& y);
        void set(crypto_key* key, uint16 curve, const binary_t& x, bool ysign);
        void set(cose_orderlist_t& order);
        cbor_map* cbor();

       private:
        uint16 _curve;
        binary_t _x;
        binary_t _y;
        bool _ysign;
        bool _compressed;
        cose_orderlist_t _order;
    };

   private:
    cose_variantmap_t _data_map;
    cose_orderlist_t _order;
    binary_t _payload;
    cose_recipient* _layer;
    std::list<cose_key*> _keys;
};

/**
 * @brief protected
 */
class cose_protected {
    friend class cose_composer;
    friend class cose_data;
    friend class cose_recipient;

   public:
    cose_protected();
    ~cose_protected();

    /**
     * @brief add
     */
    cose_protected& add(cose_key_t key, uint32 value);
    /**
     * @brief set
     */
    cose_protected& set(const binary_t& bin);
    /**
     * @brief data
     */
    cose_data& data();
    /**
     * @brief clear
     */
    cose_protected& clear();
    /**
     * @brief cbor
     */
    cbor_data* cbor();

   protected:
    /**
     * @brief set
     */
    return_t set(cbor_data* object);

   private:
    cose_data _protected;
};

/**
 * @brief unprotected
 */
class cose_unprotected {
    friend class cose_composer;
    friend class cose_data;
    friend class cose_recipient;

   public:
    cose_unprotected();
    ~cose_unprotected();

    /**
     * @brief add
     */
    cose_unprotected& add(cose_key_t key, int32 value);
    cose_unprotected& add(cose_key_t key, const char* value);
    cose_unprotected& add(cose_key_t key, std::string& value);
    cose_unprotected& add(cose_key_t key, const std::string& value);
    cose_unprotected& add(cose_key_t key, binary_t& value);
    cose_unprotected& add(cose_key_t key, const binary_t& value);
    /**
     * @brief ephemeral key
     * @param cose_key_t key [in] cose_key_t::cose_ephemeral_key
     * @param uint16 curve [in]
     * @param const binary_t& x [in]
     * @param const binary_t& y [in]
     */
    cose_unprotected& add(cose_key_t key, uint16 curve, const binary_t& x, const binary_t& y);
    cose_unprotected& add(cose_key_t key, uint16 curve, const binary_t& x, bool ysign);
    /**
     * @brief counter signature
     */
    cose_unprotected& add(cose_alg_t alg, const char* kid, const binary_t& signature);
    /**
     * @brief data
     */
    cose_data& data();
    /**
     * @brief clear
     */
    cose_unprotected& clear();
    /**
     * @brief cbor
     */
    cbor_map* cbor();

   protected:
    /**
     * @brief set
     */
    return_t set(cbor_map* object);

   private:
    cose_data _unprotected;
};

/**
 * @brief signature, ciphertext, tag
 */
class cose_binary {
    friend class cose_composer;
    friend class cose_data;
    friend class cose_recipient;

   public:
    cose_binary();

    /**
     * @brief set
     */
    cose_binary& set_b16(const char* value);
    cose_binary& set_b16(const std::string& value);
    cose_binary& set(const std::string& value);
    cose_binary& set(const binary_t& value);
    /**
     * @brief data
     */
    cose_data& data();
    /**
     * @brief empty, size
     */
    bool empty();
    size_t size();
    void get(binary_t& bin);
    /**
     * @brief clear
     */
    cose_binary& clear();
    /**
     * @brief cbor
     */
    cbor_data* cbor();

   protected:
    /**
     * @brief set
     */
    return_t set(cbor_data* object);

   private:
    cose_data _payload;
};

/**
 * @brief recipients, signatures
 */
class cose_recipients {
    friend class cose_composer;
    friend class cose_data;
    friend class cose_recipient;

   public:
    cose_recipients();
    virtual ~cose_recipients();

    /**
     * @brief add
     */
    cose_recipient& add(cose_recipient* recipient);
    /**
     * @brief clear
     */
    cose_recipients& clear();

    bool empty();
    size_t size();
    cose_recipient* operator[](size_t index);

    virtual cbor_array* cbor();

    return_t finditem(int key, int& value, int scope = cose_scope_layer);
    return_t finditem(int key, std::string& value, int scope = cose_scope_layer);
    return_t finditem(int key, binary_t& value, int scope = cose_scope_layer);

   protected:
    void for_each(void (*for_each_handler)(cose_recipient*, void* userdata), void* userdata);
    cose_recipients& set_upperlayer(cose_recipient* layer);
    cose_recipient* get_upperlayer();
    std::list<cose_recipient*>& get_recipients();
    const std::list<cose_recipient*>& get_recipients() const;

   private:
    std::list<cose_recipient*> _recipients;
    cose_recipient* _upperlayer;
};

enum cose_property_t {
    cose_property_normal = 0,
    cose_property_countersign = 1,
};

class cose_recipient {
    friend class cose_composer;
    friend class cose_data;

   public:
    cose_recipient();
    virtual ~cose_recipient();

    /**
     * @brief add
     */
    cose_recipient& add(cose_recipient* recipient = nullptr);
    /**
     * @brief get
     */
    cose_protected& get_protected();
    cose_unprotected& get_unprotected();
    cose_binary& get_payload();
    cose_binary& get_singleitem();
    cose_binary& get_signature();
    cose_binary& get_tag();
    cose_recipients& get_recipients();
    cose_data& get_params();
    crypto_key& get_static_key();
    cose_countersigns* get_countersigns0();
    cose_countersigns* get_countersigns1();
    /**
     * @brief clear
     */
    cose_recipient& clear();
    /**
     * @brief cbor
     */
    virtual cbor_array* cbor();

    void set_upperlayer(cose_recipient* layer);
    cose_recipient* get_upperlayer();
    cose_recipient* get_upperlayer2();
    uint16 get_depth();
    void set_composer(cose_composer* composer);
    cose_composer* get_composer();
    cose_recipient& set_property(uint16 property);
    uint16 get_property();

    return_t finditem(int key, int& value, int scope = cose_scope_layer);
    return_t finditem(int key, std::string& value, int scope = cose_scope_layer);
    return_t finditem(int key, binary_t& value, int scope = cose_scope_layer);

    return_t setparam(cose_param_t id, const binary_t& bin);
    return_t getparam(cose_param_t id, binary_t& bin);

    cose_alg_t get_algorithm();
    std::string get_kid();
    void for_each(void (*for_each_handler)(cose_recipient*, void* userdata), void* userdata);

   protected:
    return_t parse(cbor_array* root);
    return_t parse_header(cbor_array* root);
    return_t parse_message(cbor_array* root);

    return_t parse_protected(cbor_object* object);
    return_t parse_unprotected(cbor_object* object);
    return_t parse_payload(cbor_object* object);
    return_t parse_singleitem(cbor_object* object);

   private:
    cose_protected _protected;
    cose_unprotected _unprotected;
    cose_binary _payload;
    cose_binary _singleitem;
    cose_recipients _recipients;
    cose_countersigns* _countersigns;
    crypto_key _static_key;
    cose_data _params;

    cose_recipient* _upperlayer;
    uint16 _depth;
    uint16 _property;
    cose_composer* _composer;
    cbor_tag_t _cbor_tag;
};

class cose_unsent {
    friend class cose_recipient;

   public:
    cose_unsent();
    ~cose_unsent();

    cose_unsent& add(int key, const char* value);
    cose_unsent& add(int key, const unsigned char* value, size_t size);
    cose_unsent& add(int key, binary_t& value);
    cose_unsent& add(int key, const binary_t& value);

    cose_data& data();

   protected:
    bool isvalid(int key);

   private:
    cose_data _unsent;
};

class cose_countersign : public cose_recipient {
   public:
    cose_countersign() : cose_recipient() {}
    virtual ~cose_countersign() {}

    virtual cbor_array* cbor() {
        cbor_array* object = new cbor_array;
        *object << get_protected().cbor() << get_unprotected().cbor() << get_signature().cbor();
        return object;
    }

   protected:
};

class cose_countersigns : public cose_recipients {
   public:
    cose_countersigns() : cose_recipients() {}
    virtual ~cose_countersigns() {}

    virtual cbor_array* cbor() {
        cbor_array* object = nullptr;
        return_t ret = errorcode_t::success;
        __try2 {
            size_t size_countersigns = size();
            const auto& recipients = get_recipients();
            if (size_countersigns > 1) {
                __try_new_catch(object, new cbor_array, ret, __leave2);

                for (cose_recipient* sign : recipients) {
                    *object << sign->cbor();  // array in array
                }
            } else if (size_countersigns == 1) {
                object = recipients.front()->cbor();  // array
            }
        }
        __finally2 {
            // do nothing
        }
        return object;
    }
};

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
