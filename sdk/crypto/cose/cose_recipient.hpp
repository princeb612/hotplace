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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_COSERECIPIENT__
#define __HOTPLACE_SDK_CRYPTO_COSE_COSERECIPIENT__

#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/crypto/cose/cose_binary.hpp>
#include <hotplace/sdk/crypto/cose/cose_data.hpp>
#include <hotplace/sdk/crypto/cose/cose_protected.hpp>
#include <hotplace/sdk/crypto/cose/cose_recipients.hpp>
#include <hotplace/sdk/crypto/cose/cose_unprotected.hpp>
#include <hotplace/sdk/crypto/cose/types.hpp>
#include <hotplace/sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace crypto {

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

}  // namespace crypto
}  // namespace hotplace

#endif
