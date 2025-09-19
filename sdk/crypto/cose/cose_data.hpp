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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_COSEDATA__
#define __HOTPLACE_SDK_CRYPTO_COSE_COSEDATA__

#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/crypto/cose/types.hpp>
#include <hotplace/sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace crypto {

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

}  // namespace crypto
}  // namespace hotplace

#endif
