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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_TYPES__
#define __HOTPLACE_SDK_CRYPTO_COSE_TYPES__

#include <sdk/base.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/types.hpp>
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_encode.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>
#include <sdk/io/cbor/concise_binary_object_representation.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

typedef struct _cose_context_t cose_context_t;
// typedef struct _cose_structure_t cose_structure_t;

enum cose_param_t {
    cose_external = 1,
    cose_unsent_apu_id = 2,
    cose_unsent_apu_nonce = 3,
    cose_unsent_apu_other = 4,
    cose_unsent_apv_id = 5,
    cose_unsent_apv_nonce = 6,
    cose_unsent_apv_other = 7,
    cose_unsent_pub_other = 8,
    cose_unsent_priv_other = 9,
    cose_unsent_iv = 10,
    cose_unsent_alg = 11,

    cose_param_aad = 13,
    cose_param_cek = 14,
    cose_param_context = 15,
    cose_param_iv = 16,
    cose_param_kek = 17,
    cose_param_salt = 18,
    cose_param_secret = 19,
    cose_param_tobesigned = 20,
    cose_param_tomac = 21,
    cose_param_apu_id = 22,
    cose_param_apu_nonce = 23,
    cose_param_apu_other = 24,
    cose_param_apv_id = 25,
    cose_param_apv_nonce = 26,
    cose_param_apv_other = 27,
    cose_param_pub_other = 28,
    cose_param_priv_other = 29,
};

enum cose_flag_t {
    cose_flag_allow_debug = (1 << 1),
    cose_flag_auto_keygen = (1 << 2),

    // debug
    cose_debug_notfound_key = (1 << 16),
    cose_debug_partial_iv = (1 << 17),
};

typedef std::list<int> cose_orderlist_t;
typedef std::map<cose_param_t, binary_t> cose_binarymap_t;
typedef std::map<int, variant_t> cose_variantmap_t;

static inline void cose_variantmap_copy(cose_variantmap_t& target, cose_variantmap_t& source) {
    variant_t vt;
    cose_variantmap_t::iterator map_iter;
    for (map_iter = source.begin(); map_iter != source.end(); map_iter++) {
        int key = map_iter->first;
        variant_t& value = map_iter->second;
        variant_copy(vt, value);
        target.insert(std::make_pair(key, vt));
    }
}

static inline void cose_variantmap_move(cose_variantmap_t& target, cose_variantmap_t& source) {
    variant_t vt;
    cose_variantmap_t::iterator map_iter;
    for (map_iter = source.begin(); map_iter != source.end(); map_iter++) {
        int key = map_iter->first;
        variant_t& value = map_iter->second;
        variant_move(vt, value);
        target.insert(std::make_pair(key, vt));
    }
    source.clear();
}

static inline void cose_variantmap_free(cose_variantmap_t& map) {
    cose_variantmap_t::iterator map_iter;
    for (map_iter = map.begin(); map_iter != map.end(); map_iter++) {
        variant_t& value = map_iter->second;
        variant_free(value);
    }
    map.clear();
}

class cose_structure_t {
    friend class cbor_object_encryption;
    friend class cbor_object_signing;
    friend class cbor_object_signing_encryption;

   public:
    cose_structure_t() : parent(nullptr), alg(cose_alg_t::cose_unknown), epk(nullptr){};

    ~cose_structure_t() { clear(); }

    void add(cose_structure_t* child) {
        child->parent = this;
        multiitems.push_back(child);
    }

    void clearall() {
        clear();
        binarymap.clear();
    }

    void clear() {
        parent = nullptr;
        bin_protected.clear();
        bin_payload.clear();
        singleitem.clear();
        std::list<cose_structure_t*>::iterator iter;
        for (iter = multiitems.begin(); iter != multiitems.end(); iter++) {
            cose_structure_t* item = *iter;
            delete item;
        }
        multiitems.clear();

        alg = cose_alg_t::cose_unknown;
        kid.clear();

        cose_variantmap_free(protected_map);
        cose_variantmap_free(unprotected_map);
        protected_list.clear();
        unprotected_list.clear();
        key.clear();
        if (epk) {
            EVP_PKEY_free((EVP_PKEY*)epk);
            epk = nullptr;
        }
    }

   private:
    cose_structure_t* parent;
    binary_t bin_protected;  // protected
    binary_t bin_payload;
    binary_t singleitem;                      // signature, tag, ...
    std::list<cose_structure_t*> multiitems;  // [+recipient], [+signature]

    cose_alg_t alg;
    std::string kid;
    cose_variantmap_t protected_map;
    cose_variantmap_t unprotected_map;
    cose_orderlist_t protected_list;
    cose_orderlist_t unprotected_list;
    cose_binarymap_t binarymap;
    crypto_key key;        // encryption
    crypto_key ephemeral;  // ephemeral
    const EVP_PKEY* epk;
};

struct _cose_context_t {
    cbor_tag_t cbor_tag;

    uint32 flags;
    uint32 debug_flags;
    basic_stream debug_stream;

    // restructuring in progress
    // cose_composer* composer;
    // cose_unsent* unsent;

    // to be deprecated
    cose_structure_t body;
    cose_binarymap_t binarymap;  // external, unsent, cek, kek, context, aad, secret, tobesigned/tomac

    _cose_context_t() : cbor_tag(cbor_tag_t::cbor_tag_unknown), flags(0), debug_flags(0) {
        // composer = new cose_composer;
    }
    ~_cose_context_t() {
        clearall();
        // delete composer;
    }
    void clearall() {
        clear();
        flags = 0;
        debug_flags = 0;
        debug_stream.clear();
    }
    void clear() {
        cbor_tag = cbor_tag_t::cbor_tag_unknown;
        body.clear();
    }
};

}  // namespace crypto
}  // namespace hotplace

#endif
