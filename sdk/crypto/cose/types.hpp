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

#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/types.hpp>
#include <sdk/io/cbor/cbor.hpp>
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_encode.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

typedef struct _cose_context_t cose_context_t;
// typedef struct _cose_structure_t cose_structure_t;

enum cose_param_t {
    cose_param_base = 0x1000,

    cose_external = cose_param_base + 1,
    cose_unsent_apu_id = cose_param_base + 2,
    cose_unsent_apu_nonce = cose_param_base + 3,
    cose_unsent_apu_other = cose_param_base + 4,
    cose_unsent_apv_id = cose_param_base + 5,
    cose_unsent_apv_nonce = cose_param_base + 6,
    cose_unsent_apv_other = cose_param_base + 7,
    cose_unsent_pub_other = cose_param_base + 8,
    cose_unsent_priv_other = cose_param_base + 9,
    cose_unsent_iv = cose_param_base + 10,
    cose_unsent_alg = cose_param_base + 11,

    cose_param_aad = cose_param_base + 13,
    cose_param_cek = cose_param_base + 14,
    cose_param_context = cose_param_base + 15,
    cose_param_iv = cose_param_base + 16,
    cose_param_kek = cose_param_base + 17,
    cose_param_salt = cose_param_base + 18,
    cose_param_secret = cose_param_base + 19,
    cose_param_tobesigned = cose_param_base + 20,
    cose_param_tomac = cose_param_base + 21,
    cose_param_apu_id = cose_param_base + 22,
    cose_param_apu_nonce = cose_param_base + 23,
    cose_param_apu_other = cose_param_base + 24,
    cose_param_apv_id = cose_param_base + 25,
    cose_param_apv_nonce = cose_param_base + 26,
    cose_param_apv_other = cose_param_base + 27,
    cose_param_pub_other = cose_param_base + 28,
    cose_param_priv_other = cose_param_base + 29,
    cose_param_ciphertext = cose_param_base + 30,
    cose_param_plaintext = cose_param_base + 31,
};

enum cose_flag_t {
    cose_flag_allow_debug = (1 << 1),
    cose_flag_auto_keygen = (1 << 2),

    // debug
    cose_debug_notfound_key = (1 << 16),
    cose_debug_partial_iv = (1 << 17),
    cose_debug_counter_sig = (1 << 18),
};

typedef std::list<int> cose_orderlist_t;
typedef std::map<cose_param_t, binary_t> cose_binarymap_t;
typedef std::map<int, variant> cose_variantmap_t;

class cose_composer;
struct _cose_context_t {
    uint32 flags;
    uint32 debug_flags;
    basic_stream debug_stream;

    // see cbor_object_signing_encryption::open() and close()
    cose_composer* composer;

    _cose_context_t() : flags(0), debug_flags(0) {}
    ~_cose_context_t() { clearall(); }
    void clearall() {
        clear();
        flags = 0;
        debug_flags = 0;
        debug_stream.clear();
    }
    void clear() {
        // do nothing
    }
};

class cose_binary;
class cose_composer;
class cose_countersign;
class cose_countersigns;
class cose_protected;
class cose_recipient;
class cose_recipients;
class cose_unprotected;
class cose_unsent;

class crypto_key;

typedef cose_recipient cose_layer;
typedef cose_recipients cose_layers;

}  // namespace crypto
}  // namespace hotplace

#endif
