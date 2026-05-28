/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_TYPES__
#define __HOTPLACE_SDK_CRYPTO_COSE_TYPES__

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/types.hpp>
#include <hotplace/sdk/io/cbor/cbor.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>

namespace hotplace {
namespace crypto {

enum cose_param_t : uint16 {
    cose_param_unknown = 0,

    cose_param_external,
    cose_param_unsent_apu_id,
    cose_param_unsent_apu_nonce,
    cose_param_unsent_apu_other,
    cose_param_unsent_apv_id,
    cose_param_unsent_apv_nonce,
    cose_param_unsent_apv_other,
    cose_param_unsent_pub_other,
    cose_param_unsent_priv_other,
    cose_param_unsent_iv,
    cose_param_unsent_alg,

    cose_param_aad,
    cose_param_cek,
    cose_param_context,
    cose_param_iv,
    cose_param_kek,
    cose_param_salt,
    cose_param_secret,
    cose_param_tobesigned,
    cose_param_tomac,
    cose_param_apu_id,
    cose_param_apu_nonce,
    cose_param_apu_other,
    cose_param_apv_id,
    cose_param_apv_nonce,
    cose_param_apv_other,
    cose_param_pub_other,
    cose_param_priv_other,
    cose_param_ciphertext,
    cose_param_plaintext,
};

enum cose_flag_t {
    auto_keygen = (1 << 2),

    // debug
    debug_notfound_key = (1 << 16),
    debug_partial_iv = (1 << 17),
    debug_counter_sig = (1 << 18),
};

typedef std::list<int> cose_orderlist_t;
typedef std::map<cose_param_t, binary_t> cose_binarymap_t;
typedef std::map<int, variant> cose_variantmap_t;

class cose_composer;
struct cose_context_t {
    uint32 flags;
    uint32 debug_flags;
    basic_stream debug_stream;

    // see cbor_object_signing_encryption::open() and close()
    cose_composer* composer;

    cose_context_t() : flags(0), debug_flags(0) {}
    ~cose_context_t() { clearall(); }
    void clearall() {
        flags = 0;
        debug_flags = 0;
        debug_stream.clear();
    }
};

enum class cose_message_t : uint8 {
    unknown = 0,
    _protected = 1,
    unprotected = 2,
    payload = 3,
    singleitem = 4,
    layered = 5,  // recipients, signatures
};

enum cose_scope_t : uint32 {
    _protected = 0x00000001,
    unprotected = 0x00000010,
    unsent = 0x00000100,
    params = 0x00001000,
    layer = 0x00001111,
    children = 0x00010000,
    all = 0x11111111,
};

class cbor_object_encryption;
class cbor_object_signing;
class cbor_object_signing_encryption;
class cbor_web_key;

class cose_binary;
class cose_composer;
class cose_countersign;
class cose_countersigns;
class cose_data;
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
