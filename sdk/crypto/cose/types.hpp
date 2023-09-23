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

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/crypto/types.hpp>

namespace hotplace {
namespace crypto {

typedef std::map <crypt_item_t, variant_t> cose_object_map_t;
typedef std::list <cose_object_map_t> cose_object_map_list_t;
typedef struct _cose_context_t {
    std::string kid;
    uint32 sig; // crypt_sig_t
    uint32 tag; // cbor_tag_t
    cose_object_map_t object_map;
    cose_object_map_list_t array;

    _cose_context_t () : sig (0), tag (0)
    {
    }
} cose_context_t;

}
}  // namespace

#endif
