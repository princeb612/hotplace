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

typedef struct _cose_item_t {
    variant_t key;
    variant_t value;
} cose_item_t;
typedef std::list <cose_item_t> cose_list_t;

typedef std::map <uint32, variant_t> cose_object_map_t;
typedef struct _cose_conents_t {
    cose_object_map_t protected_map;
    cose_object_map_t unprotected_map;
    binary_t data;
} cose_conents_t;
typedef std::list <cose_conents_t> cose_conents_list_t;

typedef struct _cose_context_t {
} cose_context_t;

}
}  // namespace

#endif
