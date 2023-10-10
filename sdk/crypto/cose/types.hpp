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

typedef struct _cose_parts_t {
    // sign, verify
    uint8 tag;
    binary_t bin_protected;
    binary_t bin_data;
    // for sign (just generation)
    crypt_variantlist_t protected_list;
    crypt_variantlist_t unprotected_list;
    // for verify (to search)
    crypt_cosemap_t protected_map;
    crypt_cosemap_t unprotected_map;

    void clear ()
    {
        tag = 0;
        bin_protected.clear ();
        bin_data.clear ();

        crypt_variantlist_t::iterator list_iter;
        for (list_iter = protected_list.begin (); list_iter != protected_list.end (); list_iter++) {
            variant_free (list_iter->key);
            variant_free (list_iter->value);
        }
        for (list_iter = unprotected_list.begin (); list_iter != unprotected_list.end (); list_iter++) {
            variant_free (list_iter->key);
            variant_free (list_iter->value);
        }

        crypt_cosemap_t::iterator map_iter;
        for (map_iter = protected_map.begin (); map_iter != protected_map.end (); map_iter++) {
            variant_free (map_iter->second);
        }
        protected_map.clear ();
        for (map_iter = unprotected_map.begin (); map_iter != unprotected_map.end (); map_iter++) {
            variant_free (map_iter->second);
        }
        unprotected_map.clear ();
    }
} cose_parts_t;

typedef struct _cose_context_t {
    uint8 tag;
    cose_parts_t body;
    binary_t payload;
    std::list <cose_parts_t> subitems;
} cose_context_t;

}
}  // namespace

#endif
