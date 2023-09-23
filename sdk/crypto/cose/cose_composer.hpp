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

#include <hotplace/sdk/crypto/cose/types.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief   interface prototyping
 */
typedef struct _cose_item_t {
    variant_t key;
    variant_t value;
} cose_item_t;
typedef std::list <cose_item_t> cose_list_t;

class cose_composer
{
public:
    cose_composer ();
    ~cose_composer ();

    return_t build_protected (cbor_data** object);
    return_t build_protected (cbor_data** object, cose_list_t& input);
    return_t build_protected (cbor_data** object, cbor_map* input);
    return_t build_unprotected (cbor_map** object);
    return_t build_unprotected (cbor_map** object, cose_list_t& input);
    return_t build_data (cbor_data** object, const char* payload);
    return_t build_data (cbor_data** object, const byte_t* payload, size_t size);
    return_t build_data_b16 (cbor_data** object, const char* str);
};

}
}  // namespace

#endif
