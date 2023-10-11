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

#include <hotplace/sdk/crypto/cose/cbor_object_encryption.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>

namespace hotplace {
namespace crypto {

cbor_object_encryption::cbor_object_encryption() {
    // do nothing
}

cbor_object_encryption::~cbor_object_encryption() {
    // do nothing
}

return_t cbor_object_encryption::encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    return ret;
}

return_t cbor_object_encryption::encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    return ret;
}

return_t cbor_object_encryption::decrypt(cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result) {
    return_t ret = errorcode_t::success;

    return_t check = errorcode_t::success;
    cbor_object_signing cose_sign;
    std::set<bool> results;
    cbor_object_signing_encryption::composer composer;

    __try2 {
        ret = errorcode_t::verify;
        result = false;

        composer.parse(handle, cbor_tag_t::cose_tag_encrypt, input);

        const char* k = nullptr;

        binary_t enc_structure;
        size_t size_subitems = handle->subitems.size();
        std::list<cose_parts_t>::iterator iter;
        for (iter = handle->subitems.begin(); iter != handle->subitems.end(); iter++) {
            cose_parts_t& item = *iter;
            // compose_enc_structure (enc_structure, handle->tag, item.bin_protected, convert (""));
            int alg = 0;
            std::string kid;
            composer.finditem(cose_key_t::cose_alg, alg, item.protected_map, handle->body.protected_map);
            composer.finditem(cose_key_t::cose_kid, kid, item.unprotected_map, handle->body.unprotected_map);
            if (kid.size()) {
                k = kid.c_str();
            }

            // check = decrypt (handle, key, k, (cose_alg_t) alg, enc_structure, item.bin_data);
            // results.insert((errorcode_t::success == check) ? true : false);
        }

        if ((1 == results.size()) && (true == *results.begin())) {
            result = true;
            ret = errorcode_t::success;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace crypto
}  // namespace hotplace
