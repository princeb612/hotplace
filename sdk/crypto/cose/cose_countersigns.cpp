/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 8152 CBOR Object Signing and Encryption (COSE)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/crypto/cose/cose_countersigns.hpp>
#include <hotplace/sdk/crypto/cose/cose_recipient.hpp>
#include <hotplace/sdk/crypto/cose/cose_recipients.hpp>

namespace hotplace {
namespace crypto {

cose_countersigns::cose_countersigns() : cose_recipients() {}

cose_countersigns::~cose_countersigns() {}

cbor_array* cose_countersigns::cbor() {
    cbor_array* object = nullptr;
    return_t ret = errorcode_t::success;
    __try2 {
        size_t size_countersigns = size();
        const auto& recipients = get_recipients();
        if (size_countersigns > 1) {
            __try_new_catch(object, new cbor_array, ret, __leave2);

            for (cose_recipient* sign : recipients) {
                *object << sign->cbor();  // array in array
            }
        } else if (size_countersigns == 1) {
            object = recipients.front()->cbor();  // array
        }
    }
    __finally2 {}
    return object;
}

}  // namespace crypto
}  // namespace hotplace
