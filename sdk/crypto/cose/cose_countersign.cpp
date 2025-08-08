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

#include <sdk/crypto/cose/cose_countersign.hpp>

namespace hotplace {
namespace crypto {

cose_countersign::cose_countersign() : cose_recipient() {}

cose_countersign::~cose_countersign() {}

cbor_array* cose_countersign::cbor() {
    cbor_array* object = new cbor_array;
    *object << get_protected().cbor() << get_unprotected().cbor() << get_signature().cbor();
    return object;
}

}  // namespace crypto
}  // namespace hotplace
