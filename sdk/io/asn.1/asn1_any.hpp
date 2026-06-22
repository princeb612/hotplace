/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_any.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1ANY__
#define __HOTPLACE_SDK_IO_ASN1_ASN1ANY__

#include <hotplace/sdk/io/asn.1/asn1_type.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   ASN.1 X.208 legacy
 * @example
 *          // X.509
 *          // algorithm = rsaEncryption
 *          // parameters = NULL
 *          // algorithm = ecPublicKey
 *          // parameters = OID(secp256r1) -- TLV
 *          AlgorithmIdentifier ::= SEQUENCE {algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL}
 *          Algorithm ::= SEQUENCE {algorithm OBJECT IDENTIFIER, parameter ANY DEFINED BY algorithm}
 *
 *          Extension ::= SEQUENCE {extnID OBJECT IDENTIFIER, extnValue OCTET STRING}
 * @sa      ITU-T X.681 Information Object
 */
class asn1_any : public asn1_type {
   public:
    asn1_any(const std::string& name, bool optional = false);
    // asn1_any(const std::string& name, const std::string& ref);
    virtual ~asn1_any();

    virtual asn1_any* clone();
    virtual asn1_any* addref();

   protected:
    virtual void represent(uint32 depth, stream_t* s, asn1_value* value = nullptr);
    virtual bool represent(uint32 depth, binary_t* b, asn1_value* value = nullptr, uint16 flags = 0);

   private:
    std::string _ref;
    binary_t _der;
};

}  // namespace io
}  // namespace hotplace

#endif
