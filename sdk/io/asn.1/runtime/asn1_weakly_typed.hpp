/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_weakly_typed.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1WEAKLYTYPED__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1WEAKLYTYPED__

#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_bytestream.hpp>

namespace hotplace {
namespace io {

/**
 * without notation, weakly-typed raw TLV tree
 *
 * Type1 ::= VisibleString                  "1A 05 4A 6F 6E 65 73"             (PC=0 UNIVERSAL, VisibleString)
 *
 * primitive as implicit
 * Type2 ::= [Application 3] IMPLICIT Type1 "43 05 4A 6F 6E 65 73"             (PC=0 APPLICATION 3)
 * Type5 ::= [2] IMPLICIT Type2             "82 05 4A 6F 6E 65 73"             (PC=0 CONTEXT)
 *
 * Type3 ::= [2] Type2                      "a2 07 43 05 4A 6F 6E 65 73"       (PC=1 CONTEXT 2, PC=0 APPLICATION 3)
 * Type4 ::= [Application 7] IMPLICIT Type3 "67 07 43 05 4A 6F 6E 65 73"       (PC=1 APPLICATION 7, PC=0 APPLICATION 3)
 * Type6 ::= [1] EXPLICIT Type1,            "A1 07 1A 05 4A 6F 6E 65 73"       (PC=1 CONTEXT 1, PC=0 UNIVERSAL)
 * Type7 ::= [2] EXPLICIT Type6,            "A2 09 A1 07 1A 05 4A 6F 6E 65 73" (PC=1 CONTEXT 2, PC=1 CONTEXT 1, PC=0 UNIVERSAL)
 */
class asn1_weakly_typed {
    friend class asn1_runtime;

   public:
    using asn1_tlv_t = asn1_bytestream::asn1_tlv_t;
    using TLV_tree = asn1_bytestream::TLV_tree;
    using TLV_node = asn1_bytestream::TLV_node;

    asn1_weakly_typed();
    ~asn1_weakly_typed();

    /**
     * DER parser
     */
    return_t read(asn1_runtime* target, const byte_t* stream, size_t size, size_t& pos);

    void clear();

   protected:
    static asn1_object* transform(asn1_runtime* target, const asn1_node* node, asn1_object* parent = nullptr);
    /**
     * schema-less transform
     */
    return_t transform(asn1_runtime* target);

   private:
    asn1_bytestream _stream;
};

}  // namespace io
}  // namespace hotplace

#endif
