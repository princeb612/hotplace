/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_weak_typed.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1WEAKLYTYPED__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1WEAKLYTYPED__

#include <hotplace/sdk/base/nostd/tree.hpp>
#include <hotplace/sdk/io/asn.1/basic/types.hpp>

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
class asn1_weak_typed {
    friend class asn1;

   public:
    struct asn1_tlv_t {
        uint8 ident;
        uint64 tag;
        size_t len;
        size_t pos;
        uint32 node_id;
        asn1_object* asn1obj;

        asn1_tlv_t() : ident(0), tag(0), len(0), pos(0), node_id(0), asn1obj(nullptr) {}
    };
    using TLV_tree = t_tree<asn1_tlv_t>;
    using TLV_node = t_treenode<asn1_tlv_t>;

    asn1_weak_typed();

    return_t read(asn1* target, const byte_t* stream, size_t size, size_t& pos);
    void clear();

   protected:
    /**
     * @brief   binary stream to t_tree<asn1_tlv_t>
     * @sa      read
     */
    return_t read_node(const byte_t* stream, size_t size, size_t& pos, TLV_tree* tree, TLV_node* parent);
    /**
     * @brief   create a asn1_object* per TLV
     * @sa      read
     */
    return_t postread_prebuild();
    /**
     * @brief   make a hierarchical structure
     * @sa      read
     */
    return_t postread_postbuild(asn1* target, const byte_t* stream, size_t size);

   private:
    TLV_tree _tree;
};

}  // namespace io
}  // namespace hotplace

#endif
