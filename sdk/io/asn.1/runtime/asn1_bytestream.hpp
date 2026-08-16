/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_bytestream.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1BYTESTREAM__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1BYTESTREAM__

#include <hotplace/sdk/base/nostd/tree.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

/**
 * @comments
 *  - Notation
 *    - Type4 ::= [APPLICATION 7] IMPLICIT Type3
 *  - DER (input stream)
 *    - 67 07 43 05 4A 6F 6E 65 73
 *  - weakly-typed TLV tree (output)
 *    - [x] TL 67 07
 *    - node 1 I 0x60 (APPLICATION+CONSTRUCTED) T 7 ([APPLICATION 7]) L 7
 *      - [x] TL 43 05 V 4A 6F 6E 65 73
 *      - node 2 I 0x40 (APPLICATION) T 3 ([APPLICATION 3]) L 5
 * @remarks
 *  asn1_weakly_typed
 *      asn1_bytestream::read
 *      assign and bind asn1_constructed_node if it is a container, and asn1_primitive_node if it is a leaf.
 *      convert each asn1_node* into asn1_object* form
 *      hierarchically link using asn1_sequence or asn_tagged_type
 */
class asn1_bytestream {
   public:
    struct asn1_tlv_t {
        uint8 ident;          // identifier + P/C bit
        uint64 tag;           // Tag
        size_t begin;         // TLV offset
        size_t len;           // V length
        size_t pos;           // V offet, V := [stream + pos .. stream + pos + len]
        uint32 node_id;       // debug
        uint32 flags;         // asn1_builder_flag_t
        asn1_node* asn1node;  // [optional] asn1_weakly_typed intermediate

        asn1_tlv_t() : ident(0), tag(0), begin(0), len(0), pos(0), node_id(0), flags(0), asn1node(nullptr) {}

        uint8 get_class() const { return (ident & asn1_class_mask); }
        bool is_constructed() const { return (ident & asn1_tag_mask) ? true : false; }
        uint64 get_tag() const { return tag; }
    };
    using TLV_tree = t_tree<asn1_tlv_t>;
    using TLV_node = t_treenode<asn1_tlv_t>;

    asn1_bytestream();
    ~asn1_bytestream();

    /**
     * DER parser
     */
    return_t read(const byte_t* stream, size_t size, size_t& pos);
    TLV_tree& get_tree();

   protected:
    /**
     * @brief   binary stream to t_tree<T>
     * @sa      read
     */
    return_t read_node(const byte_t* stream, size_t size, size_t& pos, TLV_tree* tree, TLV_node* parent);

   private:
    TLV_tree _tree;
};

}  // namespace io
}  // namespace hotplace

#endif
