/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_ast_visitor.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_VISITOR_ASN1ASTVISOTOR__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_VISITOR_ASN1ASTVISOTOR__

#include <hotplace/sdk/base/nostd/tree.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/io/asn.1/basic/types.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   Abstract Syntax Tree
 * @comments
 *          // sketch
 *          - Type4 referenced type
 *            - tagged type
 *              - tag type
 *                - [APPLICATION 7] IMPLICIT
 *              - Type3 referenced type
 *                - tagged type
 *                  - tag type
 *                    - [2] EXPLICIT
 *                  - Type2 referenced type
 *                    - tagged type
 *                      - tag type
 *                        - [APPLICATION 3] IMPLICIT
 *                      - Type1 referenced type
 *                        - VisibleString
 *
 * @sa      print_ast
 */
struct asn1_ast_descriptor {
    std::string name;     //
    basic_stream syntax;  // tag type
    basic_stream detail;  // [APPLICATION 7] IMPLICIT
    basic_stream cons;    //
    const asn1_object* object;

    asn1_ast_descriptor() : object(nullptr) {}
};

class asn1_ast_visitor {
   public:
    using asn1_tree = t_tree<asn1_ast_descriptor>;
    using asn1_treenode = t_treenode<asn1_ast_descriptor>;

    asn1_ast_visitor();
    ~asn1_ast_visitor() = default;

    t_tree<asn1_ast_descriptor>* visit(const asn1_object* object) const;
    void visit(const asn1_object* object, asn1_treenode* parent) const;

   protected:
    asn1_ast_descriptor describe(const asn1_object* object) const;

   private:
};

enum asn1_ast_flags : uint32 {
    asn1_ast_flag_ansicolor = 1 << 0,
};
return_t print_ast(const asn1_object* object, basic_stream& bs, uint32 flags = asn1_ast_flag_ansicolor);
return_t print_ast(const asn1_runtime* object, basic_stream& bs, uint32 flags = asn1_ast_flag_ansicolor);

}  // namespace io
}  // namespace hotplace

#endif
