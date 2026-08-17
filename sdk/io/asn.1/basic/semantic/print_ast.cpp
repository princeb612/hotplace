/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   print_ast.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_ast_visitor.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>

namespace hotplace {
namespace io {

static return_t print_ast(t_tree<asn1_ast_descriptor>* tree, basic_stream& bs, uint32 flags) {
    bool ansicolor = (flags & asn1_ast_flag_ansicolor);

    if (ansicolor) bs << ANSI_ESCAPE << "1;32m";
    bs << "AST";
    if (ansicolor) bs << ANSI_ESCAPE << "0m";
    bs << "\n";

    auto lambda = [&bs, &ansicolor](t_treenode<asn1_ast_descriptor>* node) -> void {
        if (node) {
            int depth = node->depth();
            auto& descriptor = node->_data;

            bs.fill(depth << 1, ' ');
            bs << "- ";
            if (false == descriptor.name.empty()) {
                if (ansicolor) bs << ANSI_ESCAPE << "1;36m";
                bs << descriptor.name;
                if (ansicolor) bs << ANSI_ESCAPE << "0m";
                bs << " ";
            }
            if (ansicolor) bs << ANSI_ESCAPE << "1;33m";
            bs << descriptor.syntax;
            if (ansicolor) bs << ANSI_ESCAPE << "0m";
            bs << "\n";

            if (false == descriptor.detail.empty()) {
                bs.fill((depth + 1) << 1, ' ');
                bs << "- ";
                if (ansicolor) bs << ANSI_ESCAPE << "1;33m";
                bs << descriptor.detail;
                if (ansicolor) bs << ANSI_ESCAPE << "0m";
                bs << "\n";
            }
            if (false == descriptor.cons.empty()) {
                bs.fill((depth + 1) << 1, ' ');
                bs << "- [constraints]";
                if (ansicolor) bs << ANSI_ESCAPE << "1;33m";
                bs << descriptor.cons;
                if (ansicolor) bs << ANSI_ESCAPE << "0m";
                bs << "\n";
            }
        }
    };

    t_tree_visitor<asn1_ast_descriptor> treevisitor(lambda);
    treevisitor.visit(tree);
    tree->release();

    return errorcode_t::success;
}

return_t print_ast(const asn1_object* object, basic_stream& bs, uint32 flags) {
    if (nullptr == object) return errorcode_t::invalid_parameter;

    asn1_ast_visitor visitor;
    auto tree = visitor.visit(object);

    return print_ast(tree, bs, flags);
}

return_t print_ast(const asn1_runtime* runtime, basic_stream& bs, uint32 flags) {
    if (nullptr == runtime) return errorcode_t::invalid_parameter;

    auto tree = new t_tree<asn1_ast_descriptor>();

    asn1_ast_visitor visitor;
    runtime->for_each([&](asn1_object* item) -> void { visitor.visit(item, tree->root()); });

    return print_ast(tree, bs, flags);
}

}  // namespace io
}  // namespace hotplace
