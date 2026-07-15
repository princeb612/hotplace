/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_ast_visitor.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_ast_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_tag.hpp>

namespace hotplace {
namespace io {

asn1_ast_visitor::asn1_ast_visitor() {}

t_tree<asn1_ast_descriptor>* asn1_ast_visitor::visit(asn1_object* object) {
    auto tree = new t_tree<asn1_ast_descriptor>();
    visit(object, tree->root());
    return tree;
}

void asn1_ast_visitor::visit(asn1_object* object, asn1_treenode* parent) {
    asn1_ast_descriptor desc = describe(object);

    auto entity = get_entity(object, true);

    asn1_treenode* node = nullptr;
    parent->add_child(desc, [&](asn1_treenode* temp) -> void { node = temp; });

    switch (entity) {
        case asn1_entity_tagged_type: {
            visit(object->get_tag(), node);
            visit(object->get_object(), node);
        } break;
        case asn1_entity_referenced_type: {
            auto ref = (asn1_referenced_type*)object;
            if (ref->is_definition()) visit(object->get_object(), node);
        } break;
        case asn1_entity_sequence:
        case asn1_entity_set:
        case asn1_entity_choice: {
            auto cont = (asn1_container*)object;
            cont->for_each([&](asn1_object* item) -> bool {
                visit(item, node);
                return true;
            });
        } break;
        case asn1_entity_sequence_of:
        case asn1_entity_set_of: {
            auto obj = object->get_object();
            if (obj) visit(obj, node);
        } break;
        default: {
        } break;
    }
}

asn1_ast_descriptor asn1_ast_visitor::describe(asn1_object* object) {
    asn1_ast_descriptor desc;

    desc.object = object;
    basic_stream& syntax = desc.syntax;
    basic_stream& detail = desc.detail;

    auto resource = asn1_resource::get_instance();
    auto component = get_entity(object, true);
    const auto& name = object->get_name();

    switch (component) {
        case asn1_entity_tagged_type:
        case asn1_entity_choice:
        case asn1_entity_sequence:
        case asn1_entity_sequence_of:
        case asn1_entity_set:
        case asn1_entity_set_of: {
            if (false == name.empty()) desc.name = name;
            syntax << get_entity_name(object, true);
        } break;
        case asn1_entity_referenced_type: {
            if (object->get_object()) desc.name = name;
            syntax << get_entity_name(object, true);
        } break;
        case asn1_entity_tag: {
            auto tag = (asn1_tag*)object;
            auto classtype = tag->get_class();
            auto cn = tag->get_class_number();
            auto tagtype = tag->get_tag_type();
            if (classtype & asn1_class_mask) {
                syntax << get_entity_name(object, true);
                detail << "[";
                if (false == asn1_is_context(classtype)) detail << resource->get_class_name(classtype).c_str() << " ";
                detail << cn << "]";
                if (tagtype) detail << " " << resource->get_tagtype_name(tagtype);
            }
        } break;
        case asn1_entity_builtin_type:
            object->get_constraints().represent(&desc.cons, object, nullptr);
        default: {
            if (false == name.empty()) desc.name = name;

            syntax << get_entity_name(object, false);
        } break;
    }

    return desc;
}

return_t print_ast(asn1_object* object, basic_stream& bs, bool ansicolor) {
    if (nullptr == object) return errorcode_t::invalid_parameter;

    bs.clear();

    asn1_ast_visitor visitor;
    auto tree = visitor.visit(object);

    if (ansicolor) bs << ANSI_ESCAPE << "1;32m";
    bs << "AST";
    if (ansicolor) bs << ANSI_ESCAPE << "0m";
    bs << "\n";

    auto lambda = [&](t_treenode<asn1_ast_descriptor>* node) -> void {
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
                bs << "+ constraints";
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

}  // namespace io
}  // namespace hotplace
