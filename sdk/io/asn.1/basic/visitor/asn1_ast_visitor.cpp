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

#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_ast_visitor.hpp>
// #include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>

namespace hotplace {
namespace io {

asn1_ast_visitor::asn1_ast_visitor() {}

t_tree<asn1_ast_descriptor>* asn1_ast_visitor::visit(const asn1_object* object) const {
    auto tree = new t_tree<asn1_ast_descriptor>();
    visit(object, tree->root());
    return tree;
}

void asn1_ast_visitor::visit(const asn1_object* object, asn1_treenode* parent) const {
    asn1_ast_descriptor desc = describe(object);

    auto entity = get_entity(object, true);

    asn1_treenode* node = nullptr;
    parent->add_child(desc, [&](asn1_treenode* child) -> void { node = child; });

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

asn1_ast_descriptor asn1_ast_visitor::describe(const asn1_object* object) const {
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
        case asn1_entity_set: {
            if (false == name.empty()) desc.name = name;
            syntax << get_entity_name(object, true);
        } break;
        case asn1_entity_sequence_of:
        case asn1_entity_set_of: {
            if (false == name.empty()) desc.name = name;
            syntax << get_entity_name(object, true);
            object->get_constraints().represent(&desc.cons, object, nullptr);
        } break;
        case asn1_entity_referenced_type: {
            auto ref = (asn1_referenced_type*)object;
            desc.name = name;
            if (ref->is_definition())
                syntax << get_entity_name(object, true);
            else
                syntax << ref->get_reference();
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
            // fallthrough
        default: {
            if (false == name.empty()) desc.name = name;

            syntax << get_entity_name(object, false);
        } break;
    }

    return desc;
}

}  // namespace io
}  // namespace hotplace
