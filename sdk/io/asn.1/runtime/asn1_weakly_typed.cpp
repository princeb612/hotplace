/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_weakly_typed.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/structural/asn1_constructed_node.hpp>
#include <hotplace/sdk/io/asn.1/basic/structural/asn1_node.hpp>
#include <hotplace/sdk/io/asn.1/basic/structural/asn1_primitive_node.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_weakly_typed.hpp>

namespace hotplace {
namespace io {

asn1_weakly_typed::asn1_weakly_typed() {}

asn1_weakly_typed::~asn1_weakly_typed() { clear(); }

return_t asn1_weakly_typed::read(asn1_runtime* target, const byte_t* stream, size_t size, size_t& pos) {
    if (nullptr == target || nullptr == stream) return errorcode_t::invalid_parameter;

    // make a tree
    auto test = _stream.read(stream, size, pos);
    if (errorcode_t::success != test) return test;

    // traverse handler
    auto lambda = [&stream, &size](TLV_node* node) -> void {
        auto& tlv = node->_data;
        asn1_node* structural_node = nullptr;

        if (node->is_leaf()) {
            structural_node = new asn1_primitive_node(tlv.ident, tlv.tag, tlv.len, stream, size, tlv.pos);
        } else {
            structural_node = new asn1_constructed_node(tlv.ident, tlv.tag, tlv.len);
        }

        structural_node->set_name(format("NODE%u", tlv.node_id));

        auto& parent_tlv = node->_parent->_data;
        auto parent_structural_node = parent_tlv.asn1node;
        if (parent_structural_node) parent_structural_node->add(structural_node);

        tlv.asn1node = structural_node;
    };

    // traverse a tree
    t_tree_visitor<asn1_tlv_t> visitor(lambda);
    visitor.visit(&_stream.get_tree());

    // create a hierarchical structure
    test = transform(target);
    if (errorcode_t::success != test) return test;

    return errorcode_t::success;
}

return_t asn1_weakly_typed::transform(asn1_runtime* target) {
    if (nullptr == target) return errorcode_t::invalid_parameter;

    target->clear();

    // top-down
    auto lambda = [this, &target](TLV_node* node) -> void {
        auto obj = transform(target, node->_data.asn1node);
        if (obj) {
            target->add(obj);
            auto value = target->get(obj);
            value->set_schema(obj);

#if defined DEBUG
            // comparison
            if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal,
                                  [&](basic_stream& dbs) -> void { print_ast(obj, dbs, asn1_ast_flag_ansicolor); });
            }
#endif
        }
    };
    _stream.get_tree().root()->for_each(lambda);

    return errorcode_t::success;
}

asn1_object* asn1_weakly_typed::transform(asn1_runtime* target, const asn1_node* node, asn1_object* parent) {
    if (nullptr == node) return nullptr;

    uint32 flags = 0;
    auto size = node->size();

    if (node->is_leaf())
        flags |= flag_is_leaf;
    else {
        if (0 == size)
            throw exception(errorcode_t::unexpected);
        else if (size > 1)
            flags |= flag_as_sequence;
        else
            flags |= flag_as_constructed;
    }

    auto obj = asn1_builder::build(node->get_identifier(), node->get_tag(), flags);
    obj->set_name(node->get_name());
    if (parent) {
        obj->set_parent(parent);

        asn1_object* container = nullptr;
        asn1_object* tagobj = nullptr;
        auto entity = get_entity(parent);
        switch (entity) {
            case asn1_entity_sequence:
            case asn1_entity_set: {
                container = parent;
            } break;
            case asn1_entity_tagged_type: {
                if (is_kind_of_container(parent->get_object())) {
                    container = parent->get_object();
                } else {
                    tagobj = parent;
                }
            } break;
            default: {
            } break;
        }

        if (container)
            ((asn1_container*)container)->add(obj);
        else if (tagobj)
            tagobj->set_object(obj);
        else
            throw exception(errorcode_t::unexpected);
    }

    // top-down
    node->for_each([&](asn1_node* child) -> void { transform(target, child, obj); });

    if (node->is_leaf()) {
        auto top = obj;
        while (top->get_parent()) {
            top = top->get_parent();
        }
        auto value = target->get(top);
        if (nullptr == value) {
            value = new asn1_value(nullptr);

            auto test = target->set(top, value);
            if (errorcode_t::success != test) throw exception(errorcode_t::unexpected);
        }

        const auto& bin = ((asn1_primitive_node*)node)->get();
        auto name = obj->resolve_name();
        if (asn1_class_universal == (node->get_identifier() & asn1_class_mask)) {
            size_t pos = 0;
            asn1_encode::read(bin.data(), bin.size(), pos, (asn1_entity_t)node->get_tag(), node->get_len(), name, value);
        } else {
            variant vt(bin);
            value->set(name, std::move(vt));
        }
    }

    return obj;
}

void asn1_weakly_typed::clear() {
    auto& tree = _stream.get_tree();
    auto lambda = [&](TLV_node* node) -> void {
        auto& tlv = node->_data;
        tlv.asn1node->release();
    };
    tree.root()->for_each(lambda);
    tree.clear();
}

}  // namespace io
}  // namespace hotplace
