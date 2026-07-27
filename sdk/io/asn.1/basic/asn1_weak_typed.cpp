/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_weak_typed.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_weak_typed.hpp>

namespace hotplace {
namespace io {

asn1_weak_typed::asn1_weak_typed() {}

return_t asn1_weak_typed::read(asn1* target, const byte_t* stream, size_t size, size_t& pos) {
    if (nullptr == target || nullptr == stream) return errorcode_t::invalid_parameter;

    target->clear();

    auto test = read_node(stream, size, pos, &_tree, nullptr);
    if (errorcode_t::success != test) return test;

    test = postread_prebuild();
    if (errorcode_t::success != test) return test;

    return postread_postbuild(target, stream, size);
}

return_t asn1_weak_typed::read_node(const byte_t* stream, size_t size, size_t& pos, TLV_tree* tree, TLV_node* parent) {
    if (pos >= size) return errorcode_t::bad_data;

    while (pos < size) {
        if (parent) {
            const auto& outer = parent->_data;
            if (pos >= outer.pos + outer.len) {
                break;
            }
        }

        size_t tpos = pos;

        uint8 ident = 0;
        uint64 tag = 0;
        size_t len = 0;
        return_t test = errorcode_t::success;

        test = asn1_encode::read_identifier(stream, size, tpos, ident, tag);  // T
        if (errorcode_t::success != test) return test;
        test = asn1_encode::read_length(stream, size, tpos, len);  // L
        if (errorcode_t::success != test) return test;

        if (tpos + len > size) return errorcode_t::bad_data;
        if (parent) {
            const auto& outer = parent->_data;
            if (tpos + len > outer.pos + outer.len) {
                return errorcode_t::bad_data;
            }
        }

        asn1_tlv_t item;
        item.ident = ident;
        item.tag = tag;
        item.pos = tpos;
        item.len = len;
        item.node_id = 1 + tree->size();  // increment start with 1

        bool is_constructed = (ident & asn1_tag_constructed) != 0;
        auto node = tree->add_node(item, parent);

        if (is_constructed && len) {
            size_t cpos = tpos;
            read_node(stream, tpos + len, cpos, tree, node);
        }
        pos = tpos + len;
    }

    return errorcode_t::success;
}

return_t asn1_weak_typed::postread_prebuild() {
    auto lambda = [&](TLV_node* node) -> void {
        auto& tlv = node->_data;
        auto obj = asn1_builder::build(tlv.ident, tlv.tag, node->is_leaf());
        obj->set_name(format("NAME%u", tlv.node_id));
        tlv.asn1obj = obj;
    };

    t_tree_visitor<asn1_tlv_t> visitor(lambda);
    visitor.visit(&_tree);

    return errorcode_t::success;
}

return_t asn1_weak_typed::postread_postbuild(asn1* target, const byte_t* stream, size_t size) {
    // prototype codes
    // TODO optimization

    std::set<TLV_node*> branches;                    // first
    std::multimap<TLV_node*, TLV_node*> leaf_nodes;  // first, leaves

    auto lambda = [&](TLV_node* node) -> void {
        auto parent = node->parent();
        auto& parent_tlv = parent->get();
        auto parent_obj = parent_tlv.asn1obj;
        if (parent_obj) {
            auto& node_tlv = node->get();
            auto node_obj = node_tlv.asn1obj;
            auto node_entity = get_entity(node_obj);
            if (asn1_entity_tag == node_entity) {
                // replace
                if (1 == node->_children.size()) {
                    auto child_obj = node->_children.front()->get().asn1obj;
                    node_obj = new asn1_tagged_type((asn1_tag*)node_obj, child_obj);
                    node_tlv.asn1obj = node_obj;
                } else {
                    throw;
                }
            }
            auto parent_entity = get_entity(parent_obj);
            switch (parent_entity) {
                case asn1_entity_sequence:
                case asn1_entity_set: {
                    // containing
                    ((asn1_container*)parent_obj)->add(node_obj);
                } break;
                case asn1_entity_tag: {
                    parent_obj = new asn1_tagged_type((asn1_tag*)parent_obj, node_obj);
                    parent_tlv.asn1obj = parent_obj;
                } break;
                default: {
                } break;
            }
        }
        if (node->is_leaf()) {
            auto first = node;
            while (first->parent() != _tree.root()) {
                first = first->parent();
            }

            branches.insert(first);  // one of root()._children
            leaf_nodes.emplace(first, node);
        }
    };

    t_tree_visitor<asn1_tlv_t> visitor(lambda);
    visitor.visit(&_tree);

    // instatiate
    std::map<TLV_node*, asn1_value*> values;
    _tree.root()->for_each([&](t_treenode<asn1_tlv_t>* node) -> void {
        auto type = node->get().asn1obj;
        auto value = type->instantiate();
        values.emplace(node, value);

        target->_types.push_back(type);
        target->_values.push_back(value);
    });

    // read values
    for (auto& pair : leaf_nodes) {
        auto first = pair.first;
        auto leaf = pair.second;

#if 0
        asn1_value* value = nullptr;
        auto iter = values.find(first);
        if (values.end() != iter) value = iter->second;
        if (nullptr == value) {
            throw exception(errorcode_t::internal_error);  // do not reach
        }
#else
        auto value = values[first];
#endif

        auto& node_tlv = leaf->get();
        const auto& name = node_tlv.asn1obj->resolve_name();

        if (asn1_class_universal == (node_tlv.ident & asn1_class_mask)) {
            auto pos = node_tlv.pos;
            asn1_encode::read(stream, size, pos, (asn1_entity_t)node_tlv.tag, node_tlv.len, name, value);
        } else {
            variant vt(stream + node_tlv.pos, node_tlv.len);
            value->set(name, std::move(vt));
        }
    }

    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            for (auto& pair : values) {
                auto value = pair.second;

                value->for_each([&](const std::string& name, const variant& vt) -> void {
                    dbs << name << " ";
                    vtprintf(&dbs, vt, vtprintf_style_t::vtprintf_style_asn1);
                    dbs << "\n";
                });
            }
        });
    }

    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            for (auto& pair : values) {
                auto type = pair.first->get().asn1obj;
                auto value = pair.second;
                dbs << "publish type\n";
                type->publish(&dbs);
                dbs << "\n";
                dbs << "publish value\n";
                value->publish(&dbs);
                dbs << "\n";
                dbs << "publish DER\n";
                binary_t bin;
                value->publish(&bin);
                dbs << base16_encode(bin);
                dbs << "\n";
            }
            // _tree.root()->for_each([&](t_treenode<asn1_tlv_t>* node) -> void {
            //     node->get().asn1obj->publish(&dbs);
            //     dbs << "\n";
            // });
        });
    }

    return errorcode_t::success;
}

void asn1_weak_typed::clear() { _tree.clear(); }

}  // namespace io
}  // namespace hotplace
