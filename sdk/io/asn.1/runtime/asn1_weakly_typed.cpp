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

#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/structural/asn1_constructed_node.hpp>
#include <hotplace/sdk/io/asn.1/basic/structural/asn1_node.hpp>
#include <hotplace/sdk/io/asn.1/basic/structural/asn1_primitive_node.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_weakly_typed.hpp>

namespace hotplace {
namespace io {

asn1_weakly_typed::asn1_weakly_typed() {}

return_t asn1_weakly_typed::read(asn1_runtime* target, const byte_t* stream, size_t size, size_t& pos) {
    if (nullptr == target || nullptr == stream) return errorcode_t::invalid_parameter;

    auto test = read_node(stream, size, pos, &_tree, nullptr);
    if (errorcode_t::success != test) return test;

    auto lambda = [&](TLV_node* node) -> void {
        auto& tlv = node->_data;
        asn1_node* structural_node = nullptr;

        if (node->is_leaf()) {
            structural_node = new asn1_primitive_node(tlv.ident, tlv.tag, tlv.len, stream, size, tlv.pos);
        } else {
            structural_node = new asn1_constructed_node(tlv.ident, tlv.tag, tlv.len);
        }

        structural_node->set_name(format("NAME%u", tlv.node_id));

        auto& parent_tlv = node->_parent->_data;
        auto parent_structural_node = parent_tlv.asn1node;
        if (parent_structural_node) parent_structural_node->add(structural_node);

        tlv.asn1node = structural_node;
    };

    t_tree_visitor<asn1_tlv_t> visitor(lambda);
    visitor.visit(&_tree);

    test = transform(target);
    if (errorcode_t::success != test) return test;

    return errorcode_t::success;
}

return_t asn1_weakly_typed::read_node(const byte_t* stream, size_t size, size_t& pos, TLV_tree* tree, TLV_node* parent) {
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
        if (errorcode_t::do_nothing == test)
            ;  // case [APPLICATION 31]
        else if (errorcode_t::success != test)
            return test;

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

        if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
            trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                auto depth = node->depth();
                dbs.fill(depth << 1, ' ');
                dbs << "- [x] " << ANSI_ESCAPE << "1;36m" << "TL" << ANSI_ESCAPE << "0m" << " "
                    << base16_encode(stream + pos, tpos - pos, encoding_base16_capital | encoding_base16_space);

                if (false == is_constructed) {
                    dbs << " " << ANSI_ESCAPE << "1;36m" << "V" << ANSI_ESCAPE << "0m" << " "
                        << base16_encode(stream + tpos, len, encoding_base16_capital | encoding_base16_space);
                }
                dbs << "\n";

                dbs.fill(depth << 1, ' ');
                std::string identifier_desc;
                switch (ident & asn1_class_mask) {
                    case asn1_class_application:
                        identifier_desc = "APPLICATION";
                        break;
                    case asn1_class_context:
                        identifier_desc = "CONTEXT";
                        break;
                    case asn1_class_private:
                        identifier_desc = "PRIVATE";
                        break;
                    case asn1_class_universal:
                        identifier_desc = "UNIVERSAL";
                        break;
                }
                if (ident & asn1_tag_constructed) identifier_desc += "+CONSTRUCTED";
                auto resource = asn1_resource::get_instance();
                valist va;
                va << item.node_id << ident << identifier_desc << tag << resource->get_entity_name(ident, (asn1_entity_t)tag) << len;
                dbs.vaprintf("- node {1} I {2:02X} ({3}) T {4} ({5}) L {6}\n", va);
            });
        }

        if (is_constructed && len) {
            size_t cpos = tpos;
            read_node(stream, tpos + len, cpos, tree, node);
        }
        pos = tpos + len;
    }

    return errorcode_t::success;
}

return_t asn1_weakly_typed::transform(asn1_runtime* target) {
    if (nullptr == target) return errorcode_t::invalid_parameter;

    target->clear();

    // top-down
    auto lambda = [&](TLV_node* node) -> void {
        auto obj = transform(target, node->_data.asn1node);
        if (obj) {
            target->add(obj);
        }
    };
    _tree.root()->for_each(lambda);

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
            throw;
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
        else if (tagobj) {
            tagobj->set_object(obj);
        } else
            throw;
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
            value = top->instantiate();

            auto test = target->set(top, value);
            if (errorcode_t::success != test) throw;
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

void asn1_weakly_typed::clear() { _tree.clear(); }

}  // namespace io
}  // namespace hotplace
