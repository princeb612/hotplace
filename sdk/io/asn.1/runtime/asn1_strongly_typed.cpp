/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_strongly_typed.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

// #include <hotplace/sdk/base/stream/basic_stream.hpp>
// #include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
// #include <hotplace/sdk/io/asn.1/basic/asn1_builder.hpp>
// #include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
// #include <hotplace/sdk/io/asn.1/basic/semantic/asn1_builtin_type.hpp>
// #include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
// #include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
// #include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_strongly_typed.hpp>

namespace hotplace {
namespace io {

asn1_strongly_typed::asn1_strongly_typed() {}

asn1_strongly_typed::~asn1_strongly_typed() {}

return_t asn1_strongly_typed::read(asn1_runtime* target, const std::string& name, const byte_t* stream, size_t size, size_t& pos) {
    if (nullptr == target || nullptr == stream) return errorcode_t::invalid_parameter;

    // schema
    auto schema = target->get(name);
    if (nullptr == schema) return errorcode_t::not_found;

    // value
    auto value = target->get(schema);
    if (nullptr == value) {
        value = new asn1_value(nullptr);

        auto test = target->set(schema, value);
        if (errorcode_t::success != test) throw exception(errorcode_t::unexpected);
        value->set_schema(schema);
    }

    asn1_bytestream asn1stream;
    auto test = asn1stream.read(stream, size, pos);
    if (errorcode_t::success != test) return test;

    auto cursor = asn1stream.get_tree().create_cursor();
    uint8 mode = asn1_explicit;

    auto lambda = [&stream, &size, &value, &cursor, &mode](asn1_object* item) -> void {
        if (false == cursor.valid()) throw exception(errorcode_t::invalid_context);

        auto entity = item->get_component_entity();
        switch (entity) {
            case asn1_entity_tagged_type: {
                auto tag = item->get_tag();
                auto c = tag->get_class();
                auto n = tag->get_class_number();
                auto t = tag->get_tag_type();

                const auto& tlv = cursor->get();
                if ((tlv.get_class() == c) && (tlv.get_tag() == n)) {
                    int debug = 0;  // on my way
                } else if (asn1_explicit != mode) {
                    int debug = 0;  // replaced - do nothing
                } else {
                    throw exception(errorcode_t::mismatch);
                }
                if (t == asn1_explicit) cursor.next();
                mode = t;
            } break;
            case asn1_entity_sequence:
            case asn1_entity_set: {
            } break;
            case asn1_entity_builtin_type: {
                if (cursor->is_leaf()) {
                    const auto& tlv = cursor->get();
                    auto entity = item->get_entity();

                    size_t pos = tlv.pos;
                    const auto& nodename = item->resolve_name();
                    if (tlv.get_class() == asn1_class_universal && tlv.get_tag() == entity) {
                        asn1_encode::read(stream, size, pos, (asn1_entity_t)entity, tlv.len, nodename, value);
                    } else if (asn1_explicit != mode) {
                        asn1_encode::read(stream, size, pos, (asn1_entity_t)entity, tlv.len, nodename, value);
                    } else {
                        throw;
                    }
                } else {
                    throw;
                    // cursor.next();
                }
                int n = 0;
            } break;
            // case asn1_entity_referenced_type: {
            // } break;
            // case asn1_entity_any: {
            // } break;
            // case asn1_entity_sequence_of:
            // case asn1_entity_set_of:
            // case asn1_entity_choice:
            // case asn1_entity_enum_type: {
            // } break;
            default: {
            } break;
        }
    };
    asn1_visitor visitor(target, lambda);
    visitor.visit(schema);

    return errorcode_t::success;
}

return_t asn1_strongly_typed::read_node(asn1_bytestream::TLV_node* node, asn1_object* object) { return errorcode_t::success; }

}  // namespace io
}  // namespace hotplace
