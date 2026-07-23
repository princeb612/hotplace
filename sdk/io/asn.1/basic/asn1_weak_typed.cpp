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

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_any.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_weak_typed.hpp>

namespace hotplace {
namespace io {

asn1_weak_typed::asn1_weak_typed() {}

return_t asn1_weak_typed::read(const byte_t* stream, size_t size, size_t& pos) { return read_node(stream, size, pos, &_tree, nullptr); }

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
        uint8 mode = asn1_automatic;
        return_t test = errorcode_t::success;

        test = asn1_encode::read_identifier(stream, size, tpos, ident, tag);  // T
        if (errorcode_t::success != test) return test;
        test = asn1_encode::read_length(stream, size, tpos, len);  // L
        if (errorcode_t::success != test) return test;

        uint8 ident_class = ident & asn1_class_mask;
        uint8 ident_pcbit = ident & asn1_tag_mask;

        if (tpos + len > size) return errorcode_t::bad_data;
        if (parent) {
            const auto& outer = parent->_data;
            if (tpos + len > outer.pos + outer.len) {
                return errorcode_t::bad_data;
            }
        }

        if (asn1_class_universal == ident_class) {
            // do nothing
        } else {
            if (asn1_tag_primitive == ident_pcbit) {
                // mode = asn1_implicit;  // Primitive as IMPLICIT
            }
        }
        // in other cases - not 100%

        asn1_tlv_t item;
        item.ident = ident;
        item.tag = tag;
        item.mode = mode;
        item.pos = tpos;
        item.len = len;

#if defined DEBUG
        auto lambda_builder = [](uint8 ident, uint64 tag, uint8 mode) -> asn1_object* {
            if (asn1_class_universal == (ident & asn1_class_mask)) {
                auto obj = new asn1_builtin_type((asn1_entity_t)tag);
                if (ident & asn1_tag_constructed) {
                    obj->as_constructed();
                }
                return obj;
            } else {
                return new asn1_tag(ident, tag, mode);
            }
        };

        if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
            trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                dbs << ANSI_ESCAPE << "1;36m";
                auto schema = lambda_builder(ident, tag, mode);
                schema->publish(&dbs);
                schema->release();
                dbs << ANSI_ESCAPE << "0m" << "\n";
            });
        }
#endif

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

}  // namespace io
}  // namespace hotplace
