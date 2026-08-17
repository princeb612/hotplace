/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_bytestream.cpp
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
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_bytestream.hpp>

namespace hotplace {
namespace io {

asn1_bytestream::asn1_bytestream() {}

asn1_bytestream::~asn1_bytestream() {}

return_t asn1_bytestream::read(const byte_t* stream, size_t size, size_t& pos) {
    if (nullptr == stream) return errorcode_t::invalid_parameter;

    return read_node(stream, size, pos, &_tree, nullptr);
}

t_tree<asn1_bytestream::asn1_tlv_t>& asn1_bytestream::get_tree() { return _tree; }

return_t asn1_bytestream::read_node(const byte_t* stream, size_t size, size_t& pos, TLV_tree* tree, TLV_node* parent) {
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
        item.begin = pos;
        item.len = len;
        item.pos = tpos;
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

}  // namespace io
}  // namespace hotplace
