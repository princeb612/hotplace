/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_tag.cpp
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
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>

namespace hotplace {
namespace io {

asn1_tag::asn1_tag(int ctype, int cnumber, int tmode) : asn1_object(asn1_entity_tag, "", nullptr), _class_type(ctype), _class_number(cnumber), _tag_mode(tmode) {}

asn1_tag::asn1_tag(const asn1_tag& other) : asn1_object(other), _class_type(other._class_type), _class_number(other._class_number), _tag_mode(other._tag_mode) {}

asn1_tag::~asn1_tag() {}

asn1_tag* asn1_tag::clone() { return new asn1_tag(*this); }

int asn1_tag::get_class() const { return _class_type; }

int asn1_tag::get_class_number() const { return _class_number; }

int asn1_tag::get_tag_type() const { return _tag_mode; }

bool asn1_tag::is_implicit() const { return asn1_implicit == get_tag_type(); }

void asn1_tag::represent(uint32 depth, stream_t* s) {
    if (s) {
        if (get_class() & asn1_class_mask) {
            s->printf("[");
            if (false == asn1_is_context(get_class())) {
                s->printf("%s", asn1_resource::get_instance()->get_class_name(get_class()).c_str());
                s->printf(" ");
            }

            s->printf("%i", get_class_number());

            s->printf("]");
            if (get_tag_type()) {
                s->printf(" %s", asn1_resource::get_instance()->get_tagtype_name(get_tag_type()).c_str());
            }
        }
    }
}

void asn1_tag::represent(uint32 depth, binary_t* b, asn1_value* value) {
    auto has_explicit = false;
    auto parent = get_parent();
    if (parent && (asn1_entity_tagged_type == parent->get_entity())) {
        asn1_object* node = parent;
        while (node) {
            auto tag = node->get_tag();
            if (tag) {
                if (false == tag->is_implicit()) {
                    has_explicit = true;
                    break;
                }
            }
            node = node->_object;
        }
    }

    uint8 ident = get_class() | get_ident();
    if (has_explicit) ident |= asn1_tag_constructed;
    if (b && (false == is_suppressed())) {
        asn1_encode::asn1_ident_octets(*b, ident, get_class_number());
    }

#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_debug)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            dbs.fill(depth << 1, ' ');
            dbs.println("ASN.1 tag");
            dbs.fill(depth << 1, ' ');
            dbs.println("- entity " ANSI_ESCAPE "1;33m%s %s" ANSI_ESCAPE "0m",
                        asn1_resource::get_instance()->get_entity_name(ident, (asn1_entity_t)get_class_number()).c_str(), is_implicit() ? "IMPLICIT" : "EXPLICIT");
            // dbs.fill(depth << 1, ' ');
            // dbs.println("- suppressed %s", is_suppressed() ? "true" : "false");
            // if (b && (false == is_suppressed())) {
            //     dbs.fill(depth << 1, ' ');
            //     dbs.println("- identifier octet %02x tag %i", ident, get_class_number());
            // }
        });
    }
#endif
}

}  // namespace io
}  // namespace hotplace
