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
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_tag.hpp>

namespace hotplace {
namespace io {

asn1_tag::asn1_tag(int ctype, int cnumber, int tmode) : asn1_object(asn1_entity_tag, "", nullptr), _class_type(ctype), _class_number(cnumber), _tag_mode(tmode) {}

asn1_tag::asn1_tag(const asn1_tag& other) : asn1_object(other), _class_type(other._class_type), _class_number(other._class_number), _tag_mode(other._tag_mode) {}

asn1_tag::~asn1_tag() {}

asn1_tag* asn1_tag::clone() { return new asn1_tag(*this); }

asn1_tag* asn1_tag::addref() {
    asn1_object::addref();
    return this;
}

int asn1_tag::get_class() const { return _class_type; }

int asn1_tag::get_class_number() const { return _class_number; }

int asn1_tag::get_tag_type() const { return _tag_mode; }

bool asn1_tag::is_implicit() const { return asn1_implicit == get_tag_type(); }

void asn1_tag::represent(uint32 depth, stream_t* s, asn1_value* value) {
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

bool asn1_tag::represent(uint32 depth, binary_t* b, asn1_value* value, uint16 flags) {
    auto parent = get_parent();
    if (parent && (asn1_entity_tagged_type == parent->get_entity())) {
        asn1_object* node = parent;
        while (node) {
            auto tag = node->get_tag();
            if (tag) {
                if (false == tag->is_implicit()) {
                    as_constructed();
                    break;
                }
            }
            node = node->_object;
        }
        if (is_primitive()) {
            node = parent;
            while (node) {
                if (node->is_constructed()) {
                    as_constructed();
                    break;
                }
                node = node->_object;
            }
        }
    }

    uint8 ident = get_class() | get_ident();
    if (b && (false == is_suppressed())) {
        asn1_encode::write_ident_octets(*b, ident, get_class_number());
    }

#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            auto resource = asn1_resource::get_instance();
            dbs.fill(depth << 1, ' ');
            dbs.println(ANSI_ESCAPE
                        "1;33m"
                        "%s" ANSI_ESCAPE "0m",
                        resource->get_component_entity_name(get_component_entity()).c_str());
            dbs.fill(depth << 1, ' ');
            dbs.println("- " ANSI_ESCAPE "1;33m%s %s" ANSI_ESCAPE "0m", asn1_resource::get_instance()->get_entity_name(ident, (asn1_entity_t)get_class_number()).c_str(),
                        is_implicit() ? "IMPLICIT" : "EXPLICIT");
        });
    }
#endif

    return true;
}

}  // namespace io
}  // namespace hotplace
