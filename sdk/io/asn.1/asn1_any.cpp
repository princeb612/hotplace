/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_any.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/io/asn.1/asn1_any.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>

namespace hotplace {
namespace io {

asn1_any::asn1_any(const std::string& name, bool optional) : asn1_type(asn1_entity_any, name, nullptr) {
    if (optional) as_optional();
}

// asn1_any::asn1_any(const std::string& name, const std::string& ref) : asn1_type(asn1_entity_any, name, nullptr) { _ref = ref; }

asn1_any::~asn1_any() {}

asn1_any* asn1_any::clone() { return new asn1_any(*this); }

asn1_any* asn1_any::addref() {
    asn1_object::addref();
    return this;
}

void asn1_any::represent(uint32 depth, stream_t* s, asn1_value* value) {
    auto resource = asn1_resource::get_instance();
    auto entity = get_entity();

    if (false == get_name().empty()) s->printf("%s ", get_name().c_str());
    if (value) {
        value->write(s, get_name());
    } else {
        s->printf("%s", resource->get_entity_name(get_ident(), entity).c_str());
    }
    auto type = get_component_type();
    switch (type) {
        case asn1_default:
        case asn1_optional: {
            s->printf(" %s", resource->get_tagtype_name(type).c_str());
        } break;
        default: {
        } break;
    }
}

bool asn1_any::represent(uint32 depth, binary_t* b, asn1_value* value, uint16 flags) {
    auto entity = get_entity();

#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            auto resource = asn1_resource::get_instance();
            dbs.fill(depth << 1, ' ');
            dbs.println("%s", resource->get_component_entity_name(get_component_entity()).c_str());
            dbs.fill(depth << 1, ' ');
            dbs << "- ";
            if (false == get_name().empty()) {
                dbs << get_name() << " ";
            }
            dbs.println(ANSI_ESCAPE "1;33m%s" ANSI_ESCAPE "0m", resource->get_entity_name(get_ident(), entity).c_str());
        });
    }
#endif

    std::string name;
    if (value) {
        name = resolve_name();
#if defined DEBUG
        if (false == name.empty()) {
            if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                    dbs.fill(depth << 1, ' ');
                    dbs.println("- resolving " ANSI_ESCAPE "1;36m%s" ANSI_ESCAPE "0m", name.c_str());
                });
            }
        }
#endif

        value->add_binary(*b, name);
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
