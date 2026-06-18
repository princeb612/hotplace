/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_builtin_type.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>

namespace hotplace {
namespace io {

asn1_builtin_type::asn1_builtin_type(asn1_entity_t entity) : asn1_type(asn1_entity_builtin_type, "", new asn1_type(entity)) {}

asn1_builtin_type::asn1_builtin_type(const std::string& name, asn1_entity_t entity) : asn1_type(asn1_entity_builtin_type, "", new asn1_object(entity, name)) {}

asn1_builtin_type::~asn1_builtin_type() {}

asn1_builtin_type* asn1_builtin_type::clone() { return new asn1_builtin_type(*this); }

void asn1_builtin_type::represent(uint32 depth, stream_t* s, asn1_value* value) { get_object()->represent(depth + 1, s, value); }

void asn1_builtin_type::represent(uint32 depth, binary_t* b, asn1_value* value) {
#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            dbs.fill(depth << 1, ' ');
            dbs.println("ASN.1 builtin type");
        });
    }
#endif

    get_object()->represent(depth + 1, b, value);
}

}  // namespace io
}  // namespace hotplace
