/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_container_of.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_container_of.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_tag.hpp>

namespace hotplace {
namespace io {

asn1_container_of::asn1_container_of(asn1_entity_t entity, const std::string& name, asn1_entity_t item) : asn1_container_of(entity, name, new asn1_builtin_type(item)) {}

asn1_container_of::asn1_container_of(asn1_entity_t entity, const std::string& name, asn1_object* object) : asn1_type(entity, name, object, nullptr) {
    as_constructed(false); /* no cascade */
}

asn1_container_of::~asn1_container_of() {}

asn1_container_of* asn1_container_of::clone() { return new asn1_container_of(*this); }

asn1_container_of* asn1_container_of::addref() {
    asn1_object::addref();
    return this;
}

void asn1_container_of::release() {
    //
    asn1_object::release();
}

void asn1_container_of::represent(uint32 depth, stream_t* s, asn1_value* value) {
    if (s) {
        auto entity = get_entity();

        if (false == get_name().empty()) {
            s->printf("%s ", get_name().c_str());
        }
        s->printf("%s OF ", asn1_resource::get_instance()->get_entity_name(get_ident(), entity).c_str());

        get_object()->represent(depth + 1, s, value);
    }
}

bool asn1_container_of::represent(uint32 depth, binary_t* b, asn1_value* value, uint16 flags) {
    debug_print(depth);

    size_t pos = 0;
    if (false == is_suppressed()) {
        asn1_encode::write_ident_octets2(*b, this);
        pos = b->size();
    }

    auto entity = get_entity();
    if (entity == asn1_entity_sequence) {
        // asn1_sequence_of : asn1_container_of
        get_object()->represent(depth + 1, b, value, asn1_visitor_sequence_of);
    } else if (entity == asn1_entity_set) {
        // asn1_set_of : asn1_container_of
        get_object()->represent(depth + 1, b, value, asn1_visitor_set_of);
    } else {
        // impossible
    }

    if (false == is_suppressed()) {
        asn1_encode::t_asn1_length_octets<size_t>(*b, b->size() - pos, pos);
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
