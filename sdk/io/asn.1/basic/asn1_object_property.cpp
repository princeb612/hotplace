/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_object_property.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>

namespace hotplace {
namespace io {

asn1_entity_t get_entity(asn1_object* object, bool component) {
    if (nullptr == object) return asn1_entity_syntax;
    if (component)
        return object->get_component_entity();
    else
        return object->get_entity();
}

std::string nameof(asn1_object* object) {
    if (object)
        return object->resolve_name();
    else
        return "";
}

bool is_kind_of_integer(asn1_object* object) {
    if (nullptr == object) return false;
    return is_kind_of_integer(get_entity(object));
}

bool is_kind_of_real(asn1_object* object) {
    if (nullptr == object) return false;
    return is_kind_of_real(get_entity(object));
}

bool is_kind_of_cstring(asn1_object* object) {
    if (nullptr == object) return false;
    return is_kind_of_cstring(get_entity(object));
}

bool is_kind_of_bstring(asn1_object* object) {
    if (nullptr == object) return false;
    return is_kind_of_bstring(get_entity(object));
}

bool is_kind_of_container(asn1_object* object) {
    if (nullptr == object) return false;
    return is_kind_of_container(get_entity(object, true));
}

bool is_kind_of_container_of(asn1_object* object) {
    if (nullptr == object) return false;
    return is_kind_of_container_of(get_entity(object, true));
}

bool is_kind_of_integer(asn1_entity_t entity) {
    switch (entity) {
        case asn1_entity_integer:
            return true;
        default:
            return false;
    }
}

bool is_kind_of_real(asn1_entity_t entity) {
    switch (entity) {
        case asn1_entity_real:
            return true;
        default:
            return false;
    }
}

bool is_kind_of_cstring(asn1_entity_t entity) {
    switch (entity) {
        case asn1_entity_utf8string:
        case asn1_entity_numstring:
        case asn1_entity_printstring:
        case asn1_entity_teletexstring:
        case asn1_entity_videotexstring:
        case asn1_entity_ia5string:
        case asn1_entity_graphicstring:
        case asn1_entity_visiblestring:
        case asn1_entity_generalstring:
        case asn1_entity_universalstring:
        case asn1_entity_cstring:
        case asn1_entity_bmpstring:
            return true;
        default:
            return false;
    }
}

bool is_kind_of_bstring(asn1_entity_t entity) {
    switch (entity) {
        case asn1_entity_bitstring:
        case asn1_entity_octstring:
            return true;
        default:
            return false;
    }
}

bool is_kind_of_container(asn1_entity_t entity) {
    switch (entity) {
        case asn1_entity_sequence:
        case asn1_entity_set:
            return true;
        default:
            return false;
    }
}

bool is_kind_of_container_of(asn1_entity_t entity) {
    switch (entity) {
        case asn1_entity_sequence_of:
        case asn1_entity_set_of:
            return true;
        default:
            return false;
    }
}

}  // namespace io
}  // namespace hotplace
