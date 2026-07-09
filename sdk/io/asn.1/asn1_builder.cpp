/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_builder.cpp
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
#include <hotplace/sdk/io/asn.1/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/builtin/asn1_bitstring.hpp>
#include <hotplace/sdk/io/asn.1/basic/builtin/asn1_integer.hpp>
#include <set>

namespace hotplace {
namespace io {

asn1_builder::asn1_builder() {}

asn1_object* asn1_builder::build(asn1_entity_t entity, std::function<void(asn1_object*)> f) {
    asn1_object* object = nullptr;
    switch (entity) {
        case asn1_entity_integer:
            object = new asn1_integer;
            break;
        case asn1_entity_bitstring:
            object = new asn1_bitstring;
            break;
        case asn1_entity_boolean:
        case asn1_entity_octstring:
        case asn1_entity_null:
        case asn1_entity_oid:
        case asn1_entity_objdesc:
        case asn1_entity_extern:
        case asn1_entity_real:
        case asn1_entity_enum:
        case asn1_entity_embedpdv:
        case asn1_entity_utf8string:
        case asn1_entity_reloid:
        case asn1_entity_sequence:
        case asn1_entity_set:
        case asn1_entity_numstring:
        case asn1_entity_printstring:
        case asn1_entity_teletexstring:
        // case asn1_entity_t61string:
        case asn1_entity_videotexstring:
        case asn1_entity_ia5string:
        case asn1_entity_utctime:
        case asn1_entity_generalizedtime:
        case asn1_entity_graphicstring:
        case asn1_entity_visiblestring:
        // case asn1_entity_iso646string:
        case asn1_entity_generalstring:
        case asn1_entity_universalstring:
        case asn1_entity_cstring:
        case asn1_entity_bmpstring:
        case asn1_entity_date:
        case asn1_entity_timeofday:
        case asn1_entity_datetime:
        case asn1_entity_duration:
            object = new asn1_builtin_type(entity);
            break;
        default:
            break;
    }
    if (object && f) {
        f(object);
    }
    return object;
}

}  // namespace io
}  // namespace hotplace
