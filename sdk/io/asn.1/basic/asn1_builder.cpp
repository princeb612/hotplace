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

#include <hotplace/sdk/io/asn.1/basic/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_any.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_enum.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_sequence.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_set.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/builtin/asn1_bitstring.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/builtin/asn1_integer.hpp>

namespace hotplace {
namespace io {

asn1_builder::asn1_builder() {}

asn1_object* asn1_builder::build(uint8 ident, uint64 tag, uint32 flags) {
    asn1_object* obj = nullptr;
    if (asn1_class_universal == (ident & asn1_class_mask)) {
        obj = build((asn1_entity_t)tag);
        if (ident & asn1_tag_constructed) {
            obj->as_constructed();
        }
    } else {
        if (flags & asn1_builder_flag_t::flag_as_sequence) {
            auto tagobj = new asn1_tag(ident, tag, asn1_implicit);
            obj = new asn1_tagged_type(tagobj, new asn1_sequence);
        } else if (flags & asn1_builder_flag_t::flag_as_constructed) {
            auto tagobj = new asn1_tag(ident, tag, asn1_explicit);
            obj = new asn1_tagged_type(tagobj, nullptr);
        } else {
            auto tagobj = new asn1_tag(ident, tag, asn1_automatic);
            if (flags & asn1_builder_flag_t::flag_is_leaf) {
                obj = new asn1_tagged_type(tagobj, new asn1_any);
            } else {
                obj = tagobj;
            }
        }
    }
    return obj;
}

asn1_object* asn1_builder::build(asn1_entity_t entity, std::function<void(asn1_object*)> f) {
    asn1_object* object = nullptr;
    switch (entity) {
        case asn1_entity_boolean:
        case asn1_entity_octstring:
        case asn1_entity_null:
        case asn1_entity_oid:
        case asn1_entity_objdesc:
        case asn1_entity_extern:
        case asn1_entity_real:
        case asn1_entity_embedpdv:
        case asn1_entity_utf8string:
        case asn1_entity_reloid:
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
        case asn1_entity_integer:
            object = new asn1_integer;
            break;
        case asn1_entity_bitstring:
            object = new asn1_bitstring;
            break;
        case asn1_entity_sequence:
            object = new asn1_sequence;
            break;
        case asn1_entity_set:
            object = new asn1_set;
            break;
        case asn1_entity_enum:
            object = new asn1_enum;
            break;
        default:
            break;
    }
    if (object && f) {
        f(object);
    }
    return object;
}

asn1_object* asn1_builder::build(const std::string& name, asn1_entity_t entity, std::function<void(asn1_object*)> f) {
    auto obj = build(entity, f);
    if (obj) obj->set_name(name);
    return obj;
}

asn1_object* asn1_builder::build(asn1_object* object, std::function<void(asn1_object*)> f) {
    if (object && f) {
        f(object);
    }
    return object;
}

}  // namespace io
}  // namespace hotplace
