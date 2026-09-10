/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_resource.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/string/string.hpp>  // format
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/parser/types.hpp>

namespace hotplace {
namespace io {

asn1_resource asn1_resource::_instance;

asn1_resource::asn1_resource() {}

asn1_resource* asn1_resource::get_instance() {
    _instance.load_resource();
    return &_instance;
}

void asn1_resource::load_resource() {
    if (_type_id.empty()) {
        critical_section_guard guard(_lock);
        if (_type_id.empty()) {
            doload_resource();
        }
    }
}

const struct asn1_entity_resource_t resource_asn1_entities[] = {
    {asn1_entity_boolean, "BOOLEAN", asn1_perm_primitive, token_bool},
    {asn1_entity_integer, "INTEGER", asn1_perm_primitive, token_int},
    {asn1_entity_bitstring, "BIT STRING", asn1_perm_both, token_bitstring},
    {asn1_entity_octstring, "OCTET STRING", asn1_perm_both, token_octstring},
    {asn1_entity_null, "NULL", asn1_perm_primitive, token_null},
    {asn1_entity_oid, "OBJECT IDENTIFIER", asn1_perm_primitive, token_oid},
    {asn1_entity_objdesc, "ObjectDescriptor", asn1_perm_primitive, token_objdesc},
    {asn1_entity_extern, "EXTERNAL", asn1_perm_constructed, token_extern},
    {asn1_entity_real, "REAL", asn1_perm_both, token_real},
    {asn1_entity_enum, "ENUMERATED", asn1_perm_primitive, token_enum},
    {asn1_entity_embedpdv, "EMBEDDED PDV", asn1_perm_constructed, token_embedpdv},
    {asn1_entity_utf8string, "UTF8String", asn1_perm_both, token_utf8string},
    {asn1_entity_reloid, "RELATIVE-OID", asn1_perm_primitive, token_reloid},
    {asn1_entity_numstring, "NumericString", asn1_perm_both, token_numstring},
    {asn1_entity_printstring, "PrintableString", asn1_perm_both, token_printstring},
    {asn1_entity_teletexstring, "TeletexString", asn1_perm_both, token_t61string},
    {asn1_entity_videotexstring, "VideotexString", asn1_perm_both, token_videotexstring},
    {asn1_entity_ia5string, "IA5String", asn1_perm_both, token_ia5string},
    {asn1_entity_utctime, "UTCTime", asn1_perm_primitive, token_utctime},
    {asn1_entity_generalizedtime, "GeneralizedTime", asn1_perm_primitive, token_generalizedtime},
    {asn1_entity_graphicstring, "GraphicString", asn1_perm_both, token_graphicstring},
    {asn1_entity_visiblestring, "VisibleString", asn1_perm_both, token_visiblestring},
    {asn1_entity_generalstring, "GeneralString", asn1_perm_both, token_genaralstring},
    {asn1_entity_universalstring, "UniversalString", asn1_perm_both, token_universalstring},
    {asn1_entity_cstring, "CHARACTER STRING", asn1_perm_both, token_cstring},
    {asn1_entity_bmpstring, "BMPString", asn1_perm_both, token_bmpstring},
    {asn1_entity_date, "DATE", asn1_perm_primitive, token_date},
    {asn1_entity_timeofday, "TIME-OF-DAY", asn1_perm_primitive, token_timeofday},
    {asn1_entity_datetime, "DATE-TIME", asn1_perm_primitive, token_datetime},
    {asn1_entity_duration, "DURATION", asn1_perm_primitive, token_duration},
    {asn1_entity_any, "ANY", asn1_perm_both, token_any},
    {asn1_entity_choice, "CHOICE", asn1_perm_constructed, token_choice},

    {asn1_entity_sequence, "SEQUENCE", asn1_perm_constructed, token_sequence},
    {asn1_entity_set, "SET", asn1_perm_constructed, token_set},

    {asn1_entity_builtin_type, "builtin type", asn1_perm_none},
    // {asn1_entity_named_type, "named type", asn1_perm_none},
    {asn1_entity_referenced_type, "referenced type", asn1_perm_none},
    {asn1_entity_tag, "tag", asn1_perm_none},
    {asn1_entity_tagged_type, "tagged type", asn1_perm_none},

    {asn1_entity_syntax, "::=", asn1_perm_none, token_assign},
    {asn1_entity_syntax, "--", asn1_perm_none, token_comments},
    {asn1_entity_syntax, "OF", asn1_perm_none, token_of},
    {asn1_entity_syntax, "TRUE", asn1_perm_none, token_true},
    {asn1_entity_syntax, "FALSE", asn1_perm_none, token_false},
    {asn1_entity_syntax, "tagged mode", asn1_perm_none, token_taggedmode},
    {asn1_entity_syntax, "class", asn1_perm_none, token_class},
    {asn1_entity_syntax, "UNIVERSAL", asn1_perm_none, token_universal},
    {asn1_entity_syntax, "APPLICATION", asn1_perm_none, token_application},
    {asn1_entity_syntax, "PRIVATE", asn1_perm_none, token_private},
    {asn1_entity_syntax, "IMPLICIT", asn1_perm_none, token_implicit},
    {asn1_entity_syntax, "EXPLICIT", asn1_perm_none, token_explicit},
    {asn1_entity_syntax, "DEFAULT", asn1_perm_none, token_default},
    {asn1_entity_syntax, "OPTIONAL", asn1_perm_none, token_optional},
    {asn1_entity_syntax, "|", asn1_perm_none, token_union},
    {asn1_entity_syntax, "INTERSECTION", asn1_perm_none, token_intersection},
    {asn1_entity_syntax, "EXCEPT", asn1_perm_none, token_except},
    {asn1_entity_syntax, "ALL EXCEPT", asn1_perm_none, token_allexcept},
    {asn1_entity_syntax, "SIZE", asn1_perm_none, token_size},
    {asn1_entity_syntax, "FROM", asn1_perm_none, token_from},
    {asn1_entity_syntax, "PATTERN", asn1_perm_none, token_pattern},
    {asn1_entity_syntax, "MIN", asn1_perm_none, token_min},
    {asn1_entity_syntax, "MAX", asn1_perm_none, token_max},
    {asn1_entity_syntax, "..", asn1_perm_none, token_fromto},
};
const size_t sizeof_resource_asn1_entities = RTL_NUMBER_OF(resource_asn1_entities);

void asn1_resource::doload_resource() {
    if (_type_id.empty()) {
        for (const auto& item : resource_asn1_entities) {
            if (asn1_entity_syntax == item.type) continue;
            _type_id.emplace(item.type, item.token);
            _type_rid.emplace(item.token, item.type);
            _type_perm.emplace(item.type, item.permission);
        }

        struct type_table {
            uint8 type;
            const char* value;
        };
        type_table class_table[] = {
            {asn1_class_universal, "UNIVERSAL"},      //
            {asn1_class_application, "APPLICATION"},  //
            {asn1_class_private, "PRIVATE"},          //
            {asn1_class_context, ""},                 // CONTEXT
        };
        type_table mode_table[] = {
            {asn1_implicit, "IMPLICIT"},
            {asn1_explicit, "EXPLICIT"},
            {asn1_default, "DEFAULT"},
            {asn1_optional, "OPTIONAL"},
        };

        for (const auto& entry : class_table) {
            _class_id.emplace(entry.type, entry.value);
            _class_rid.emplace(entry.value, entry.type);
        }
        for (const auto& entry : mode_table) {
            _mode_id.emplace(entry.type, entry.value);
            _mode_rid.emplace(entry.value, entry.type);
        }
    }
}

std::string asn1_resource::get_component_entity_name(asn1_entity_t entity) const {
    std::string name;
    auto iter = _type_id.find(entity);
    if (_type_id.end() != iter) {
        name = iter->second;
    }
    return name;
}

std::string asn1_resource::get_entity_name(uint8 ident, asn1_entity_t entity) const {
    std::string name;
    auto c = (ident & asn1_class_mask);
    switch (c) {
        case asn1_class_universal: {
            auto iter = _type_id.find(entity);
            if (_type_id.end() != iter) {
                name = iter->second;
            } else {
                name = format("[UNIVERSAL %u]", (unsigned int)entity);
            }
        } break;
        case asn1_class_application: {
            name = format("[APPLICATION %u]", (unsigned int)entity);
        } break;
        case asn1_class_context: {
            name = format("[%u]", (unsigned int)entity);
        } break;
        case asn1_class_private: {
            name = format("[PRIVATE %u]", (unsigned int)entity);
        } break;
    }
    return name;
}

asn1_entity_t asn1_resource::get_entity(const std::string& name) const {
    asn1_entity_t entity = asn1_entity_unknown;
    auto iter = _type_rid.find(name);
    if (_type_rid.end() != iter) {
        entity = iter->second;
    }
    return entity;
}

asn1_perm_t asn1_resource::get_perm(asn1_entity_t entity) const {
    auto iter = _type_perm.find(entity);
    return (_type_perm.end() == iter) ? asn1_perm_none : iter->second;
}

std::string asn1_resource::get_class_name(int c) const {
    std::string name;
    auto iter = _class_id.find(c & asn1_class_mask);
    if (_class_id.end() != iter) {
        name = iter->second;
    }
    return name;
}

uint8 asn1_resource::get_class(const std::string& name) const {
    uint8 type = 0;
    auto iter = _class_rid.find(name);
    if (_class_rid.end() != iter) {
        type = iter->second;
    }
    return type;
}

std::string asn1_resource::nameof_mode(uint16 t) const {
    std::string name;
    auto iter = _mode_id.find(t);
    if (_mode_id.end() != iter) {
        name = iter->second;
    }
    return name;
}

uint8 asn1_resource::valueof_mode(const std::string& name) const {
    uint8 value = 0;
    auto iter = _mode_rid.find(name);
    if (_mode_rid.end() != iter) {
        value = iter->second;
    }
    return value;
}

}  // namespace io
}  // namespace hotplace
