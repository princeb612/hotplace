/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_object_validate.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/pattern/regex.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/basic/oid.hpp>

namespace hotplace {
namespace io {

bool asn1_object::validate(const asn1_value* value) {
    if (nullptr == value || nullptr == value) return false;

    return validate_node(this, value);
}

bool asn1_object::validate_node(const asn1_object* node, const asn1_value* value) const {
    if (nullptr == value) return false;
    while (node) {
        if (false == node->validate_type(value)) {
            return false;
        }
        if (node->have_constraints()) {
            return node->get_constraints().validate(node, value);
        }
        if (is_kind_of_container(node)) {
            auto container = dynamic_cast<const asn1_container*>(node);
            auto test = container->for_each([&](asn1_object* item) -> bool { return item->validate_node(item, value); });
            if (false == test) return false;
        }
        node = node->get_object();
    }
    return true;
}

static bool asn1_validate_type(std::list<variant>& values, const asn1_object* object, const asn1_value* value, uint16 flags) {
    bool ret = false;
    if (object && value) {
        const auto& name = object->resolve_name();
        ret = value->find(name, values, flags);
    }
    return ret;
}

template <typename F>
static bool asn1_validate_type(std::list<variant>& values, const asn1_object* object, const asn1_value* value, uint16 flags, F&& func) {
    bool ret = false;
    if (object && value) {
        const auto& name = object->resolve_name();
        ret = value->find(name, values, flags);
        if (ret) {
            for (const auto& item : values) {
                if (false == std::forward<F>(func)(item)) return false;
            }
        }
    }
    return ret;
}

bool asn1_object::validate_type(const asn1_value* value) const {
    bool ret = false;
    std::list<variant> values;
    switch (_entity) {
        case asn1_entity_boolean: {
            ret = asn1_validate_type(values, this, value, vt_flag_bool);
        } break;
        case asn1_entity_octstring: {
            auto lambda = [](const variant& item) -> bool {
                std::string str;
                item.to_string(str);
                if (str.empty() || (str.size() % 2)) {
                    return false;
                }
                for (char c : str) {
                    if (false == std::isxdigit((unsigned char)c)) {
                        return false;
                    }
                }
                return true;
            };
            ret = asn1_validate_type(values, this, value, vt_flag_string, lambda);
        } break;
        case asn1_entity_bitstring: {
            auto lambda = [](const variant& item) -> bool {
                std::string str;
                item.to_string(str);
                for (char c : str) {
                    if ('0' == c || '1' == c) {
                        continue;
                    } else {
                        return false;
                    }
                }
                return true;
            };
            ret = asn1_validate_type(values, this, value, vt_flag_string, lambda);
        } break;
        case asn1_entity_null: {
            auto lambda = [](const variant& item) -> bool { return (vartype_t::TYPE_NULL == item.type()); };
            ret = asn1_validate_type(values, this, value, -1, lambda);
            if ((false == ret) && values.empty()) {
                ret = true;
            }
        } break;
        case asn1_entity_oid:
        case asn1_entity_reloid: {
            auto lambda = [](const variant& item) -> bool {
                std::string str;
                item.to_string(str);
                oid_t oid;
                str_to_oid(str, oid);
                return (false == oid.empty());
            };
            ret = asn1_validate_type(values, this, value, vt_flag_string, lambda);
        } break;
        case asn1_entity_integer: {
            ret = asn1_validate_type(values, this, value, vt_flag_int);
        } break;
        case asn1_entity_real: {
            ret = asn1_validate_type(values, this, value, vt_flag_float);
        } break;
        case asn1_entity_numstring: {
            auto lambda = [](const variant& item) -> bool {
                std::string str;
                item.to_string(str);
                for (char c : str) {
                    if (false == std::isdigit((unsigned char)c)) {
                        return false;
                    }
                }
                return true;
            };
            ret = asn1_validate_type(values, this, value, vt_flag_string, lambda);
        } break;
        case asn1_entity_printstring: {
            auto lambda = [](const variant& item) -> bool {
                std::string str;
                item.to_string(str);
                for (char c : str) {
                    if (false == std::isprint((unsigned char)c)) {
                        return false;
                    }
                }
                return true;
            };
            ret = asn1_validate_type(values, this, value, vt_flag_string, lambda);
        } break;
        case asn1_entity_utf8string:
        case asn1_entity_teletexstring:
        case asn1_entity_videotexstring:
        case asn1_entity_ia5string:
        case asn1_entity_graphicstring:
        case asn1_entity_visiblestring:
        case asn1_entity_generalstring:
        case asn1_entity_universalstring:
        case asn1_entity_cstring: {
            ret = asn1_validate_type(values, this, value, vt_flag_string);
        } break;
        case asn1_entity_utctime: {
            // cf. test/testcase/base/pattern/testvector_regex.yml
            auto lambda = [](const variant& item) -> bool {
                std::string str;
                item.to_string(str);
                size_t pos = 0;
                std::list<std::string> tokens;
                const char* pattern = R"(^([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|2[0-3])([0-5][0-9])([0-5][0-9])?(Z|[+-][0-9]{4})$)";
                regex_token(str, pattern, pos, tokens);
                return false == tokens.empty();
            };
            ret = asn1_validate_type(values, this, value, vt_flag_string, lambda);
        } break;
        case asn1_entity_generalizedtime: {
            // cf. test/testcase/base/pattern/testvector_regex.yml
            auto lambda = [](const variant& item) -> bool {
                std::string str;
                item.to_string(str);
                size_t pos = 0;
                std::list<std::string> tokens;
                const char* pattern = R"(^([0-9]{4})(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|2[0-3])([0-5][0-9])?([0-5][0-9])?(\.[0-9]+)?(Z|[+-][0-9]{4})$)";
                regex_token(str, pattern, pos, tokens);
                return false == tokens.empty();
            };
            ret = asn1_validate_type(values, this, value, vt_flag_string, lambda);
        } break;
        default:
            ret = true;  // sequence, set, sequence_of, set_of, enum, referenced_type, ...
            break;
    }
    return ret;
}

}  // namespace io
}  // namespace hotplace
