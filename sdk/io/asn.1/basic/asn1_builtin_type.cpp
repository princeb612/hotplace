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

#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints.hpp>

namespace hotplace {
namespace io {

asn1_builtin_type::asn1_builtin_type(asn1_entity_t entity) : asn1_type(entity, "", new asn1_type(entity)) {}

asn1_builtin_type::asn1_builtin_type(const std::string& name, asn1_entity_t entity) : asn1_type(entity, name, nullptr) {}

asn1_builtin_type::asn1_builtin_type(const std::string& name, asn1_entity_t entity, const variant& value) : asn1_type(entity, name, nullptr) {
    set_default_value(value.content());
}

asn1_builtin_type::~asn1_builtin_type() {}

asn1_builtin_type* asn1_builtin_type::clone() { return new asn1_builtin_type(*this); }

asn1_builtin_type* asn1_builtin_type::addref() {
    asn1_object::addref();
    return this;
}

asn1_entity_t asn1_builtin_type::get_component_entity() const { return asn1_entity_builtin_type; }

void asn1_builtin_type::represent(uint32 depth, stream_t* s, asn1_value* value) {
    if (s) {
        auto resource = asn1_resource::get_instance();
        auto entity = get_entity();

        if (asn1_entity_referenced_type == entity)
            s->printf("%s", _name.c_str());
        else {
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
            if (asn1_default == type) {
                s->printf(" ");
                vtprintf(s, _vt, vtprintf_style_t::vtprintf_style_asn1);
            }

            get_constraints().represent(s, this, value);
        }
    }
}

bool asn1_builtin_type::represent(uint32 depth, binary_t* b, asn1_value* value, uint16 flags) {
    debug_print(depth);

    // value binding
    std::string name;
    if (value) {
        name = resolve_name();
        debug_print(depth, name);

        if (asn1_visitor_choice == flags) {
            if (false == value->find(name)) {
                return false;
            }
        }
    }

    if (false == is_suppressed()) {
        switch (flags) {
            // if homogenious container
            case asn1_visitor_sequence_of:
            case asn1_visitor_set_of:
                // do nothing
                break;
            case asn1_visitor_choice:
            default:
                asn1_encode::write_ident_octets2(*b, this);
                break;
        }
    }

    if (value) {
        switch (flags) {
            case asn1_visitor_sequence_of:
                value->encode_sequenceof_value(*b, this, name);
                break;
            case asn1_visitor_set_of:
                value->encode_setof_value(*b, this, name);
                break;
            default: {
                bool do_len = false;
                auto pos = b->size();
                value->encode_value(*b, this, name, do_len);
                if (do_len && (false == is_suppressed())) {
                    // insert L between L and V
                    asn1_encode::t_asn1_length_octets<size_t>(*b, b->size() - pos, pos);
                }
            } break;
        }
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
