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

asn1_builtin_type::asn1_builtin_type(asn1_entity_t entity) : asn1_type(entity, "", new asn1_type(entity)) { set_component_entity(asn1_entity_builtin_type); }

asn1_builtin_type::asn1_builtin_type(const std::string& name, asn1_entity_t entity) : asn1_type(entity, name, nullptr) { set_component_entity(asn1_entity_builtin_type); }

asn1_builtin_type::~asn1_builtin_type() {}

asn1_builtin_type* asn1_builtin_type::clone() { return new asn1_builtin_type(*this); }

asn1_builtin_type* asn1_builtin_type::addref() {
    asn1_object::addref();
    return this;
}

void asn1_builtin_type::represent(uint32 depth, stream_t* s, asn1_value* value) {
    if (s) {
        auto entity = get_entity();
        if (asn1_entity_referenced_type == entity)
            s->printf("%s", _name.c_str());
        else {
            if (false == get_name().empty()) s->printf("%s ", get_name().c_str());
            if (value) {
                value->write(s, get_name());
            } else {
                s->printf("%s", asn1_resource::get_instance()->get_entity_name(get_ident(), entity).c_str());
            }
        }
    }
}

bool asn1_builtin_type::represent(uint32 depth, binary_t* b, asn1_value* value, uint16 flags) {
    auto entity = get_entity();

#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            dbs.fill(depth << 1, ' ');
            dbs.println("ASN.1 builtin type");
            dbs.fill(depth << 1, ' ');
            dbs << "- ";
            if (false == get_name().empty()) {
                dbs << get_name() << " ";
            }
            dbs.println(ANSI_ESCAPE "1;33m%s" ANSI_ESCAPE "0m", asn1_resource::get_instance()->get_entity_name(get_ident(), entity).c_str());
        });
    }
#endif

    // value binding
    std::string name;
    if (value) {
        auto lambda_join = [](const std::vector<std::string>& path, const std::string& word) -> std::string {
            std::string value;
            for (auto iter = path.begin(); iter != path.end(); ++iter) {
                if (iter != path.begin()) {
                    value += word;
                }
                value += *iter;
            }
            return value;
        };
        auto lambda_resolve = [&](asn1_object* node) -> std::string {
            std::vector<std::string> path;
            while (node) {
                auto entity = node->get_component_entity();
                switch (entity) {
                    case asn1_entity_builtin_type:
                    case asn1_entity_tagged_type:
                    case asn1_entity_sequence:
                    case asn1_entity_set:
                    case asn1_entity_choice: {
                        const auto& nodename = node->get_name();
                        if (false == nodename.empty()) {
                            path.push_back(nodename);
                        }
                    } break;
                    case asn1_entity_referenced_type:
                    default:
                        break;
                }

                node = node->get_parent();  // transparent
            }

            std::reverse(path.begin(), path.end());
            return lambda_join(path, ".");
        };

        name = lambda_resolve(this);
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
                asn1_encode::asn1_ident_octets(*b, get_ident(), get_entity());
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
