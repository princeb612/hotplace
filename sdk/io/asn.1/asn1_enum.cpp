/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_enum.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_enum.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>

namespace hotplace {
namespace io {

asn1_enum::asn1_enum() : asn1_enum("") {}

asn1_enum::asn1_enum(const std::string& name) : asn1_type(asn1_entity_enum, name, nullptr) { as_primitive(false); }

asn1_enum::asn1_enum(const std::initializer_list<std::pair<std::string, int>>& items) : asn1_enum("", items) {}

asn1_enum::asn1_enum(const std::string& name, const std::initializer_list<std::pair<std::string, int>>& items) : asn1_type(asn1_entity_enum, name, nullptr) {
    as_primitive(false);
    add(items);
}

asn1_enum::~asn1_enum() {}

asn1_enum* asn1_enum::clone() { return new asn1_enum(*this); }

asn1_enum* asn1_enum::addref() {
    asn1_type::addref();
    return this;
}

asn1_entity_t asn1_enum::get_component_entity() const { return asn1_entity_enum_type; }

asn1_enum& asn1_enum::add(const std::string& en, int value) {
    _enum.emplace(en, value);
    _reverse.emplace(value, en);
    return *this;
}

asn1_enum& asn1_enum::operator<<(const std::initializer_list<std::pair<std::string, int>>& items) { return add(items); }

asn1_enum& asn1_enum::add(const std::initializer_list<std::pair<std::string, int>>& items) {
    for (const auto& item : items) {
        _enum.emplace(item.first, item.second);
        _reverse.emplace(item.second, item.first);
    }
    return *this;
}

void asn1_enum::represent(uint32 depth, stream_t* s, asn1_value* value) {
    auto resource = asn1_resource::get_instance();
    auto entity = get_entity();

    if (false == get_name().empty()) s->printf("%s ", get_name().c_str());

    s->printf("%s ", resource->get_entity_name(get_ident(), entity).c_str());
    s->printf("{");
    if (false == _reverse.empty()) {
        auto iter = _reverse.begin();
        s->printf("%s(%i)", iter->second.c_str(), iter->first);
        ++iter;
        while (_reverse.end() != iter) {
            s->printf(", %s(%i)", iter->second.c_str(), iter->first);
            ++iter;
        }
    }
    s->printf("}");
}

bool asn1_enum::represent(uint32 depth, binary_t* b, asn1_value* value, uint16 flags) {
    auto entity = get_entity();
    auto name = resolve_name();
#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            auto resource = asn1_resource::get_instance();
            dbs.fill(depth << 1, ' ');
            dbs.println(ANSI_ESCAPE "1;33m%s" ANSI_ESCAPE "0m", resource->get_component_entity_name(get_component_entity()).c_str());
            dbs.fill(depth << 1, ' ');
            dbs << "- ";
            if (false == get_name().empty()) {
                dbs << get_name() << " ";
            }
            dbs.println(ANSI_ESCAPE "1;33m%s" ANSI_ESCAPE "0m", asn1_resource::get_instance()->get_entity_name(get_ident(), entity).c_str());

            dbs.fill(depth << 1, ' ');
            dbs.println("- resolving " ANSI_ESCAPE "1;36m%s" ANSI_ESCAPE "0m", name.c_str());
        });
    }
#endif

    // enum to integer
    auto lambda_enum2int = [&](const std::string& ename, int& evalue) -> bool {
        evalue = 0;
        bool ret = false;
        auto iter = _enum.find(ename);
        if (_enum.end() != iter) {
            evalue = iter->second;
            ret = true;
        }
        return ret;
    };

    // node name to integer
    auto lambda_find = [&](asn1_value* value, const std::string& name, int& evalue) -> bool {
        bool ret = false;
        if (value) {
            variant v;
            auto test = value->find(name, v);
            if (test) {
                std::string key;
                v.to_string(key);
                ret = lambda_enum2int(key, evalue);
            }
        }
        return ret;
    };

    int evalue = 0;
    if (value) {
        auto test = lambda_find(value, name, evalue);
        if (test) {
            asn1_encode::asn1_ident_octets(*b, get_ident(), get_entity());

            auto pos = b->size();

            asn1_encode enc;
            enc.t_asn1_integer_value(*b, evalue);

            asn1_encode::t_asn1_length_octets<size_t>(*b, b->size() - pos, pos);
        }
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
