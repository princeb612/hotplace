/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_container.cpp
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
#include <hotplace/sdk/io/asn.1/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>

namespace hotplace {
namespace io {

asn1_container::asn1_container(asn1_entity_t entity, const std::string& name, asn1_object* object) : asn1_type(entity, name, nullptr, nullptr) {
    as_constructed();
    if (object) {
        if (object->is_named_type()) {
            *this << object;
        }
    }
}

asn1_container::asn1_container(asn1_entity_t entity, const std::string& name, const std::initializer_list<std::pair<std::string, asn1_entity_t>>& items)
    : asn1_container(entity, name, nullptr) {
    for (const auto& item : items) {
        const auto& name = item.first;
        const auto& entity = item.second;

        auto obj = new asn1_builtin_type(name, entity);
        _list.push_back(obj);
        _map.emplace(entity, obj);
        obj->set_parent(this);
    }
}

asn1_container::asn1_container(asn1_entity_t entity, const std::string& name, const std::initializer_list<asn1_object*>& items) : asn1_container(entity, name, nullptr) {
    for (const auto& item : items) {
        if (item) {
            if (item->is_named_type()) {
                *this << item;
            }
        }
    }
}

asn1_container::asn1_container(const asn1_container& other) : asn1_type(other) { *this = other; }

asn1_container::~asn1_container() {}

asn1_container* asn1_container::clone() { return new asn1_container(*this); }

asn1_container* asn1_container::addref() {
    for (auto item : _list) {
        item->addref();
    }
    asn1_object::addref();
    return this;
}

void asn1_container::release() {
    for (auto item : _list) {
        item->release();
    }
    asn1_object::release();
}

asn1_container& asn1_container::operator=(const asn1_container& other) {
    asn1_object::operator=(other);
    for (const auto& item : other._list) {
        *this << item->clone();
    }
    return *this;
}

asn1_container& asn1_container::operator<<(asn1_object* other) {
    if (other) {
        _list.push_back(other);
        auto entity = other->get_entity();
        _map.emplace(entity, other);
        other->set_parent(this);
    }
    return *this;
}

asn1_container& asn1_container::add(std::function<asn1_object*(asn1_container*)> func) {
    if (func) {
        auto obj = func(this);
        return *this << obj;
    }
    return *this;
}

void asn1_container::represent(uint32 depth, stream_t* s, asn1_value* value) {
    if (s) {
        auto entity = get_entity();

        if (false == get_name().empty()) {
            s->printf("%s ", get_name().c_str());
        }
        s->printf("%s ", asn1_resource::get_instance()->get_entity_name(get_ident(), entity).c_str());

        s->printf("{");
        for (auto iter = _list.begin(); iter != _list.end(); ++iter) {
            if (_list.begin() != iter) {
                s->printf(", ");
            }
            (*iter)->represent(depth + 1, s, value);
        }
        s->printf("}");
    }
}

bool asn1_container::represent(uint32 depth, binary_t* b, asn1_value* value, uint16 flags) {
    auto entity = get_entity();

    size_t pos = 0;
    if ((false == is_suppressed()) && (asn1_entity_choice != entity)) {
        asn1_encode::asn1_ident_octets(*b, get_ident(), entity);
        pos = b->size();
    }

#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            dbs.fill(depth << 1, ' ');
            if (false == get_name().empty()) {
                dbs << get_name() << " ";
            }
            dbs.println(ANSI_ESCAPE "1;33m%s" ANSI_ESCAPE "0m", asn1_resource::get_instance()->get_entity_name(get_ident(), entity).c_str());
        });
    }
#endif

    switch (entity) {
        case asn1_entity_sequence: {
            // asn1_sequence : asn1_container
            for (auto item : _list) {
                item->represent(depth + 1, b, value);
            }
        } break;
        case asn1_entity_set: {
            // asn1_set : asn1_container
            for (auto item : _map) {
                auto obj = item.second;
                obj->represent(depth + 1, b, value);
            }
        } break;
        case asn1_entity_choice: {
            // asn1_choice : asn1_container
            for (auto item : _map) {
                auto obj = item.second;
                auto test = obj->represent(depth + 1, b, value, asn1_visitor_choice);
                if (test) break;
            }
        } break;
        default: {
            // impossible
        } break;
    }

    if ((false == is_suppressed()) && (asn1_entity_choice != entity)) {
        asn1_encode::t_asn1_length_octets<size_t>(*b, b->size() - pos, pos);
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
