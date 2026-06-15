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

#include <hotplace/sdk/io/asn.1/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>

namespace hotplace {
namespace io {

asn1_container::asn1_container(asn1_entity_t entity, const std::string& name, asn1_object* object) : asn1_type(entity, name, object, nullptr) {}

asn1_container::asn1_container(const asn1_container& other) : asn1_type(other) { *this = other; }

asn1_container::~asn1_container() {
    for (auto item : _list) {
        item->release();
    }
}

asn1_container& asn1_container::operator=(const asn1_container& other) {
    asn1_object::operator=(other);
    for (auto item : other._list) {
        *this << item->clone();
    }
    return *this;
}

asn1_container& asn1_container::operator<<(asn1_object* other) {
    if (other) {
        _list.push_back(other);
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

void asn1_container::represent(uint32 depth, stream_t* s) {
    if (s) {
        if (false == get_name().empty()) {
            switch (get_entity()) {
                case asn1_entity_sequence:
                case asn1_entity_set:
                    s->printf("%s ::= ", get_name().c_str());
                    break;
                default:
                    break;
            }
        }
        s->printf("%s ", asn1_resource::get_instance()->get_entity_name(get_ident(), get_entity()).c_str());
        switch (get_entity()) {
            case asn1_entity_sequence_of:
            case asn1_entity_set_of:
                s->printf("%s ", get_name().c_str());
                break;
            default:
                break;
        }
        if (get_componenttype()) {
            s->printf("%s ", asn1_resource::get_instance()->get_componenttype_name(get_componenttype()).c_str());
        }
        switch (get_componenttype()) {
            case asn1_optional:
                break;
            default:
                s->printf("{");
                for (auto iter = _list.begin(); iter != _list.end(); iter++) {
                    if (_list.begin() != iter) {
                        s->printf(", ");
                    }
                    (*iter)->represent(depth + 1, s);
                }
                s->printf("}");
                break;
        }
    }
}

void asn1_container::represent(uint32 depth, binary_t* b, asn1_value* value) {}

void asn1_container::addref() {
    for (auto item : _list) {
        item->addref();
    }
    asn1_object::addref();
}

void asn1_container::release() {
    for (auto item : _list) {
        item->release();
    }
    asn1_object::release();
}

}  // namespace io
}  // namespace hotplace
