/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_union.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint_single_value.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint_union.hpp>

namespace hotplace {
namespace io {

asn1_constraint_union::asn1_constraint_union(asn1_constraint* lhs, asn1_constraint* rhs) : asn1_constraint(asn1_entity_constraint_union) {
    if (nullptr == lhs || nullptr == rhs) {
        // throw exception(errorcode_t::invalid_parameter);
    }

    lhs->set_parent(this);
    rhs->set_parent(this);

    _items.push_back(lhs);
    _items.push_back(rhs);
}

asn1_constraint_union::asn1_constraint_union(const std::initializer_list<asn1_constraint*>& items) : asn1_constraint(asn1_entity_constraint_union) {
    if (items.size() < 2) {
        // throw exception(errorcode_t::invalid_parameter);
    }

    for (auto item : items) {
        item->set_parent(this);
        _items.push_back(item);
    }
}

asn1_constraint_union::asn1_constraint_union(const std::initializer_list<int>& items) : asn1_constraint(asn1_entity_constraint_union) {
    if (items.size() < 2) {
        // throw exception(errorcode_t::invalid_parameter);
    }

    for (auto item : items) {
        auto obj = new asn1_constraint_single_value(item);
        obj->set_parent(this);
        _items.push_back(obj);
    }
}

asn1_constraint_union::asn1_constraint_union(const std::initializer_list<std::string>& items) : asn1_constraint(asn1_entity_constraint_union) {
    if (items.size() < 2) {
        // throw exception(errorcode_t::invalid_parameter);
    }

    for (auto item : items) {
        auto obj = new asn1_constraint_single_value(item);
        obj->set_parent(this);
        _items.push_back(obj);
    }
}

asn1_constraint_union::~asn1_constraint_union() {}

asn1_constraint_union::asn1_constraint_union(const asn1_constraint_union& other) : asn1_constraint(asn1_entity_constraint_union) { *this = other; }

asn1_constraint_union& asn1_constraint_union::operator=(const asn1_constraint_union& other) {
    for (auto item : other._items) {
        auto obj = item->clone();
        obj->set_parent(this);
        _items.push_back(obj);
    }
    return *this;
}

asn1_constraint_union* asn1_constraint_union::clone() { return new asn1_constraint_union(*this); }

bool asn1_constraint_union::is_applicable(asn1_entity_t entity) {
    bool ret = false;
    switch (entity) {
        case asn1_entity_constraint_single:
        case asn1_entity_constraint_size:
        case asn1_entity_constraint_range:
        case asn1_entity_constraint_from:
        case asn1_entity_constraint_pattern:
        case asn1_entity_constraint_including:
        case asn1_entity_constraint_containing:
        case asn1_entity_constraint_union:
        case asn1_entity_constraint_intersection:
        case asn1_entity_constraint_except:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

void asn1_constraint_union::addref() {
    asn1_constraint::addref();
    for (auto item : _items) {
        item->addref();
    }
}

void asn1_constraint_union::release() {
    for (auto item : _items) {
        item->release();
    }
    asn1_constraint::release();
}

void asn1_constraint_union::represent(stream_t* s, asn1_object* object, asn1_value* value) {
    if (false == _items.empty()) {
        auto iter = _items.begin();
        (*iter)->represent(s, object, value);
        while (++iter != _items.end()) {
            s->printf(" | ");
            (*iter)->represent(s, object, value);
        }
    }
}

}  // namespace io
}  // namespace hotplace
