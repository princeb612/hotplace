/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraints.hpp>

namespace hotplace {
namespace io {

asn1_constraints::asn1_constraints() {}

asn1_constraints::asn1_constraints(const asn1_constraints& other) : asn1_constraints() { *this = other; }

asn1_constraints::asn1_constraints(asn1_constraints&& other) : asn1_constraints() { *this = std::move(other); }

asn1_constraints& asn1_constraints::operator=(const asn1_constraints& other) {
    if (false == other._constraints.empty()) {
        for (auto& item : other._constraints) {
            add(item->clone());
        }
    }
    return *this;
}

asn1_constraints& asn1_constraints::operator=(asn1_constraints&& other) {
    std::swap(_constraints, other._constraints);
    return *this;
}

asn1_constraints& asn1_constraints::add(asn1_constraint_t* cons, std::function<void(asn1_constraint_t*)> f) {
    if (cons) {
        if (f) {
            f(cons);
        }
        _constraints.push_back(cons);
    }
    return *this;
}

bool asn1_constraints::empty() const { return _constraints.empty(); }

void asn1_constraints::represent(stream_t* s, const asn1_object* object, const asn1_value* value) const {
    if (false == _constraints.empty()) {
        for (auto& item : _constraints) {
            bool parenthesis = (false == is_kind_of_container_of(object));
            s->printf(" ");
            if (parenthesis) s->printf("(");
            asn1_constraint_notation_visitor visitor(s, object);
            item->accept(&visitor);
            if (parenthesis) s->printf(")");
        }
    }
}

bool asn1_constraints::validate(const asn1_object* node, const asn1_value* value) const {
    if (nullptr == node || nullptr == value) return false;

    if (false == _constraints.empty()) {
        for (auto item : _constraints) {
            bool test = false;
            auto entity = item->get_entity();
            if (asn1_entity_constraint_size == entity) {
                test = do_validate<int64>(item, node, value);
            } else {
                if (is_kind_of_integer(node) || is_kind_of_container_of(node)) {
                    test = do_validate<int64>(item, node, value);
                } else if (is_kind_of_real(node)) {
                    test = do_validate<double>(item, node, value);
                } else if (is_kind_of_cstring(node) || is_kind_of_bstring(node)) {
                    test = do_validate<std::string>(item, node, value);
                }
            }
            if (false == test) return false;
        }
    } else if (is_kind_of(node, asn1_entity_enum)) {
        return do_validate<std::string>(nullptr, node, value);
    }
    return true;
}

void asn1_constraints::addref() {
    if (false == _constraints.empty()) {
        for (auto& item : _constraints) {
            item->addref();
        }
    }
}

void asn1_constraints::release() {
    if (false == _constraints.empty()) {
        for (auto& item : _constraints) {
            item->release();
        }
    }
}

}  // namespace io
}  // namespace hotplace
