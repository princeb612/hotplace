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

asn1_constraints::asn1_constraints(const asn1_constraints& other) { *this = other; }

asn1_constraints::asn1_constraints(asn1_constraints&& other) { *this = std::move(other); }

asn1_constraints& asn1_constraints::operator=(const asn1_constraints& other) {
    if (false == other._constraints.empty()) {
        for (auto& item : other._constraints) {
            add(item->clone());
        }
    }
    return *this;
}

asn1_constraints& asn1_constraints::operator=(asn1_constraints&& other) {
    _constraints = std::move(other._constraints);
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

bool asn1_constraints::empty() { return _constraints.empty(); }

void asn1_constraints::represent(stream_t* s, asn1_object* object, asn1_value* value) {
    if (false == _constraints.empty()) {
        for (auto& item : _constraints) {
            s->printf(" (");
            asn1_constraint_notation_visitor visitor(s, object);
            item->accept(&visitor);
            s->printf(")");
        }
    }
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
