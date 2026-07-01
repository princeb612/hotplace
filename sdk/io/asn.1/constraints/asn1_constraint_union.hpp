/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_union.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTUNION__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTUNION__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 * @example
 *          auto type =
 *              asn1_referenced_type::define("type",
 *                  asn1_builder::build(asn1_entity_integer,
 *                              [&](asn1_builtin_type* builtin) -> void {
 *                                  builtin->get_constraints().add(
 *                                          new asn1_constraint_union<int>(
 *                                              new asn1_constraint_range<int>(1, 10),
 *                                              new asn1_constraint_range<int>(20, 30)));
 *                              }));
 */
template <typename T>
class asn1_constraint_union : public asn1_constraint_base<T> {
   public:
    asn1_constraint_union(asn1_constraint* lhs, asn1_constraint* rhs) : asn1_constraint_base<T>(asn1_entity_constraint_union) {
        if (nullptr == lhs || nullptr == rhs) {
            // throw exception(errorcode_t::invalid_parameter);
        }

        lhs->set_parent(this);
        rhs->set_parent(this);

        _items.push_back(lhs);
        _items.push_back(rhs);
    }
    asn1_constraint_union(const std::initializer_list<asn1_constraint*>& items) : asn1_constraint_base<T>(asn1_entity_constraint_union) {
        if (items.size() < 2) {
            // throw exception(errorcode_t::invalid_parameter);
        }

        for (auto item : items) {
            item->set_parent(this);
            _items.push_back(item);
        }
    }
    asn1_constraint_union(const std::initializer_list<int>& items) : asn1_constraint_base<T>(asn1_entity_constraint_union) {
        if (items.size() < 2) {
            // throw exception(errorcode_t::invalid_parameter);
        }

        for (auto item : items) {
            auto obj = new asn1_constraint_single_value<T>(item);
            obj->set_parent(this);
            _items.push_back(obj);
        }
    }
    asn1_constraint_union(const std::initializer_list<std::string>& items) : asn1_constraint_base<T>(asn1_entity_constraint_union) {
        if (items.size() < 2) {
            // throw exception(errorcode_t::invalid_parameter);
        }

        for (auto item : items) {
            auto obj = new asn1_constraint_single_value<T>(item);
            obj->set_parent(this);
            _items.push_back(obj);
        }
    }

    virtual ~asn1_constraint_union() = default;

    asn1_constraint_union* clone() { return new asn1_constraint_union<T>(*this); }

    virtual bool is_applicable(asn1_entity_t entity) {
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
                return true;
                break;
            default:
                return false;
                break;
        }
    }

    virtual void addref() {
        asn1_constraint_base<T>::addref();
        for (auto item : _items) {
            item->addref();
        }
    }
    virtual void release() {
        for (auto item : _items) {
            item->release();
        }
        asn1_constraint_base<T>::release();
    }

   protected:
    asn1_constraint_union(const asn1_constraint_union& other) : asn1_constraint_base<T>(asn1_entity_constraint_union) { *this = other; }
    asn1_constraint_union& operator=(const asn1_constraint_union& other) {
        for (auto item : other._items) {
            auto obj = item->clone();
            obj->set_parent(this);
            _items.push_back(obj);
        }
        return *this;
    }

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr) {
        if (false == _items.empty()) {
            auto iter = _items.begin();
            (*iter)->represent(s, object, value);
            while (++iter != _items.end()) {
                s->printf(" | ");
                (*iter)->represent(s, object, value);
            }
        }
    }

   private:
    std::list<asn1_constraint*> _items;
};

}  // namespace io
}  // namespace hotplace

#endif
