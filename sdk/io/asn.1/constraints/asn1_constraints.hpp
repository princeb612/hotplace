/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraints.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTS__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTS__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 * ITU-T X.682 ISO/IEC 8824-3
 */
class asn1_constraints {
   public:
    asn1_constraints() = default;
    asn1_constraints(const asn1_constraints& other);
    asn1_constraints(asn1_constraints&& other);
    virtual ~asn1_constraints() = default;

    asn1_constraints& operator=(const asn1_constraints& other);
    asn1_constraints& operator=(asn1_constraints&& other);

    asn1_constraints& add(asn1_constraint_t* cons, std::function<void(asn1_constraint_t*)> f = nullptr);
    bool empty();

    void represent(stream_t* s, asn1_object* object, asn1_value* value);

    bool validate(asn1_object* node, asn1_value* value) {
        if (nullptr == node || nullptr == value) return false;

        if (false == _constraints.empty()) {
            for (auto item : _constraints) {
                bool test = false;
                auto entity = item->get_entity();
                if (is_kind_of_integer(node)) {
                    test = do_validate<int64>(item, node, value);
                } else if (is_kind_of_real(node)) {
                    test = do_validate<double>(item, node, value);
                } else if (is_kind_of_cstring(node)) {
                    switch (entity) {
                        case asn1_entity_constraint_size:
                            test = do_validate<int64>(item, node, value);
                            break;
                        default:
                            test = do_validate<std::string>(item, node, value);
                            break;
                    }
                }
                if (false == test) return false;
            }
        }
        return true;
    }

    void addref();
    void release();

   protected:
    template <typename T, typename std::enable_if<custom::is_integral<typename std::decay<T>::type>::value, int>::type = 0>
    bool do_validate(asn1_constraint_t* cons, asn1_object* object, asn1_value* value) {
        asn1_constraint_evaluator<T> visitor;
        cons->accept(&visitor);

        auto entity = cons->get_entity();
        auto name = nameof(object);  // object->resolve_name()

        uint16 flags = 0;
        if (asn1_entity_constraint_size == entity)
            flags |= vt_flag_string;
        else
            flags |= vt_flag_int;

        std::list<variant> values;
        value->find(name, values, flags);

        bool test = false;
        for (const auto& vt : values) {
            if (asn1_entity_constraint_size == entity) {
                auto size = vt.to_str().size();
                test = visitor.get_result_set().contains(size);
            } else if (vt_flag_int & flags) {
                auto t = t_vtoi<int64>(vt.content());
                test = visitor.get_result_set().contains(t);
            }
            if (false == test) return false;
        }
        return true;
    }
    template <typename T, typename std::enable_if<std::is_floating_point<typename std::decay<T>::type>::value, int>::type = 0>
    bool do_validate(asn1_constraint_t* cons, asn1_object* object, asn1_value* value) {
        asn1_constraint_evaluator<T> visitor;
        cons->accept(&visitor);

        auto name = nameof(object);  // object->resolve_name()

        uint16 flags = 0;
        flags = std::is_arithmetic<T>::value ? vt_flag_int : vt_flag_string;
        flags |= std::is_floating_point<T>::value ? vt_flag_float : 0;

        std::list<variant> values;
        value->find(name, values, flags);

        bool test = false;
        for (const auto& vt : values) {
            if (vt_flag_float & flags) {
                auto d = vt.content().data.d;
                test = visitor.get_result_set().contains(d);
                if (false == test) return false;
            }
        }
        return true;
    }
    template <typename T, typename std::enable_if<std::is_same<T, std::string>::value, int>::type = 0>
    bool do_validate(asn1_constraint_t* cons, asn1_object* object, asn1_value* value) {
        asn1_constraint_evaluator<T> visitor;
        cons->accept(&visitor);

        auto name = nameof(object);  // object->resolve_name()

        uint16 flags = 0;
        flags = std::is_arithmetic<T>::value ? vt_flag_int : vt_flag_string;

        std::list<variant> values;
        value->find(name, values, flags);

        bool test = false;
        for (const auto& vt : values) {
            if (vt_flag_string & flags) {
                auto s = vt.to_str();
                test = visitor.get_result_set().contains(s);
                if (false == test) return false;
            }
        }
        return true;
    }

   private:
    std::list<asn1_constraint_t*> _constraints;
};

}  // namespace io
}  // namespace hotplace

#endif
