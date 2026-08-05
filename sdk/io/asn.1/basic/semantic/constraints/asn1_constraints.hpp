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

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTS__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_ASN1CONSTRAINTS__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

/**
 * ITU-T X.682 ISO/IEC 8824-3
 */
class asn1_constraints {
    friend class asn1_object;

   public:
    asn1_constraints();
    asn1_constraints(const asn1_constraints& other);
    asn1_constraints(asn1_constraints&& other);
    virtual ~asn1_constraints() = default;

    asn1_constraints& operator=(const asn1_constraints& other);
    asn1_constraints& operator=(asn1_constraints&& other);

    asn1_constraints& add(asn1_constraint_t* cons, std::function<void(asn1_constraint_t*)> f = nullptr);
    bool empty() const;

    void represent(stream_t* s, const asn1_object* object, const asn1_value* value) const;

    bool validate(const asn1_object* node, const asn1_value* value) const;

    void addref();
    void release();

   protected:
    void dump(const variant& vt, bool test) const {
#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
            trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                dbs.printf("> ");
                vtprintf(&dbs, vt, vtprintf_style_t::vtprintf_style_asn1);
                dbs.println(" : %s ", test ? "valid" : "invalid");
            });
        }
#endif
    }

    template <typename T, typename std::enable_if<custom::is_integral<typename std::decay<T>::type>::value, int>::type = 0>
    bool do_validate(asn1_constraint_t* cons, const asn1_object* object, const asn1_value* value) const {
        asn1_constraint_evaluator<T> visitor;
        cons->accept(&visitor);

        auto entity = cons->get_entity();
        auto name = nameof(object);  // object->resolve_name()

        uint16 flags = 0;
        if (is_kind_of_integer(object))
            flags = vt_flag_int;
        else if (is_kind_of_real(object))
            flags = vt_flag_float;
        else if (is_kind_of_container_of(object))
            flags |= (vt_flag_int | vt_flag_float | vt_flag_string);
        else if (is_kind_of_cstring(object))
            flags = vt_flag_string;
        else if (is_kind_of_bstring(object))
            flags = vt_flag_string;

        std::list<variant> values;
        value->find(name, values, flags);

        if (is_kind_of_container_of(object)) {
            // SEQUENCE SIZE(1..5) OF
            auto size = values.size();
            return visitor.get_result_set().contains(size);
        } else {
            // asn1_entity_builtin_type
            bool test = false;
            for (const auto& vt : values) {
                if (asn1_entity_constraint_size == entity) {
                    auto size = vt.to_str().size();
                    auto oent = get_entity(object);
                    if (asn1_entity_octstring == oent) {
                        // OCTET STRING
                        if (size % 2) {
                            test = false;
                        } else {
                            size /= 2;
                            test = visitor.get_result_set().contains(size);
                        }
                    } else {
                        // BIT STRING and any other xxxSTRING
                        test = visitor.get_result_set().contains(size);
                    }
                } else if (vt_flag_int & flags) {
                    auto t = t_vtoi<int64>(vt.get());
                    test = visitor.get_result_set().contains(t);
                }
                dump(vt, test);
                if (false == test) return false;
            }
            return true;
        }
    }
    template <typename T, typename std::enable_if<std::is_floating_point<typename std::decay<T>::type>::value, int>::type = 0>
    bool do_validate(asn1_constraint_t* cons, const asn1_object* object, const asn1_value* value) const {
        asn1_constraint_evaluator<T> visitor;
        cons->accept(&visitor);

        auto name = nameof(object);  // object->resolve_name()

        uint16 flags = vt_flag_float;

        std::list<variant> values;
        value->find(name, values, flags);

        bool test = false;
        for (const auto& vt : values) {
            if (vt_flag_float & flags) {
                auto d = vt.get().data.d;
                test = visitor.get_result_set().contains(d);
                dump(vt, test);
                if (false == test) return false;
            }
        }
        return true;
    }
    /**
     * @param   asn1_constraint_t* cons [inopt] nullptr if object->get_entity() is asn1_enity_enum
     * @param   asn1_object* object [in] MUST not nullptr
     * @param   asn1_value* value [in]
     */
    template <typename T, typename std::enable_if<std::is_same<T, std::string>::value, int>::type = 0>
    bool do_validate(asn1_constraint_t* cons, const asn1_object* object, const asn1_value* value) const {
        auto name = nameof(object);  // object->resolve_name()

        uint16 flags = vt_flag_string;

        std::list<variant> values;
        value->find(name, values, flags);

        if (is_kind_of(object, asn1_entity_enum)) {
            if (values.empty()) return false;
            for (const auto& vt : values) {
                if (vt_flag_string & flags) {
                    auto s = vt.to_str();
                    auto test = evaluate(object, s);
                    dump(vt, test);
                    if (false == test) return false;
                }
            }
        } else {
            asn1_constraint_evaluator<T> visitor;
            cons->accept(&visitor);

            auto entity = cons->get_entity();

            bool test = false;
            for (const auto& vt : values) {
                if (vt_flag_string & flags) {
                    auto s = vt.to_str();
                    if (asn1_entity_constraint_from == entity) {
                        for (const auto& item : s) {
                            std::string temp;
                            temp.push_back(item);
                            test = visitor.get_result_set().match(temp);
                            if (false == test) break;
                        }
                    } else {
                        test = visitor.get_result_set().contains(s);
                    }
                    dump(vt, test);
                    if (false == test) return false;
                }
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
