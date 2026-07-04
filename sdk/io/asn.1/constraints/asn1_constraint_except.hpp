/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_constraint_except.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTEXCEPT__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_ASN1CONSTRAINTEXCEPT__

#include <hotplace/sdk/io/asn.1/constraints/asn1_constraint.hpp>

namespace hotplace {
namespace io {

/**
 */
template <typename T>
class asn1_constraint_except : public asn1_constraint<T> {
   public:
    asn1_constraint_except(asn1_constraint<T>* lhs, asn1_constraint<T>* rhs) : asn1_constraint_except() {
        if (nullptr == lhs || nullptr == rhs) {
            // throw exception(errorcode_t::invalid_parameter);
        }
        _lhs = lhs;
        _rhs = rhs;
        _lhs->set_parent(this);
        _rhs->set_parent(this);
    }
    virtual ~asn1_constraint_except() = default;

    asn1_constraint_except* clone() { return new asn1_constraint_except<T>(*this); }

    virtual bool is_applicable(asn1_entity_t entity) {
        switch (entity) {
            // TODO
            case asn1_entity_constraint_single:
            case asn1_entity_constraint_size:
            case asn1_entity_constraint_range:
            case asn1_entity_constraint_from:
            case asn1_entity_constraint_pattern:
            case asn1_entity_constraint_including:
            case asn1_entity_constraint_containing:
                return true;
                break;
            default:
                return false;
                break;
        }
    }

    virtual void addref() {
        asn1_constraint<T>::addref();
        _lhs->addref();
        _rhs->addref();
    }
    virtual void release() {
        _lhs->release();
        _rhs->release();
        asn1_constraint<T>::release();
    }

   protected:
    asn1_constraint_except() : asn1_constraint<T>(asn1_entity_constraint_except), _lhs(nullptr), _rhs(nullptr) {}
    asn1_constraint_except(const asn1_constraint_except& other) : asn1_constraint_except() { *this = other; }
    asn1_constraint_except(asn1_constraint_except&& other) : asn1_constraint_except() { *this = std::move(other); }
    asn1_constraint_except& operator=(const asn1_constraint_except& other) {
        if (_lhs) {
            _lhs->release();
            _lhs = nullptr;
        }
        if (_rhs) {
            _rhs->release();
            _rhs = nullptr;
        }
        if (other._lhs) {
            _lhs = other._lhs->clone();
            _lhs->set_parent(this);
        }
        if (other._rhs) {
            _rhs = other._rhs->clone();
            _rhs->set_parent(this);
        }
        return *this;
    }
    asn1_constraint_except& operator=(asn1_constraint_except&& other) {
        std::swap(_lhs, other._lhs);
        std::swap(_rhs, other._rhs);
        if (_lhs) _lhs->set_parent(this);
        if (_rhs) _rhs->set_parent(this);
        return *this;
    }

    virtual void accept(asn1_constraint_evaluator<T>* v) {
        if (_lhs && _rhs) {
            asn1_constraint_evaluator<T> visitor_lhs;
            asn1_constraint_evaluator<T> visitor_rhs;
            _lhs->accept(&visitor_lhs);
            _rhs->accept(&visitor_rhs);

            auto& result_lhs = visitor_lhs.get_result_set();
            auto& result_rhs = visitor_rhs.get_result_set();
            result_lhs.erase_from(result_rhs);

            auto& rs = v->get_result_set();
            rs = std::move(result_lhs);
        } else {
            // throw
        }
    }

    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr) {
        if (_lhs && _rhs) {
            auto lparenthesis = _lhs->is_operation();
            auto rparenthesis = _rhs->is_operation();

            if (lparenthesis) s->printf("(");
            _lhs->represent(s, object, value);
            if (lparenthesis) s->printf(")");
            s->printf(" EXCEPT ");
            if (rparenthesis) s->printf("(");
            _rhs->represent(s, object, value);
            if (rparenthesis) s->printf(")");
        } else {
            // throw
        }
    }

   private:
    asn1_constraint<T>* _lhs;
    asn1_constraint<T>* _rhs;
};

}  // namespace io
}  // namespace hotplace

#endif
