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

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

/**
 * ITU-T X.682 ISO/IEC 8824-3
 */
class asn1_constraints {
    friend class asn1_builtin_type;
    friend class asn1_constraints_except;
    friend class asn1_constraints_intersection;
    friend class asn1_constraints_single_value;
    friend class asn1_constraints_union;
    friend class asn1_constraints_visitor;
    friend class asn1_object;

   public:
    virtual ~asn1_constraints();

    virtual asn1_constraints* clone();

    bool is_applicable(asn1_object* object);
    virtual bool is_applicable(asn1_entity_t entity);

    asn1_entity_t get_entity();
    bool is_set_family();
    asn1_constraints* get_parent();

    virtual void addref();
    virtual void release();

   protected:
    asn1_constraints(asn1_entity_t entity);
    void set_parent(asn1_constraints* parent);

    asn1_constraints(const asn1_constraints& other);
    asn1_constraints& operator=(const asn1_constraints& other);

    virtual void accept(asn1_constraints_visitor* v);
    virtual void represent(stream_t* s, asn1_value* value = nullptr);

   private:
    asn1_entity_t _entity;
    asn1_constraints* _parent;

    t_shared_reference<asn1_constraints> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
