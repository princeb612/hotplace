/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_TYPES__
#define __HOTPLACE_SDK_IO_ASN1_CONSTRAINTS_TYPES__

#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

class asn1_constraint {
   public:
    virtual ~asn1_constraint() = default;

    virtual asn1_constraint* clone() = 0;

    virtual asn1_entity_t get_entity() = 0;
    virtual bool is_operation() = 0;

    virtual asn1_constraint* get_parent() = 0;
    virtual void set_parent(asn1_constraint* parent) = 0;

    virtual void accept(asn1_constraint_visitor* v) = 0;
    virtual void represent(stream_t* s, asn1_object* object, asn1_value* value = nullptr) = 0;

    virtual void addref() = 0;
    virtual void release() = 0;
};

}  // namespace io
}  // namespace hotplace

#endif
