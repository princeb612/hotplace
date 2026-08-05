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

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_TYPES__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_CONSTRAINTS_TYPES__

#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

class asn1_constraint_t {
   public:
    virtual ~asn1_constraint_t() = default;

    virtual asn1_constraint_t* clone() = 0;

    virtual asn1_entity_t get_entity() const = 0;
    virtual bool is_operation() const = 0;

    virtual void accept(asn1_constraint_visitor* v) = 0;
    virtual void represent(stream_t* s, const asn1_object* object, const asn1_value* value = nullptr) const = 0;

    virtual void addref() = 0;
    virtual void release() = 0;
};

}  // namespace io
}  // namespace hotplace

#endif
