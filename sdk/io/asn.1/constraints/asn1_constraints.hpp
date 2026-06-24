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
   public:
    asn1_constraints(asn1_entity_t entity);
    virtual ~asn1_constraints();

    bool is_applicable(asn1_object* object);
    virtual bool is_applicable(asn1_entity_t entity);

    asn1_entity_t get_entity();

    void addref();
    void release();

   protected:
   private:
    asn1_entity_t _entity;

    t_shared_reference<asn1_constraints> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
