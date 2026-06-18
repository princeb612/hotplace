/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_visitor.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1VISOTOR__
#define __HOTPLACE_SDK_IO_ASN1_ASN1VISOTOR__

#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

class asn1_object;
class asn1_tag;

class asn1_visitor {
   public:
    asn1_visitor() {}
    virtual ~asn1_visitor() {}

    virtual void visit(asn1_object* object) {}
};

class asn1_der_visitor : public asn1_visitor {
   public:
    asn1_der_visitor(binary_t* b, asn1_value* value = nullptr);
    virtual ~asn1_der_visitor();

    virtual void visit(asn1_object* object);

   protected:
    binary_t* get_binary();

   private:
    binary_t* _b;
    asn1_value* _value;
};

class asn1_notation_visitor : public asn1_visitor {
   public:
    asn1_notation_visitor(stream_t* s, asn1_value* value = nullptr);
    virtual ~asn1_notation_visitor();

    virtual void visit(asn1_object* object);

   protected:
    stream_t* get_stream();

   private:
    stream_t* _s;
    asn1_value* _value;
};

}  // namespace io
}  // namespace hotplace

#endif
