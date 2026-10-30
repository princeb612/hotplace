/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_specialized_type.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_PARAMETERIZED_ASN1SPECIALIZEDTYPE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_PARAMETERIZED_ASN1SPECIALIZEDTYPE__

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/types.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

class HOTPLACE_IO_API asn1_specialized_type : public asn1_type {
   public:
    asn1_specialized_type(asn1_parameterized_type* templ, const asn1_paramvalues& values, const std::string& name, asn1_object* object);
    asn1_specialized_type(const asn1_specialized_type& other);
    virtual ~asn1_specialized_type();

    asn1_specialized_type& operator=(const asn1_specialized_type& other);

    virtual asn1_specialized_type* clone();

    virtual void represent(stream_t* s, const asn1_value* value = nullptr) const;
    virtual bool represent(binary_t* b, const asn1_value* value = nullptr, uint16 flags = 0) const;

    asn1_parameterized_type* get_parameterized_type() const;
    asn1_paramvalues& get_values();

    void for_each(std::function<void(asn1_paramvalue*)> func) {
        for (auto& value : _values) func(&value);
    }
    bool lookup_name(const std::string& name, std::string& value) const;
    bool lookup_value(const std::string& name, asn1_paramvalue& value) const;

   protected:
    asn1_parameterized_type* _templ{nullptr};
    asn1_paramvalues _values;
};

}  // namespace io
}  // namespace hotplace

#endif
