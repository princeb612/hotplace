/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_parameter.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_PARAMETERIZED_ASN1PARAMETER__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_PARAMETERIZED_ASN1PARAMETER__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_parameterized_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/types.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

class HOTPLACE_IO_API asn1_parameter : public asn1_type {
   public:
    asn1_parameter(asn1_parameterized_type* templ, const std::string& name, const std::string& paramtype);
    asn1_parameter(const asn1_parameter& other);
    virtual ~asn1_parameter();

    asn1_parameter& operator=(const asn1_parameter& other);

    virtual asn1_object* clone();

    template <typename U>
    static t_value<U> value(asn1_parameterized_type* templ, const std::string& param, const std::string& name) {
        templ->add_paramtype(param, name);
        t_value<U> v(U{}, name);
        return v;
    }

    virtual void represent(stream_t* s, const asn1_value* value = nullptr) const;
    virtual bool represent(binary_t* b, const asn1_value* value = nullptr, uint16 flags = 0) const;

    void set(asn1_specialized_type* spec);
    asn1_specialized_type* get_specialized_type() const;
    void set_module(asn1_module* module);
    asn1_module* get_module() const;

   protected:
    asn1_parameterized_type* get_parameterized_type() const;

   private:
    asn1_parameterized_type* _templ{nullptr};
    asn1_specialized_type* _spec{nullptr};
    std::string _param;
    variant _vt;
    asn1_object* _instance{nullptr};
    asn1_module* _module{nullptr};
};

}  // namespace io
}  // namespace hotplace

#endif
