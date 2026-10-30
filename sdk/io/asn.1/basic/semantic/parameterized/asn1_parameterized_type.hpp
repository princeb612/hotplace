/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_parameterized_type.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_PARAMETERIZED_ASN1PARAMETERIZEDTYPE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_PARAMETERIZED_ASN1PARAMETERIZEDTYPE__

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/types.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   parameterization
 * @remarks
 *          asn1_parameterized_type - std::vector<asn1_paramvalue>
 *          asn1_parameter - link with name
 */

class HOTPLACE_IO_API asn1_parameterized_type : public asn1_type {
   public:
    virtual ~asn1_parameterized_type();

    virtual asn1_parameterized_type* clone();

    /**
     * generate a template using the pre-configured add_paramtype and object.
     */
    static asn1_parameterized_type* define(const asn1_paramtypes& types, const std::string& name, asn1_object* object);
    /**
     * automatically configures by calling add_paramtype internally.
     * can also configure it so that it is not added automatically by setting it up beforehand using `add_paramtype`.
     */
    static asn1_parameterized_type* define(const std::string& name, std::function<asn1_object*(asn1_parameterized_type*)> func);
    /**
     *
     */
    static asn1_specialized_type* specialize(const std::string& name, asn1_parameterized_type* type, const asn1_paramvalues& values);
    asn1_specialized_type* specialize(const std::string& name, const asn1_paramvalues& values);

    void set_module(asn1_module* module);
    asn1_module* get_module() const;

    asn1_paramtypes& get_types();

    /**
     * {TypeParameter}
     * add_paramtype("TypeParameter")
     */
    asn1_parameterized_type& add_paramtype(const std::string& paramtype, const std::string& paramname = "");

    virtual void represent(stream_t* s, const asn1_value* value = nullptr) const;
    virtual bool represent(binary_t* b, const asn1_value* value = nullptr, uint16 flags = 0) const;

    void for_each(std::function<void(asn1_paramtype*)> func) {
        for (auto& type : _types) func(&type);
    }

    // void add(asn1_object* object);
    // template <typename F>
    // void for_each_deferred(F&& func) { for (auto member : _deferred) std::forward<F>(func)(member); }
    // void for_each_deferred(std::function<void(asn1_object*)> func) { for_each_deferred(func); }

   protected:
    asn1_parameterized_type(const asn1_paramtypes& types, const std::string& name, asn1_object* object);
    asn1_parameterized_type(const asn1_parameterized_type& other);
    asn1_parameterized_type& operator=(const asn1_parameterized_type& other);
    void clear();

   private:
    asn1_parameterized_type* _templ{nullptr};
    asn1_module* _module{nullptr};
    asn1_paramtypes _types;
    // std::list<asn1_object*> _deferred;
};

}  // namespace io
}  // namespace hotplace

#endif
