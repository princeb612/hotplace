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

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1PARAMETERIZEDTYPE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1PARAMETERIZEDTYPE__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   parameterization
 * @remarks
 *          FRAME{TypeParam, INTEGER:maxSize} ::= SEQUENCE {
 *              header  INTEGER,
 *              payload TypeParam,
 *              length  INTEGER (0..maxSize)
 *          }
 *          MyPacket ::= FRAME{ OCTET STRING, 1024 }
 *
 */

enum class asn1_paramtype_t {
    type,
    value,
};
enum class asn1_paramvalue_t {
    entity,
    literal,
    object,
    value,
};

struct asn1_paramtype {
    std::string type;
    std::string name;

    asn1_paramtype(const std::string& t);
    asn1_paramtype(const std::string& t, const std::string& n);

    asn1_paramtype(const asn1_paramtype& other);
    asn1_paramtype(asn1_paramtype&& other);
    asn1_paramtype& operator=(const asn1_paramtype& other);
    asn1_paramtype& operator=(asn1_paramtype&& other);
    bool operator==(const asn1_paramtype& other) const;
    bool operator<(const asn1_paramtype& other) const;

    void represent(stream_t* s, const asn1_value* value) const;
};

struct asn1_paramvalue {
    asn1_paramvalue_t type{asn1_paramvalue_t::entity};
    asn1_entity_t entity{asn1_entity_t::asn1_entity_unknown};
    std::string name;
    asn1_object* object{nullptr};
    variant value;

    asn1_paramvalue(asn1_entity_t e);
    asn1_paramvalue(const char* s);
    asn1_paramvalue(asn1_object* o);
    asn1_paramvalue(const variant& v);
    asn1_paramvalue(variant&& v);

    asn1_paramvalue(const asn1_paramvalue& other);
    asn1_paramvalue(asn1_paramvalue&& other);
    asn1_paramvalue& operator=(const asn1_paramvalue& other);
    asn1_paramvalue& operator=(asn1_paramvalue&& other);

    void represent(stream_t* s, const asn1_value* value) const;
};

typedef std::vector<asn1_paramtype> asn1_paramtypes;
typedef std::vector<asn1_paramvalue> asn1_paramvalues;

/**
 * @brief   parameterization
 * @remarks
 *          asn1_parameterized_type - std::vector<asn1_paramvalue>
 *          asn1_parameter - link with name
 */

class asn1_parameterized_type : public asn1_type {
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
    static asn1_parameterized_type* specialize(const std::string& name, asn1_parameterized_type* type, const asn1_paramvalues& values);
    asn1_parameterized_type* specialize(const std::string& name, const asn1_paramvalues& values);

    asn1_paramtypes& get_types();
    asn1_paramvalues& get_values();

    /**
     * {TypeParameter}
     * add_paramtype("TypeParameter")
     */
    asn1_parameterized_type& add_paramtype(const std::string& paramtype, const std::string& paramname = "");
    // asn1_parameterized_type& add_param(asn1_parameter*);

    virtual void represent(stream_t* s, const asn1_value* value = nullptr) const;
    virtual bool represent(binary_t* b, const asn1_value* value = nullptr, uint16 flags = 0) const;

    void for_each(std::function<void(asn1_paramtype*)> func) {
        for (auto& type : _types) func(&type);
    }
    void for_each(std::function<void(asn1_paramvalue*)> func) {
        for (auto& value : _values) func(&value);
    }

   protected:
    asn1_parameterized_type(const asn1_paramtypes& types, const std::string& name, asn1_object* object);
    asn1_parameterized_type(const asn1_parameterized_type& other);
    asn1_parameterized_type& operator=(const asn1_parameterized_type& other);
    void clear();

   private:
    asn1_parameterized_type* _templ{nullptr};
    asn1_paramtypes _types;
    asn1_paramvalues _values;
};

class asn1_parameter : public asn1_type {
   public:
    asn1_parameter(asn1_parameterized_type* templ, const std::string& name, const std::string& paramtype);
    asn1_parameter(const asn1_parameter& other);
    virtual ~asn1_parameter();

    asn1_parameter& operator=(const asn1_parameter& other);

    virtual asn1_object* clone();

    template <typename U>
    static t_value<U> value(asn1_parameterized_type* templ, const std::string& param, const std::string& name) {
        templ->add_paramtype(param, name);
        t_value<U> v(U{}, name, true);
        return v;
    }

    virtual void represent(stream_t* s, const asn1_value* value = nullptr) const;
    virtual bool represent(binary_t* b, const asn1_value* value = nullptr, uint16 flags = 0) const;

   private:
    asn1_parameterized_type* _templ{nullptr};
    std::string _param;
    variant _vt;
};

}  // namespace io
}  // namespace hotplace

#endif
