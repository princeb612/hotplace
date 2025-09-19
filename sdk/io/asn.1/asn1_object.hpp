/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_ASN1OBJECT__
#define __HOTPLACE_SDK_IO_ASN1_ASN1OBJECT__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   ASN.1
 * @sample
 *          new asn1_object(asn1_type_null);            // NULL
 *          new asn1_object(asn1_type_boolean);         // BOOLEAN
 *          new asn1_object(asn1_type_integer);         // INTEGER
 *          new asn1_object(asn1_type_real);            // REAL
 *          new asn1_object(asn1_type_visiblestring);   // VisibleString
 *          new asn1_object(asn1_type_ia5string);       // IA5String
 *
 *          // SEQUENCE {name UTF8String, id UTF8String, profile Profile}
 *          auto seq = new asn1_sequence;
 *          *seq << new asn1_object("name", asn1_type_utf8string)
 *               << new asn1_object("age", asn1_type_utf8string)
 *               << new asn1_object("profile", new asn1_object("Profile", asn1_type_referenced));
 */
class asn1_object {
    friend class asn1_composite;
    friend class asn1_container;

   public:
    asn1_object(asn1_type_t type, asn1_tag* tag = nullptr);
    asn1_object(const std::string& name, asn1_type_t type, asn1_tag* tag = nullptr);
    asn1_object(const std::string& name, asn1_object* object, asn1_tag* tag = nullptr);
    asn1_object(const asn1_object& rhs);
    virtual ~asn1_object();

    virtual asn1_object* clone();

    virtual void accept(asn1_visitor* v);
    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

    asn1_object* get_parent() const;
    const std::string& get_name() const;
    asn1_type_t get_type() const;
    asn1_tag* get_tag() const;

    // ComponentType
    int get_componenttype();
    asn1_object& as_default();
    asn1_object& as_optional();

    variant& get_data();
    const variant& get_data() const;

    void addref();
    void release();

   protected:
    asn1_object& set_parent(asn1_object* parent);
    asn1_object& set_type(asn1_type_t type);

    void clear();

   private:
    std::string _name;
    asn1_type_t _type;
    asn1_tag* _tag;
    int _component_type;  // default, optional

    asn1_object* _parent;
    asn1_object* _object;

    variant _var;

    t_shared_reference<asn1_object> _ref;
};

}  // namespace io
}  // namespace hotplace

#endif
