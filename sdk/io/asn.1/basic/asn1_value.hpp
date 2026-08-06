/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_value.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1VALUE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1VALUE__

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/types.hpp>

namespace hotplace {
namespace io {

/**
 * @comments
 *          // sketch
 *          {
 *              auto schema = new asn1_sequence;
 *              (*schema) << new asn1_builtin_type("name", asn1_entity_utf8string)
 *                        << new asn1_builtin_type("age", asn1_entity_integer);
 *              auto instance = schema->instantiate();
 *
 *              (*instance).set("name", "john").set("age", 20)
 *          }
 */
class asn1_value {
   public:
    asn1_value(asn1_object* schema);
    asn1_value(const asn1_value& other);
    ~asn1_value();

    asn1_value& operator=(const asn1_value& other);

    void set_schema(asn1_object* schema);
    asn1_object* get_schema();

    asn1_value& set(const variant& vt);
    asn1_value& set(std::initializer_list<variant> items);
    asn1_value& set(const std::string& name, const variant& vt);
    asn1_value& set(const std::string& name, std::initializer_list<variant> items);
    asn1_value& set(const std::string& name, variant&& vt);

    void publish(stream_t* b);
    void publish(binary_t* b);
    void write(stream_t* s, const std::string& name) const;

    bool find(const std::string& name) const;
    /**
     * value->find(name, values, vt_flag_string);
     */
    bool find(const std::string& name, std::list<variant>& values, uint16 vtflags) const;
    bool find(const std::string& name, std::list<std::string>& values, uint16 vtflags) const;
    void write(binary_t& bin, const asn1_object* object, const std::string& name, bool& do_len) const;
    void encode_sequenceof_value(binary_t& bin, const asn1_object* object, const std::string& name) const;
    void encode_setof_value(binary_t& bin, const asn1_object* object, const std::string& name) const;
    bool encode_namedlist(binary_t& bin, const asn1_object* object, const std::string& name, const std::map<std::string, asn1_native_int_t>& namedlist) const;

    void for_each(std::function<void(const std::string&, const variant& vt)> f);

    void addref();
    void release();

   protected:
   private:
    asn1_object* _schema;
    std::multimap<std::string, variant> _values;

    t_shared_reference<asn1_value> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
