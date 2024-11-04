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

#ifndef __HOTPLACE_SDK_IO_ASN1__
#define __HOTPLACE_SDK_IO_ASN1__

#include <sdk/base/basic/base16.hpp>
#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/ieee754.hpp>
#include <sdk/base/basic/variant.hpp>
#include <sdk/base/pattern/trie.hpp>
#include <sdk/base/system/endian.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/io/asn.1/types.hpp>
#include <sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

class asn1_composite;
class asn1_object;
class asn1_tag;
class asn1_visitor;

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

    std::string _name;
    asn1_type_t _type;
    asn1_tag* _tag;
    int _component_type;  // default, optional

    asn1_object* _parent;
    asn1_object* _object;

    variant _var;

   private:
    t_shared_reference<asn1_object> _ref;
};

class asn1_data {
   public:
    asn1_data();

   private:
    variant _var;
};

/**
 * @brief   TaggedType
 *          TaggedType ::= Tag Type | Tag IMPLICIT Type | Tag EXPLICIT Type
 *          Tag ::= "[" Class ClassNumber "]"
 */
class asn1_tag : public asn1_object {
   public:
    asn1_tag(int cnumber, asn1_tag* tag = nullptr);
    asn1_tag(int cnumber, int tmode, asn1_tag* tag = nullptr);
    asn1_tag(int ctype, int cnumber, int tmode, asn1_tag* tag = nullptr);
    asn1_tag(const asn1_tag& rhs);

    virtual asn1_object* clone();

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

    int get_class() const;
    int get_class_number() const;
    int get_tag_type() const;
    bool is_implicit() const;
    void suppress();
    void unsuppress();

   protected:
    bool is_suppressed() const;

   private:
    int _class_type;    // Application
    int _class_number;  // 1
    int _tag_mode;      // implicit
    bool _suppress;
};

/**
 * @brief   SequenceType, SequenceOfType, SetType, SetOfType
 */
class asn1_container : public asn1_object {
   public:
    virtual ~asn1_container();

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

    asn1_container& operator<<(asn1_object* rhs);

    void addref();
    void release();

   protected:
    asn1_container(asn1_tag* tag);
    asn1_container(const std::string& name, asn1_tag* tag);
    asn1_container(const asn1_container& rhs);

    std::list<asn1_object*> _list;
};

/**
 * @brief   SequenceType
 * @example
 *          // snippet 1
 *          auto seq = new asn1_sequence;
 *          *seq << new asn1_object("name", asn1_type_ia5string) << new asn1_object("ok", asn1_type_boolean);
 *
 *          // snippet 2
 *          auto seq = new asn1_sequence(2, new asn1_object("name", asn1_type_ia5string), new asn1_object("ok", asn1_type_boolean));
 */
class asn1_sequence : public asn1_container {
   public:
    asn1_sequence(asn1_tag* tag = nullptr);
    asn1_sequence(const std::string& name, asn1_tag* tag = nullptr);
    asn1_sequence(const asn1_sequence& rhs);
    asn1_sequence(int count, ...);
    asn1_sequence(asn1_tag* tag, int count, ...);

    virtual asn1_object* clone();

    virtual void represent(binary_t* b);

   protected:
};

/**
 * @brief   SequenceOfType ::= SEQUENCE OF Type | SEQUENCE OF NamedType
 */
class asn1_sequence_of : public asn1_container {
   public:
    asn1_sequence_of(asn1_tag* tag = nullptr);
    asn1_sequence_of(const std::string& name, asn1_tag* tag = nullptr);
    asn1_sequence_of(const asn1_sequence_of& rhs);

    virtual asn1_object* clone();

    virtual void represent(binary_t* b);

   protected:
};

/**
 * @brief   SetType
 * @sample
 *      ChildInformation ::= SET {name Name, dateOfBirth [0] Date}
 *
 *      asn1_set* node_childinfo = new asn1_set("ChildInformation");
 *      *node_childinfo << new asn1_namedtype("name", new asn1_referenced_type("Name"))
 *                      << new asn1_namedtype("dateOfBirth", new asn1_referenced_type("Date", new asn1_tag(0)));
 *      node_childinfo->release();
 */
class asn1_set : public asn1_container {
   public:
    asn1_set(asn1_tag* tag = nullptr);
    asn1_set(const std::string& name, asn1_tag* tag = nullptr);
    asn1_set(const asn1_set& rhs);

    asn1_object* clone();

    virtual void represent(binary_t* b);

   protected:
};

/**
 * @brief   SetOfType ::= SET OF Type | SET OF NamedType
 */
class asn1_set_of : public asn1_container {
   public:
    asn1_set_of(asn1_tag* tag = nullptr);
    asn1_set_of(const std::string& name, asn1_tag* tag = nullptr);
    asn1_set_of(const asn1_set_of& rhs);

    asn1_object* clone();

    virtual void represent(binary_t* b);

   protected:
};

class asn1_composite : public asn1_object {
   public:
    /**
     * asn1_type_t type MUST be asn1_type_primitive or asn1_type_constructed
     */
    asn1_composite(asn1_type_t type, asn1_object* obj, asn1_tag* tag = nullptr);
    asn1_composite(const asn1_composite& rhs);
    virtual ~asn1_composite();

    virtual asn1_object* clone();

    asn1_composite& as_primitive();
    asn1_composite& as_constructed();

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

    asn1_object* get_object();

   protected:
    void clear();

   private:
    asn1_object* _object;
};

class asn1 {
   public:
    asn1();
    asn1(const asn1& rhs);
    virtual ~asn1();

    asn1* clone();

    // types
    asn1& add_type(asn1_object* item);
    asn1& operator<<(asn1_object* item);

    /**
     * @brief   values
     * @sample
     *          set_value_byname("name", "Smith").set_value_byname("ok", true);
     */
    asn1& set_value_byname(const std::string& name, const variant& value);
    asn1& set_value_byname(const std::string& name, variant&& value);
    asn1& set_value_byindex(unsigned index, const variant& value);
    asn1& set_value_byindex(unsigned index, variant&& value);
    asn1_object* operator[](const std::string& name);
    asn1_object* operator[](unsigned index);

    void publish(binary_t* b);
    void publish(stream_t* s);

    void addref();
    void release();

    void clear();

   protected:
   private:
    t_shared_reference<asn1> _ref;
    std::list<asn1_object*> _types;

    typedef std::map<std::string, asn1_object*> dictionary_t;
    typedef std::map<std::string, variant> namevalues_t;
    typedef std::map<unsigned, variant> indexvalues_t;

    dictionary_t _dictionary;
    namevalues_t _namevalues;
    indexvalues_t _idxvalues;

    parser _parser;
};

class asn1_encode {
   public:
    asn1_encode();

    asn1_encode& null(binary_t& bin);
    asn1_encode& primitive(binary_t& bin, bool value);
    asn1_encode& primitive(binary_t& bin, int8 value);
    asn1_encode& primitive(binary_t& bin, uint8 value);
    asn1_encode& primitive(binary_t& bin, int16 value);
    asn1_encode& primitive(binary_t& bin, uint16 value);
    asn1_encode& primitive(binary_t& bin, int32 value);
    asn1_encode& primitive(binary_t& bin, uint32 value);
    asn1_encode& primitive(binary_t& bin, int64 value);
    asn1_encode& primitive(binary_t& bin, uint64 value);
    asn1_encode& primitive(binary_t& bin, int128 value);
    asn1_encode& primitive(binary_t& bin, uint128 value);
    asn1_encode& primitive(binary_t& bin, float value);
    asn1_encode& primitive(binary_t& bin, double value);
    asn1_encode& primitive(binary_t& bin, asn1_type_t type, const std::string& value);
    asn1_encode& primitive(binary_t& bin, asn1_tag_t type, const std::string& value);
    asn1_encode& oid(binary_t& bin, const std::string& value);
    asn1_encode& reloid(binary_t& bin, const std::string& value);
    asn1_encode& encode(binary_t& bin, asn1_type_t type, const binary_t& value);
    asn1_encode& encode(binary_t& bin, asn1_type_t type, const variant& value);
    asn1_encode& encode(binary_t& bin, int tag, int class_number);

    asn1_encode& bitstring(binary_t& bin, const std::string& value);
    asn1_encode& generalstring(binary_t& bin, const std::string& value);
    asn1_encode& ia5string(binary_t& bin, const std::string& value);
    asn1_encode& octstring(binary_t& bin, const std::string& value);
    asn1_encode& printablestring(binary_t& bin, const std::string& value);
    asn1_encode& t61string(binary_t& bin, const std::string& value);
    asn1_encode& visiblestring(binary_t& bin, const std::string& value);

    asn1_encode& generalized_time(binary_t& bin, const datetime_t& dt);
    asn1_encode& generalized_time(basic_stream& bs, const datetime_t& dt);
    asn1_encode& utctime(binary_t& bin, const datetime_t& dt, int tzoffset = 0);
    asn1_encode& utctime(basic_stream& bs, const datetime_t& dt, int tzoffset = 0);

    asn1_encode& indef(binary_t& bin);
    asn1_encode& end_contents(binary_t& bin);

   protected:
};

class asn1_resource {
   public:
    static asn1_resource* get_instance();

    std::string get_type_name(asn1_type_t t);
    asn1_type_t get_type(const std::string& name);
    std::string get_class_name(int c);
    /**
     * @brief   IMPLICIT/EXPLICIT
     */
    std::string get_tagtype_name(uint32 t);
    std::string get_componenttype_name(uint32 t);

    void for_each_type_name(std::function<void(asn1_type_t, const std::string&)> f);

   protected:
    asn1_resource();
    void load_resource();

    static asn1_resource _instance;

    std::map<asn1_type_t, std::string> _type_id;
    std::map<std::string, asn1_type_t> _type_rid;
    std::map<int, std::string> _class_id;
};

}  // namespace io
}  // namespace hotplace

#endif
