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

#include <sdk/base.hpp>
#include <sdk/io/asn.1/types.hpp>
#include <sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

class asn1_object;
class asn1_tagged;

class asn1_visitor {
   public:
    virtual void visit(asn1_object* object) = 0;
};

class asn1_encoder : public asn1_visitor {
   public:
    asn1_encoder(binary_t* b);
    virtual void visit(asn1_object* object);

   protected:
    binary_t* get_binary();

    binary_t* _b;
};

class asn1_notation : public asn1_visitor {
   public:
    asn1_notation(stream_t* s);
    virtual void visit(asn1_object* object);

   protected:
    stream_t* get_stream();

    stream_t* _s;
};

class asn1_object {
   public:
    asn1_object(asn1_type_t type, asn1_tagged* tag = nullptr);
    const std::string& get_name() const;
    asn1_type_t get_type() const;
    asn1_tagged* get_tag();
    int get_componenttype();
    asn1_object& set_default();
    asn1_object& set_optional();

    variant& get_data();
    const variant& get_data() const;

    virtual void accept(asn1_visitor* v);
    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

    void addref();
    void release();

   protected:
    asn1_object(const std::string& name, asn1_type_t type, asn1_tagged* tag);

    std::string _name;
    asn1_type_t _type;
    asn1_tagged* _tag;
    int _component_type;  // default, optional
    variant _var;

   private:
    t_shared_reference<asn1_object> _ref;
};

class asn1_namedobject : public asn1_object {
   public:
    asn1_namedobject(const std::string& name, asn1_type_t type, asn1_tagged* tag = nullptr);

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   protected:
   private:
};

class asn1_tagged : public asn1_object {
   public:
    asn1_tagged(asn1_class_t c, int cn, int tt = 0);

    asn1_class_t get_class();
    int get_class_number();
    int get_tag_type();

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   protected:
   private:
    asn1_class_t _class;
    int _class_number;
    int _tag_type;
};

class asn1_type_defined : public asn1_namedobject {
   public:
    asn1_type_defined(const std::string& name, asn1_tagged* tag = nullptr);

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);
};

class asn1_type : public asn1_object {
   public:
    asn1_type(asn1_type_t type, asn1_tagged* tag = nullptr);

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);
};

/**
 * @brief   NamedType ::= identifier Type
 */
class asn1_namedtype : public asn1_namedobject {
   public:
    asn1_namedtype(const std::string& name, asn1_object* object);

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   protected:
    asn1_object* _object;
};

/**
 * @brief   SequenceType, SequenceOfType, SetType, SetOfType
 */
class asn1_container : public asn1_namedobject {
   public:
    asn1_container(const std::string& name, asn1_tagged* tag);

    asn1_container& operator<<(asn1_namedtype* rhs);

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   protected:
    std::list<asn1_namedtype*> _list;
};

/**
 * @brief   SequenceType
 */
class asn1_sequence : public asn1_container {
   public:
    asn1_sequence(const std::string& name, asn1_tagged* tag = nullptr);

    virtual void represent(binary_t* b);
};

/**
 * @brief   SequenceOfType ::= SEQUENCE OF Type | SEQUENCE OF NamedType
 */
class asn1_sequence_of : public asn1_container {
   public:
    asn1_sequence_of(const std::string& name, asn1_tagged* tag = nullptr);

    virtual void represent(binary_t* b);
};

/**
 * @brief   SetType
 */
class asn1_set : public asn1_container {
   public:
    asn1_set(const std::string& name, asn1_tagged* tag = nullptr);

    virtual void represent(binary_t* b);
};

/**
 * @brief   SetOfType ::= SET OF Type | SET OF NamedType
 */
class asn1_set_of : public asn1_container {
   public:
    asn1_set_of(const std::string& name, asn1_tagged* tag = nullptr);

    virtual void represent(binary_t* b);
};

class asn1 {
   public:
    asn1();
    ~asn1();

    /**
     * @brief   rule-based
     *          p.add.rule(...).add_rule(...).learn();
     * @sa      ITU-T X.680 Abstract Syntax Notation One (ASN.1): Specification of basic notation
     */
    asn1& add_rule(const char* rule);
    asn1& learn();

    asn1& operator<<(asn1_object*);
    /**
     * @sample
     *      n << new asn1_set("PersonnelRecord");
     *      auto item = n.clone("PersonnelRecord");
     *      // do something
     *      item->relase();
     */
    asn1_object* clone(const std::string& name);

    void publish(binary_t* b);
    void publish(stream_t* s);

    parser& get_parser();
    const parser::context& get_rule_context() const;

   protected:
    void clear();

   private:
    std::list<asn1_object*> _list;
    std::map<std::string, asn1_object*> _dictionary;

    parser _parser;
    basic_stream _buf;      // add_rule
    parser::context _rule;  // learn
};

/**
 * @brief   length octets
 * @sa
 *          X.680 8.1.3 Length octets
 *          X.690 8.1.3 Length octets
 */
template <typename type>
unsigned t_asn1_encode_length(binary_t& bin, type v) {
    unsigned size_encode = 0;
    uint8 octets = sizeof(type);

    uint128 m = 0;
    for (uint8 i = 1; i <= octets; i++) {
        m <<= 8;
        m |= 0xff;
        if (v <= m) {
            if ((1 == i) && (v <= 0x7f)) {
                bin.insert(bin.end(), (uint8)v);
                size_encode++;
            } else {
                type be = v;
                if (sizeof(type) > 1) {
                    be = convert_endian(v);
                }

                uint8 leading = 0x80 | i;
                bin.insert(bin.end(), leading);
                bin.insert(bin.end(), (byte_t*)&be + (octets - i), (byte_t*)&be + octets);
                size_encode += (i + 1);
            }
            break;
        }
    }
    return size_encode;
}

/**
 * @brief   X.690 8.3
 */
template <typename type>
unsigned t_asn1_encode_integer(binary_t& bin, type v) {
    unsigned size_encode = 0;
    uint32 tsize = sizeof(type);
    type i = convert_endian(v);
    type p = v >= 0 ? v : ~v;
    type mask = 0;
    uint32 len = 1;

    for (uint32 i = tsize; i > 0; i--) {
        mask = (0xff << ((i - 1) * 8));
        if (mask & p) {  // check occupied bytes
            len = i;
            type msb = (1 << ((len * 8) - 1));
            if (msb & p) {  // check msb is set
                len += 1;
            }
            break;
        }
    }

    bin.insert(bin.end(), asn1_tag_integer);
    size_encode = t_asn1_encode_length<type>(bin, len);
    bin.insert(bin.end(), (byte_t*)&i + (tsize - len), (byte_t*)&i + tsize);
    return size_encode + len + 1;
}

template <typename type>
unsigned t_asn1_variable_length(binary_t& bin, type v, size_t pos = -1) {
    unsigned len = 0;
    if (-1 == pos) {
        pos = bin.size();
    }
    uint8 m = 0;
    while (v >= 0x80) {
        bin.insert(bin.begin() + pos, (v & 0x7f) | m);
        v >>= 7;
        m = 0x80;
        len++;
    }
    bin.insert(bin.begin() + pos, v | m);
    return len + 1;
}

class asn1_encode {
   public:
    asn1_encode();

    asn1_encode& null(binary_t& bin);
    asn1_encode& primitive(binary_t& bin, bool value);
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
    asn1_encode& primitive(binary_t& bin, oid_t value);
    asn1_encode& primitive(binary_t& bin, reloid_t value);
    asn1_encode& primitive(binary_t& bin, asn1_tag_t c, const std::string& value);

    asn1_encode& encode(binary_t& bin, const variant& value);
    asn1_encode& encode(binary_t& bin, int tag, int class_number, const std::string& value);

    asn1_encode& generalstring(binary_t& bin, const std::string& value);
    asn1_encode& ia5string(binary_t& bin, const std::string& value);
    asn1_encode& visiblestring(binary_t& bin, const std::string& value);
    asn1_encode& bitstring(binary_t& bin, const std::string& value);

    asn1_encode& generalized_time(basic_stream& bs, const datetime_t& dt);
    asn1_encode& utctime(basic_stream& bs, const datetime_t& dt);

    asn1_encode& indef(binary_t& bin);
    asn1_encode& end_contents(binary_t& bin);

   protected:
};

class asn1_resource {
   public:
    static asn1_resource* get_instance();

    std::string get_type_name(asn1_type_t t);
    std::string get_class_name(asn1_class_t c);
    std::string get_tagtype_name(uint32 t);
    std::string get_componenttype_name(uint32 t);

   protected:
    asn1_resource();
    void load_resource();

    static asn1_resource _instance;

    std::map<asn1_type_t, std::string> _type_id;
    std::map<asn1_class_t, std::string> _class_id;
};

}  // namespace io
}  // namespace hotplace

#endif
