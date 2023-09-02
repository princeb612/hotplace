/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_CBOR__
#define __HOTPLACE_SDK_IO_CBOR__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/stream/buffer_stream.hpp>

namespace hotplace {
namespace io {

enum cbor_major_t {
    cbor_major_uint     = 0,    ///<< 0000 0
    cbor_major_nint     = 1,    ///<< 0010 2
    cbor_major_bstr     = 2,    ///<< 0100 4, 0101 1111 5f (indefinite-length)
    cbor_major_tstr     = 3,    ///<< 0110 6, 0111 1111 7f (indefinite-length)
    cbor_major_array    = 4,    ///<< 1000 8, 1001 1111 9f (indefinite-length)
    cbor_major_map      = 5,    ///<< 1010 a, 1011 1111 bf (indefinite-length)
    cbor_major_tag      = 6,    ///<< 1100 c
    cbor_major_float    = 7,    ///<< 1110 e
    cbor_major_simple   = 7,    ///<< 111x e or f, see additional info
};

enum cbor_tag_t {
    cbor_tag_std_datetime       = 0,
    cbor_tag_epoch_datetime     = 1,
    cbor_tag_positive_bignum    = 2,
    cbor_tag_negative_bignum    = 3,
    cbor_tag_decimal_fraction   = 4,
    cbor_tag_big_float          = 5,
    cbor_tag_base64url          = 21,
    cbor_tag_base64             = 22,
    cbor_tag_base16             = 23,
    cbor_tag_encoded            = 24,
    cbor_tag_uri                = 32,
    cbor_tag_base64url_utf8     = 33,
    cbor_tag_base64_utf8        = 34,
    cbor_tag_regex_utf8         = 35,
    cbor_tag_mime_utf8          = 36,
};

enum cbor_type_t {
    cbor_type_null      = 0,
    cbor_type_array     = 1,
    cbor_type_data      = 2,
    cbor_type_pair      = 3,    // keyvalue
    cbor_type_map       = 4,    // keyvalues
    cbor_type_simple    = 5,
    cbor_type_bstrs     = 6,
    cbor_type_tstrs     = 7,
};

/*
 * @desc
 *      RFC 8949 Concise Binary Object Representation (CBOR)
 *      An encoder MUST NOT issue two-byte sequences that start with 0xf8
 *      (major type 7, additional information 24) and continue with a byte
 *      less than 0x20 (32 decimal).
 */
enum cbor_simple_t {
    cbor_simple_error       = 0,    // Not applicable, not a type, ...
    cbor_simple_value       = 19,   // additional info 0..19 : unassigned
                                    // additional info 24 : following byte (value 32-255)
    cbor_simple_false       = 20,   // additional info 20 : false
                                    // f4 111 1 0100
    cbor_simple_true        = 21,   // additional info 21 : true
    cbor_simple_null        = 22,   // additional info 22 : null
    cbor_simple_undef       = 23,   // additional info 23 : undefined value
    cbor_simple_half_fp     = 25,   // additional info 25 : half-precision floaing point
    cbor_simple_single_fp   = 26,   // additional info 26 : single-precision floaing point
    cbor_simple_double_fp   = 27,   // additional info 27 : double-precision floaing point
    cbor_simple_reserved    = 30,   // additional info 28-30 : unassigned
    cbor_simple_break       = 31,   // additional info 31 : break
};

enum cbor_control_t {
    cbor_control_begin = 0,
    cbor_control_end,
};

enum cbor_flag_t {
    cbor_indef = 1,   // indefinite-length
};

class cbor_object;
class cbor_data;
class cbor_bstrings;
class cbor_tstrings;
class cbor_pair;
class cbor_map;
class cbor_array;
class cbor_visitor;

/*
 *  cbor_object
 *  \_ cbor_data
 *     - variant_t
 *  \_ cbor_bstrings
 *     - list <cbor_data*>
 *  \_ cbor_tstrings
 *     - list <cbor_data*>
 *  \_ cbor_pair
 *     - cbor_data*, cbor_object*
 *  \_ cbor_map
 *     - map <cbor_pair*>
 *  \_ cbor_array
 *     - list <cbor_object*>
 */
class cbor_object
{
    friend class cbor_reader;
public:
    cbor_object ();
    cbor_object (cbor_type_t type, uint32 flags = 0);
    virtual ~cbor_object ();

    virtual cbor_type_t type ();
    virtual size_t size ();
    virtual uint32 get_flags ();

    virtual void tag (bool use, cbor_tag_t tag);
    virtual bool tagged ();
    virtual cbor_tag_t tag_value ();

    virtual void reserve (size_t size);
    virtual size_t reserved_size ();

    virtual return_t join (cbor_object* object, cbor_object* extra = nullptr);

    virtual int addref ();
    virtual int release ();

    virtual void accept (cbor_visitor* v);
    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

private:
    cbor_type_t _type;
    uint32 _flags;
    bool _tagged; ///<< addtitional flag (cbor_tag_t::std_datetime is 0)
    cbor_tag_t _tag;
    uint64 _reserved_size;
    t_shared_reference <cbor_object>  _shared;
};

class cbor_data : public cbor_object
{
public:
    cbor_data ();
    cbor_data (bool value);
    cbor_data (int8 value);
    cbor_data (int16 value);
    cbor_data (int32 value);
    cbor_data (int64 value);
#if defined __SIZEOF_INT128__
    cbor_data (int128 value);
#endif
    cbor_data (const byte_t * bstr, size_t size);
    cbor_data (const char* tstr);
    cbor_data (const char* tstr, size_t length);
    cbor_data (float value);
    cbor_data (double value);
    virtual ~cbor_data ();

    const variant_t& data ();

    virtual void accept (cbor_visitor* v);
    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

protected:
    return_t clear ();

private:
    variant_t _vt;
};

/**
 * @brief   cbor_simple
 */
class cbor_simple : public cbor_object
{
public:
    cbor_simple (uint8 value);

    cbor_simple_t simple_type ();
    static cbor_simple_t is_kind_of (uint8 first);
    static cbor_simple_t is_kind_of_value (uint8 value);

    virtual void accept (cbor_visitor* v);
    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

private:;
    cbor_simple_t _type;
    uint8 _value;
};

class cbor_bignum_int128
{
public:
    cbor_bignum_int128 ();

    cbor_bignum_int128& load (byte_t* data, uint32 len);
    int128 value ();

private:
    binary_t _bn;
};

class cbor_bstrings : public cbor_object
{
public:
    cbor_bstrings ();
    virtual ~cbor_bstrings ();

    virtual size_t size ();

    virtual return_t join (cbor_object* object, cbor_object* extra = nullptr);

    cbor_bstrings& add (const byte_t * bstr, size_t size);
    cbor_bstrings& operator << (binary_t bin);

    virtual void accept (cbor_visitor* v);
    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

protected:
    return_t clear ();

private:
    std::list <cbor_data*> _array;
};

class cbor_tstrings : public cbor_object
{
public:
    cbor_tstrings ();
    virtual ~cbor_tstrings ();

    virtual size_t size ();

    virtual return_t join (cbor_object* object, cbor_object* extra = nullptr);

    cbor_tstrings& add (const char* str);
    cbor_tstrings& operator << (const char* str);

    virtual void accept (cbor_visitor* v);
    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

protected:
    return_t clear ();

private:
    std::list <cbor_data*> _array;
};

/*
 * @brief   pair type
 * @desc    key (int, string) : value (int, string, array)
 *          {1: 2, 3: 4}
 *          {"a": 1, "b": [2, 3]}
 *          {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}
 *          {_ "a": 1, "b": [_ 2, 3]}
 *          {_ "Fun": true, "Amt": -2}
 * @sa      cbor_map
 */
class cbor_pair : public cbor_object
{
    friend class cbor_map;
public:
#if defined __SIZEOF_INT128__
    cbor_pair (int128 value, cbor_data* object);
    cbor_pair (int128 value, cbor_array* object);
#else
    cbor_pair (int64 value, cbor_data* object);
    cbor_pair (int64 value, cbor_array* object);
#endif
    cbor_pair (const char* key, cbor_data* object);
    cbor_pair (const char* key, cbor_array* object);
    virtual ~cbor_pair ();

    cbor_object* const left ();
    cbor_object* const right ();

    virtual void accept (cbor_visitor* v);
    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

protected:
    cbor_pair (cbor_data* key, cbor_object* object);

    return_t clear ();

private:
    cbor_data* _lhs;
    cbor_object* _rhs;
};

/*
 * @biref   map type
 * @example
 *          // {1:2,3:4}
 *          cbor_map* root = new cbor_map ();
 *          *root << new cbor_pair (1, new cbor_data (2)) << new cbor_pair (3, new cbor_data (4));
 *          // ...
 *          root->release ();
 */
class cbor_map : public cbor_object
{
public:
    cbor_map ();
    cbor_map (uint32 flags);
    cbor_map (cbor_pair* object, uint32 flags = 0);
    virtual ~cbor_map ();

    virtual size_t size ();

    virtual return_t join (cbor_object* object, cbor_object* extra = nullptr);

    cbor_map& add (cbor_pair* object);
    cbor_map& operator << (cbor_pair* object);

    virtual void accept (cbor_visitor* v);
    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

protected:
    return_t clear ();

private:
    std::list <cbor_pair*> _array; /* unordered */
};

/*
 * @brief   array type
 * @example
 *          cbor_array* array = new cbor_array ();
 *          *array  << (new cbor_pair ("item1", new cbor_data ("value1")))
 *                  << (new cbor_pair ("item2", new cbor_data (12345)))
 *                  << (new cbor_pair ("item3", new cbor_data (true)))
 *                  << (new cbor_pair ("item4", new cbor_data (1.2345)))
 *                  << (new cbor_pair ("item5", new cbor_pair ("subitem1", new cbor_data ("subvalue1"))))
 *                  << (new cbor_pair ("item6", new cbor_data (true)))
 *                  << (new cbor_pair ("item7", new cbor_data ()));
 *          // ...
 *          array->release ();
 */
class cbor_array : public cbor_object
{
public:
    cbor_array ();
    cbor_array (uint32 flags);
    virtual ~cbor_array ();

    virtual size_t size ();

    virtual return_t join (cbor_object* object, cbor_object* extra = nullptr);

    cbor_array& add (cbor_array* object);
    cbor_array& add (cbor_data* object);
    cbor_array& add (cbor_map* object);

    cbor_array& operator << (cbor_array* object);
    cbor_array& operator << (cbor_data* object);
    cbor_array& operator << (cbor_map* object);

    virtual void accept (cbor_visitor* v);
    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

protected:
    void clear ();

private:
    std::list <cbor_object*> _array;
};

/*
 * @brief encode
 * @param
 * @example
 *          cbor_encode cbor;
 *          binary_t bin;
 *          variant_t vt;
 *          // variant_set_int8, variant_set_int16, variant_set_int32, variant_set_int64, variant_set_int128
 *          // variant_set_float, variant_set_double, variant_set_bool, variant_set_str
 *          cbor.encode (bin, vt);
 *          buffer_stream out;
 *          std::string hex = bin2hex (bin);
 *
 *          // variant_set_xxx examples
 *          variant_set_int8 (vt, 0);
 *          variant_set_int8 (vt, 1);
 *          variant_set_int8 (vt, 10);
 *          variant_set_int8 (vt, 23);
 *          variant_set_int8 (vt, 24);
 *          variant_set_int8 (vt, 25);
 *          variant_set_int8 (vt, 100);
 *          variant_set_int16 (vt, 1000);
 *          variant_set_int32 (vt, 1000000);
 *          variant_set_int64 (vt, 1000000000000);
 *          variant_set_uint128 (vt, atoi128 ("18446744073709551615"));
 *          variant_set_int128 (vt, atoi128 ("18446744073709551616"));
 *          variant_set_int128 (vt, atoi128 ("-18446744073709551616"));
 *          variant_set_int128 (vt, atoi128 ("-18446744073709551617"));
 *          variant_set_int32 (vt, -1);
 *          variant_set_int32 (vt, -10);
 *          variant_set_int16 (vt, -100);
 *          variant_set_int16 (vt, -1000);
 *          variant_set_float (vt, 0.0);
 *          variant_set_double (vt, 0.0);
 *          variant_set_float (vt, -0.0);
 *          variant_set_double (vt, -0.0);
 *          variant_set_float (vt, 1.0);
 *          variant_set_double (vt, 1.0);
 *          variant_set_float (vt, 1.1);
 *          variant_set_double (vt, 1.1);
 *          variant_set_float (vt, 1.5);
 *          variant_set_double (vt, 1.5);
 *          variant_set_float (vt, 65504.0);
 *          variant_set_double (vt, 65504.0);
 *          variant_set_float (vt, 100000.0);
 *          variant_set_double (vt, 100000.0);
 *          variant_set_float (vt, 3.4028234663852886e+38);
 *          variant_set_double (vt, 1.0e+300);
 *          variant_set_float (vt, 5.960464477539063e-8);
 *          variant_set_float (vt, 0.00006103515625);
 *          variant_set_float (vt, -4.0);
 *          variant_set_float (vt, -4.1);
 *          variant_set_bool (vt, false);
 *          variant_set_bool (vt, true);
 *          variant_set_str (vt, "");
 *          variant_set_str (vt, "a");
 *          variant_set_str (vt, "IETF");
 *          variant_set_str (vt, "\"\\");
 *          variant_set_str (vt, "\u00fc");
 *          variant_set_str (vt, "\u6c34");
 */
class cbor_encode
{
public:
    cbor_encode ();

    return_t encode (binary_t& bin, variant_t vt);
    return_t encode (binary_t& bin, bool value);
    return_t encode (binary_t& bin, int8 value);
    return_t encode (binary_t& bin, cbor_major_t major, uint8 value);
    return_t encode (binary_t& bin, int16 value);
    return_t encode (binary_t& bin, cbor_major_t major, uint16 value);
    return_t encode (binary_t& bin, int32 value);
    return_t encode (binary_t& bin, cbor_major_t major, uint32 value);
    return_t encode (binary_t& bin, int64 value);
    return_t encode (binary_t& bin, cbor_major_t major, uint64 value);
#if defined __SIZEOF_INT128__
    return_t encode (binary_t& bin, int128 value);
    return_t encode (binary_t& bin, cbor_major_t major, uint128 value);
#endif
    return_t encode (binary_t& bin, uint8 major);
    return_t encode (binary_t& bin, float value);
    return_t encode (binary_t& bin, double value);
    return_t encode (binary_t& bin, byte_t* value, size_t size);
    return_t encode (binary_t& bin, char* value);
    return_t encode (binary_t& bin, cbor_major_t type, cbor_control_t control, cbor_object* object);
    return_t encode (binary_t& bin, cbor_simple_t type, uint8 value);

    return_t add_tag (binary_t& bin, cbor_object* object);
};

class cbor_visitor
{
public:
    virtual return_t visit (cbor_object* object) = 0;
    virtual return_t visit (cbor_data* object) = 0;
    virtual return_t visit (cbor_bstrings* object) = 0;
    virtual return_t visit (cbor_tstrings* object) = 0;
    virtual return_t visit (cbor_pair* object) = 0;
    virtual return_t visit (cbor_map* object) = 0;
    virtual return_t visit (cbor_array* object) = 0;
};

/*
 * @brief concise
 * @sa cbor_publisher
 */
class cbor_concise_visitor : public cbor_visitor
{
public:
    cbor_concise_visitor (binary_t* concise);
    virtual ~cbor_concise_visitor ();
    virtual return_t visit (cbor_object* object);
    virtual return_t visit (cbor_data* object);
    virtual return_t visit (cbor_bstrings* object);
    virtual return_t visit (cbor_tstrings* object);
    virtual return_t visit (cbor_pair* object);
    virtual return_t visit (cbor_map* object);
    virtual return_t visit (cbor_array* object);

    binary_t* get_binary ();

private:
    binary_t* _concise;
};

/*
 * @brief diagnostic
 * @sa cbor_publisher
 */
class cbor_diagnostic_visitor : public cbor_visitor
{
public:
    cbor_diagnostic_visitor (stream_t* stream);
    virtual ~cbor_diagnostic_visitor ();
    virtual return_t visit (cbor_object* object);
    virtual return_t visit (cbor_data* object);
    virtual return_t visit (cbor_bstrings* object);
    virtual return_t visit (cbor_tstrings* object);
    virtual return_t visit (cbor_pair* object);
    virtual return_t visit (cbor_map* object);
    virtual return_t visit (cbor_array* object);

    stream_t* get_stream ();

private:
    stream_t* _diagnostic;
};

/*
 * @brief concise, diagnostic
 * @example
 *      cbor_array* root = new cbor_array ();
 *      *root << new cbor_data (1) << new cbor_data (2) << new cbor_data (3);
 *
 *      cbor_publisher publisher;
 *      binary_t bin;
 *      buffer_stream diagnostic;
 *
 *      publisher.publish (root, &diagnostic); // [1,2,3]
 *      publisher.publish (root, &bin);
 *
 *      std::string concise;
 *      base16_encode (bin, concise);   // base16 "83010203"
 */
class cbor_publisher
{
public:
    cbor_publisher ();

    /*
     * concise
     */
    return_t publish (cbor_object* object, binary_t* b);
    /*
     * diagnostic
     */
    return_t publish (cbor_object* object, stream_t* s);
};

typedef std::deque<cbor_object*> cbor_item_dequeue_t;
typedef struct _cbor_reader_context_t {
    int indef;
    cbor_object* root;
    uint32 tag_value;
    bool tag_flag;
    cbor_item_dequeue_t parents;
    cbor_item_dequeue_t items;

    _cbor_reader_context_t () : indef (0), root (nullptr), tag_value (0), tag_flag (false)
    {
    }
} cbor_reader_context_t;

/**
 * @brief   parse
 * @example
 *          const char* input = "8301820203820405";
 *          cbor_reader_context_t* handle = nullptr;
 *          ansi_string bs;
 *          binary_t bin;
 *
 *          reader.open (&handle);
 *          reader.parse (handle, input);
 *          reader.publish (handle, &bs);   // diagnostic "[1,[2,3],[4,5]]"
 *          reader.publish (handle, &bin);  // encoded 0x8301820203820405
 *          reader.close (handle);
 *
 *          std::string concise;
 *          base16_encode (bin, concise);   // base16 "8301820203820405"
 */
class cbor_reader
{
public:
    cbor_reader ();

    return_t open (cbor_reader_context_t** handle);
    return_t close (cbor_reader_context_t* handle);
    return_t parse (cbor_reader_context_t* handle, const char* expr);
    return_t parse (cbor_reader_context_t* handle, binary_t const& bin);

    return_t publish (cbor_reader_context_t* handle, stream_t* stream);
    return_t publish (cbor_reader_context_t* handle, binary_t& bin);

protected:
    return_t push (cbor_reader_context_t* handle, uint8 type, int128 data, uint32 flags);
    return_t push (cbor_reader_context_t* handle, uint8 type, const char* data, size_t size, uint32 flags);
    return_t push (cbor_reader_context_t* handle, uint8 type, const byte_t* data, size_t size, uint32 flags);
    return_t push (cbor_reader_context_t* handle, uint8 type, float data, size_t size);
    return_t push (cbor_reader_context_t* handle, uint8 type, double data, size_t size);

    return_t insert (cbor_reader_context_t* handle, cbor_object* objct);

    bool is_enough (cbor_object* object);

private:
};

}
}  // namespace

#endif
