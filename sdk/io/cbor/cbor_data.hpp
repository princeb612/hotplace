/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7049 Concise Binary Object Representation (CBOR)
 *  RFC 8949 Concise Binary Object Representation (CBOR)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORDATA__
#define __HOTPLACE_SDK_IO_CBOR_CBORDATA__

#include <deque>
#include <sdk/base.hpp>
#include <sdk/io/cbor/cbor_object.hpp>
#include <sdk/io/stream/stream.hpp>

namespace hotplace {
namespace io {

class cbor_object;
class cbor_data;
class cbor_bstrings;
class cbor_tstrings;
class cbor_pair;
class cbor_map;
class cbor_array;
class cbor_visitor;

class cbor_data : public cbor_object {
    friend class cbor_pair;
    friend class cbor_bstrings;
    friend class cbor_tstrings;
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;

   public:
    cbor_data();
    cbor_data(bool value);
    cbor_data(int8 value);
    cbor_data(int16 value);
    cbor_data(int32 value);
    cbor_data(int64 value);
#if defined __SIZEOF_INT128__
    cbor_data(int128 value);
#endif
    cbor_data(const byte_t* bstr, size_t size);
    cbor_data(const binary_t& bin);
    cbor_data(const char* tstr);
    cbor_data(const char* tstr, size_t length);
    cbor_data(const std::string& bin);
    cbor_data(const fp16_t& value);
    cbor_data(float value);
    cbor_data(double value);
    cbor_data(variant_t& vt);
    cbor_data(const variant_t& vt);
    cbor_data(variant& vt);
    cbor_data(const variant& vt);
    virtual ~cbor_data();

    variant& data();

   protected:
    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   private:
    variant _vt;
};

class cbor_bstrings : public cbor_object {
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;

   public:
    cbor_bstrings();
    virtual ~cbor_bstrings();

    /*
     * @brief   add
     * @param   cbor_object* object [in]
     * @param   cbor_object* extra [inopt] ignored
     * @return  error code (see error.hpp)
     */
    virtual return_t join(cbor_object* object, cbor_object* extra = nullptr);
    cbor_bstrings& add(cbor_object* object, cbor_object* extra = nullptr);
    cbor_bstrings& add(const byte_t* bstr, size_t size);
    cbor_bstrings& operator<<(binary_t bin);

    virtual size_t size();

    virtual int addref();
    virtual int release();

   protected:
    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   private:
    std::list<cbor_data*> _array;
};

class cbor_tstrings : public cbor_object {
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;

   public:
    cbor_tstrings();
    virtual ~cbor_tstrings();

    /*
     * @brief   add
     * @param   cbor_object* object [in]
     * @param   cbor_object* extra [inopt] ignored
     * @return  error code (see error.hpp)
     */
    virtual return_t join(cbor_object* object, cbor_object* extra = nullptr);
    cbor_tstrings& add(cbor_object* object, cbor_object* extra = nullptr);
    cbor_tstrings& add(const char* str);
    cbor_tstrings& operator<<(const char* str);

    virtual size_t size();

    virtual int addref();
    virtual int release();

   protected:
    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   private:
    std::list<cbor_data*> _array;
};

/**
 * @brief   cbor_simple
 */
class cbor_simple : public cbor_object {
   public:
    cbor_simple(uint8 value);

    cbor_simple_t simple_type();
    static cbor_simple_t is_kind_of(uint8 first);
    static cbor_simple_t is_kind_of_value(uint8 value);

   protected:
    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   private:
    cbor_simple_t _type;
    uint8 _value;
};

class cbor_bignum_int128 {
   public:
    cbor_bignum_int128();

    cbor_bignum_int128& load(byte_t* data, uint32 len);
    int128 value();

   private:
    binary_t _bn;
};

}  // namespace io
}  // namespace hotplace

#endif
