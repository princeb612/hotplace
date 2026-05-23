/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   variant.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.05.23   Soo Han and Gemini  Refined with guidance and collaboration from Gemini
 *
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_VARIANT__
#define __HOTPLACE_SDK_BASE_BASIC_VARIANT__

#include <string.h>

#include <cmath>
#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/atoi.hpp>
#include <hotplace/sdk/base/nostd/cast.hpp>
#include <hotplace/sdk/base/stream/types.hpp>
#include <hotplace/sdk/base/system/types.hpp>

namespace hotplace {

enum variant_flag_t : uint16 {
    vt_flag_support = 1 << 0,                                   // characteristic : true
    vt_flag_standalone = 1 << 1,                                // characteristic : true if size_t unnecessary
    vt_flag_composite = 1 << 2,                                 // characteristic : true if size_t required    e.g. func(char*, size_t)
    vt_flag_negative = 1 << 8,                                  // behavioral     : true if a combination of uint64 and negative tags (CBOR)
    vt_flag_free = 1 << 9,                                      // behavioral     : free
    vt_flag_int = 1 << 11,                                      // attribute      : int8~int128
    vt_flag_float = 1 << 12,                                    // attribute      : float, double
    vt_flag_string = 1 << 13,                                   // attribute      : string
    vt_flag_binary = 1 << 14,                                   // attribute      : binary
    vt_flag_user_type = 1 << 15,                                // attribute      : user-defined
    vt_mask_standalone = vt_flag_support | vt_flag_standalone,  // mask           : standalone
    vt_mask_composite = vt_flag_support | vt_flag_composite,    // mask           : composite
    vt_mask_attr = (uint16)0b1111110000000000,                  // mask           : excluding characteristics
};

/**
    |   E  |   M    |   T    |    X   | naming by group        |
    | enum | member | traits | int128 |                        |
    | --   | --     | --     | --     | --                     |
    |   v  |   v    |   v    |        | VARIANT_XGROUP_EMT     |
    |   v  |        |        |        | VARIANT_XGROUP_E       |
    |   v  |   v    |        |        | VARIANT_XGROUP_EM      |
    |   v  |   v    |   v    |    v   | VARIANT_XGROUP_EMTX    |
 */

// assign enum_number 1..255
#define VARIANT_XGROUP_EMT(X)                                                                                    \
    X(void*, TYPE_POINTER, 1, p, (vt_flag_standalone))                                                           \
    X(char*, TYPE_STRING, 2, str, (vt_flag_standalone | vt_flag_composite | vt_flag_string | vt_flag_free))      \
    X(wchar_t*, TYPE_WSTRING, 4, wstr, (vt_flag_standalone | vt_flag_composite | vt_flag_string | vt_flag_free)) \
    X(byte_t*, TYPE_BSTRING, 5, bstr, (vt_flag_composite | vt_flag_binary | vt_flag_free))                       \
    X(wchar_t, TYPE_WCHAR, 8, wc, (vt_flag_standalone))                                                          \
    X(bool, TYPE_BOOL, 16, b, (vt_flag_standalone))                                                              \
    X(int8, TYPE_INT8, 17, i8, (vt_flag_standalone | vt_flag_int))                                               \
    X(uint8, TYPE_UINT8, 18, ui8, (vt_flag_standalone | vt_flag_int))                                            \
    X(int16, TYPE_INT16, 19, i16, (vt_flag_standalone | vt_flag_int))                                            \
    X(uint16, TYPE_UINT16, 20, ui16, (vt_flag_standalone | vt_flag_int))                                         \
    X(int32, TYPE_INT32, 21, i32, (vt_flag_standalone | vt_flag_int))                                            \
    X(uint32, TYPE_UINT32, 22, ui32, (vt_flag_standalone | vt_flag_int))                                         \
    X(int64, TYPE_INT64, 23, i64, (vt_flag_standalone | vt_flag_int))                                            \
    X(uint64, TYPE_UINT64, 24, ui64, (vt_flag_standalone | vt_flag_int))                                         \
    X(float, TYPE_FLOAT, 25, f, (vt_flag_standalone | vt_flag_float))                                            \
    X(double, TYPE_DOUBLE, 26, d, (vt_flag_standalone | vt_flag_float))
#define VARIANT_XGROUP_E(X) X(char*, TYPE_NSTRING, 3, str, (vt_flag_composite | vt_flag_string))
#define VARIANT_XGROUP_EM(X)                       \
    X(char, TYPE_CHAR, 6, c, (vt_flag_standalone)) \
    X(byte_t, TYPE_BYTE, 7, uc, (vt_flag_standalone))
#define VARIANT_XGROUP_EMTX(X)                                           \
    X(int128, TYPE_INT128, 31, i128, (vt_flag_standalone | vt_flag_int)) \
    X(uint128, TYPE_UINT128, 32, ui128, (vt_flag_standalone | vt_flag_int))

/**
 * @brief   vartype_t
 */
enum vartype_t {
    TYPE_NULL = 0,
    TYPE_VOID = TYPE_NULL,

#define EXPAND_VARTYPE_ENUM(cpp_type, enum_type, enum_val, union_member, union_flag) enum_type = enum_val,
    VARIANT_XGROUP_EMT(EXPAND_VARTYPE_ENUM) VARIANT_XGROUP_E(EXPAND_VARTYPE_ENUM) VARIANT_XGROUP_EM(EXPAND_VARTYPE_ENUM)
#if defined __SIZEOF_INT128__
        VARIANT_XGROUP_EMTX(EXPAND_VARTYPE_ENUM)
#endif
#undef EXPAND_VARTYPE_ENUM

    // aliases

    TYPE_BINARY = TYPE_BSTRING,    //
    TYPE_BLOB = TYPE_BSTRING,      //
    TYPE_SINT8 = TYPE_INT8,        //
    TYPE_SHORT = TYPE_INT16,       //
    TYPE_SINT16 = TYPE_INT16,      //
    TYPE_USHORT = TYPE_UINT16,     //
    TYPE_WORD = TYPE_UINT16,       //
    TYPE_SINT32 = TYPE_INT32,      //
    TYPE_DWORD = TYPE_UINT32,      //
    TYPE_SINT64 = TYPE_INT64,      //
    TYPE_FP32 = TYPE_FLOAT,        // single precision floating point
    TYPE_FP64 = TYPE_DOUBLE,       // double precision floating point
    TYPE_INT = TYPE_INT32,         //
    TYPE_UINT = TYPE_UINT32,       //
    TYPE_LONGLONG = TYPE_INT64,    //
    TYPE_ULONGLONG = TYPE_UINT64,  //

#if defined _MBCS || defined MBCS
    TYPE_TCHAR = TYPE_CHAR,
    TYPE_TSTRING = TYPE_STRING,
#elif defined _UNICODE || defined UNICODE
    TYPE_TCHAR = TYPE_WCHAR,
    TYPE_TSTRING = TYPE_WSTRING,
#endif

#if defined __linux__
#if __WORDSIZE == 32
    TYPE_LONG = TYPE_INT32,
    TYPE_ULONG = TYPE_UINT32,
#elif __WORDSIZE == 64
    // LPI64 : think of L(Linux) with L
    TYPE_LONG = TYPE_INT64,
    TYPE_ULONG = TYPE_UINT64,
#endif
#elif defined _WIN32 || defined _WIN64
    // LLPI64 : think of W(Windows) with LL
    TYPE_LONG = TYPE_INT32,
    TYPE_ULONG = TYPE_UINT32,
#endif

    // extensions (assign enum_number 256~)

    TYPE_INT24 = 256,      //
    TYPE_UINT24 = 257,     // ex. TLS handshake length
    TYPE_INT48 = 258,      //
    TYPE_UINT48 = 259,     // ex. DTLS record sequence
    TYPE_FP16 = 260,       // half precision floating point
    TYPE_FP128 = 261,      // quadruple precision floating point
    TYPE_DATETIME = 262,   // datetime_t
    TYPE_BIGNUMBER = 263,  // see bignumber
    TYPE_BASE16 = 264,     // encoding_base16
    TYPE_BASE64 = 265,     // encoding_base64
    TYPE_BASE64URL = 266,  // encoding_base64url
    TYPE_TEXT = 267,       // JNI specially vector<string>
    TYPE_JBOOLEAN = 268,   // JNI unsigned char
    TYPE_JBYTE = 269,      // JNI signed char
    TYPE_JCHAR = 270,      // JNI unsigned short
    TYPE_JSTRING = 271,    // JNI java/lang/String

    TYPE_RESERVED = 0x1000,  //
    TYPE_USER = 0x10000,     //
};

enum variant_control_t {
    variant_trunc = (1 << 16),       // truncate
    variant_convendian = (1 << 17),  // endian conversion
};

union vartype_union {
#define EXPAND_VARTYPE_UNION(cpp_type, enum_type, enum_val, union_member, union_flag) cpp_type union_member;
    VARIANT_XGROUP_EMT(EXPAND_VARTYPE_UNION)
    VARIANT_XGROUP_EM(EXPAND_VARTYPE_UNION)
#if defined __SIZEOF_INT128__
    VARIANT_XGROUP_EMTX(EXPAND_VARTYPE_UNION)
#endif
#undef EXPAND_VARTYPE_UNION

    char jb;
    byte_t jbool;
    int i;
    uint ui;
    uint16 jc;
    datetime_t* dt;
};

struct variant_t {
    vartype_t type;
    vartype_union data;
    size_t size;
    uint16 flag;

    variant_t();
    variant_t(const variant_t& other);
    variant_t(variant_t&& other);
    ~variant_t();

    variant_t& operator=(const variant_t& other);
    variant_t& operator=(variant_t&& other);

    variant_t& reset();  // do not free
    variant_t& clear();  // free if vt_flag_free is set
};

template <typename T>
struct variant_traits {
    static constexpr uint16 flags = 0;
};

#define EXPAND_VARTYPE_TAITS(cpp_type, enum_type, enum_val, union_member, union_flag)     \
    template <>                                                                           \
    struct variant_traits<cpp_type> {                                                     \
        using cast_type = cpp_type;                                                       \
        static constexpr uint16 flags = vt_flag_support | union_flag;                     \
        static constexpr vartype_t type = enum_type;                                      \
        static constexpr cpp_type vartype_union::* member = &vartype_union::union_member; \
    };
VARIANT_XGROUP_EMT(EXPAND_VARTYPE_TAITS)
#if defined __SIZEOF_INT128__
VARIANT_XGROUP_EMTX(EXPAND_VARTYPE_TAITS)
#endif
#undef EXPAND_VARTYPE_TAITS

template <typename T>
struct variant_descriptor {
    static const vartype_t type;
    static void assign(vartype_t&, T);
    static T get(const vartype_t&);
};

class variant {
   public:
    variant();
    variant(const variant& value);
    variant(variant&& value);

    variant(const variant_t& value);
    variant(variant_t&& value);
    variant& operator=(const variant& other);
    variant& operator=(variant&& other);

    // set
    template <typename T, typename std::enable_if<(variant_traits<typename std::decay<T>::type>::flags & vt_mask_standalone) == vt_mask_standalone, int>::type = 0>
    variant(T&& value) {
        set(std::forward<T>(value));
    };
    // set_new
    template <typename T,                                                                                                                   //
              typename std::enable_if<((variant_traits<custom::remove_ptr_const_t<T>>::flags & vt_mask_composite) == vt_mask_composite) &&  //
                                          ((variant_traits<custom::remove_ptr_const_t<T>>::flags & vt_flag_free) == vt_flag_free),
                                      int>::type = 0>
    variant(T&& value, size_t size) {
        set_new(std::forward<T>(value), size);
    };

    variant(const char* value);
    variant(const uint24_t& value);
    variant(const uint48_t& value);

    variant(vartype_t vtype, void* value);

    variant(const std::string& value);
    variant(const binary_t& value);
    variant(const datetime_t& value);
    variant(const stream_t* value);
    variant(const bignumber& value);
    ~variant();

    const variant_t& content() const;
    variant_t& get();

    vartype_t type() const;
    size_t size() const;
    uint16 flag() const;

    variant& set_flag(uint16 flag);
    variant& unset_flag(uint16 flag);

    /**
     * @brief   reset
     * @remarks do not free
     */
    variant& reset();
    /**
     * @brief   clear
     * @remarks free if vt_flag_free is set
     * @example
     *          vt.clear().set_bool(true);
     */
    variant& clear();

    /**
     * @brief   setter
     * @remarks call clear before setter
     * @example
     *          vt.clear().set_new(p, 10);
     *          // do something
     *          vt.clear().set_uint32(1);
     */

    /**
     * 32/24 [0 .. 0x00ffffff]
     * 32/32 [0 .. 0xffffffff]
     */
    variant& set_int24(int32 value);
    variant& set_uint24(uint32 value);
    variant& set_uint24(const byte_t* p, size_t len);
    variant& set_uint24(const uint24_t& value);
    /**
     * 64/48
     */
    variant& set_int48(int64 value);
    variant& set_uint48(uint64 value);
    variant& set_uint48(const byte_t* p, size_t len);
    variant& set_uint48(const uint48_t& value);

    variant& set_fp16(uint16 value);   // binary16
    variant& set_bin32(uint32 value);  // binary32
    variant& set_bin64(uint64 value);  // binary64

    /**
     * user type pointer
     */
    variant& set_user_type(vartype_t vtype, void* value);

    variant& set_str_new(const char* value);

    variant& set_string(const std::string& value);
    variant& set_binary(const binary_t& bin);
    variant& set_stream(const stream_t* s);
    variant& set_datetime(const datetime_t& value);
    variant& set_bn(const bignumber& value);
    variant& set_bn(const unsigned char* p, size_t n);

    /**
     * @brief   to string
     */
    const std::string to_str() const;
    /**
     * @brief   to hexadecimal
     */
    const std::string to_hex() const;
    /**
     * @brief   to binary
     * @param   uint32 flags [inopt] see variant_control_flag_t
     */
    const binary_t to_bin(uint32 flags = 0) const;
    /**
     * @brief   to integer
     */
    int to_int();
    /*
     * @brief   to binary
     * @param   binary_t& target [out]
     * @param   uint32 flags [inopt] see variant_control_flag_t
     */
    return_t to_binary(binary_t& target, uint32 flags = 0) const;
    /**
     * @brief   to string
     * @param   std::string& target [out]
     */
    return_t to_string(std::string& target) const;

    variant& operator=(const variant_t& other);
    variant& operator=(variant_t&& other);

    /**
     * variant& set(uint32)
     */
    template <typename T, typename std::enable_if<(variant_traits<typename std::decay<T>::type>::flags & vt_mask_standalone) == vt_mask_standalone, int>::type = 0>
    variant& set(T&& value) {
        using decay_type = typename std::decay<T>::type;
        using traits = variant_traits<decay_type>;

        _vt.type = traits::type;
        _vt.size = (vt_flag_string & traits::flags) ? 0 : sizeof(decay_type);
        _vt.data.*(traits::member) = std::forward<T>(value);
        _vt.flag = vt_mask_attr & traits::flags;

        return *this;
    };
    /**
     * variant& set(char*, size_t)
     * setter assign only
     */
    template <typename T, typename std::enable_if<(variant_traits<custom::remove_ptr_const_t<T>>::flags & vt_mask_composite) == vt_mask_composite, int>::type = 0>
    variant& set(T&& value, size_t size) {
        using traits = variant_traits<custom::remove_ptr_const_t<T>>;

        _vt.type = traits::type;
        _vt.size = size;
        auto non_const_value = const_cast<typename custom::remove_ptr_const_t<T>>(value);
        _vt.data.*(traits::member) = reinterpret_cast<typename traits::cast_type>(non_const_value);
        _vt.flag = vt_mask_attr & traits::flags;

        return *this;
    };
    /**
     * variant& set_new(char*, size_t)
     */
    template <typename T,                                                                                                                   //
              typename std::enable_if<((variant_traits<custom::remove_ptr_const_t<T>>::flags & vt_mask_composite) == vt_mask_composite) &&  //
                                          ((variant_traits<custom::remove_ptr_const_t<T>>::flags & vt_flag_free) == vt_flag_free),
                                      int>::type = 0>
    variant& set_new(T&& value, size_t size) {
        using traits = variant_traits<custom::remove_ptr_const_t<T>>;

        _vt.type = traits::type;
        _vt.size = 0;
        _vt.flag = vt_mask_attr & traits::flags;
        _vt.data.*(traits::member) = nullptr;

        unsigned char* p = nullptr;
        if (size) {
            p = (unsigned char*)malloc(size + 1);
            if (p) {
                memcpy(p, value, size);
                *(p + size) = 0;
                _vt.size = size;
                _vt.flag |= vt_flag_free;
                _vt.data.*(traits::member) = reinterpret_cast<typename traits::cast_type>(p);
            }
        }

        return *this;
    };

    variant& set(const variant& other) { return *this = other; }
    variant& set(variant&& other) { return *this = std::move(other); }
    /**
     * delegation
     */
    template <typename T>
    variant& operator=(T&& value) {
        return set(std::forward<T>(value));
    }

    // variant& operator=(const void* value);
    variant& operator=(const uint24_t& value);
    variant& operator=(const uint48_t& value);

    variant& operator=(const std::string& value);
    variant& operator=(const binary_t& value);
    variant& operator=(const datetime_t& value);
    variant& operator=(const bignumber& value);

    template <typename T, typename = typename std::enable_if<custom::is_integral_traits<T>::value>::type>
    T t_toi() const {
        T i = 0;  // i = T();

        switch (_vt.type) {
            case TYPE_BOOL:
                i = _vt.data.b ? 1 : 0;
                break;
            case TYPE_INT8:
                i = _vt.data.i8;
                break;
            case TYPE_UINT8:
                i = _vt.data.ui8;
                break;
            case TYPE_INT16:
                i = t_narrow_cast(_vt.data.i16);
                break;
            case TYPE_UINT16:
                i = t_narrow_cast(_vt.data.ui16);
                break;
            case TYPE_INT24:
                i = t_narrow_cast(_vt.data.i32);
                break;
            case TYPE_UINT24:
                i = t_narrow_cast(_vt.data.ui32);
                break;
            case TYPE_INT32:
                i = t_narrow_cast(_vt.data.i32);
                break;
            case TYPE_UINT32:
                i = t_narrow_cast(_vt.data.ui32);
                break;
            case TYPE_INT48:
                i = t_narrow_cast(_vt.data.i64);
                break;
            case TYPE_UINT48:
                i = t_narrow_cast(_vt.data.ui64);
                break;
            case TYPE_INT64:
                i = (T)_vt.data.i64;
                break;
            case TYPE_UINT64:
                i = (T)_vt.data.ui64;
                break;
#if defined __SIZEOF_INT128__
            case TYPE_INT128:
                i = (T)_vt.data.i128;
                break;
            case TYPE_UINT128:
                i = (T)_vt.data.ui128;
                break;
#endif
            case TYPE_FLOAT:
                i = t_narrow_cast(std::round(_vt.data.f));
                break;
            case TYPE_DOUBLE:
                i = t_narrow_cast(std::round(_vt.data.d));
                break;
            case TYPE_STRING:
            case TYPE_NSTRING:
                if (_vt.size) {
                    i = t_atoi_n<T>(_vt.data.str, _vt.size);
                } else {
                    i = t_atoi_n<T>(_vt.data.str, strlen(_vt.data.str));
                }
                break;
            case TYPE_BINARY: {
                return_t errorcode = success;
                i = t_binary_to_integer<T>(_vt.data.bstr, _vt.size, errorcode);
            } break;
            default:
                break;
        }
        if ((i >= 0) && (vt_flag_negative & _vt.flag)) {
            i += 1;
            i = t_change_sign<T>(i);  // i = -i
        }
        return i;
    }

   protected:
   private:
    variant_t _vt;
};

}  // namespace hotplace

#endif
