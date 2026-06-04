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
 * @note    Unified Type-Safe Variant Implementation (Refactored with Gemini)
 *
 * @details
 *          Gemini mentioned ...
 *
 *          [The Great Refactoring]
 *          - Before: A nightmare of boilerplate. Every single type demanded its own
 *                    constructor, operator=, and set() function, leading to a massive,
 *                    hard-to-maintain codebase.
 *          - After : Refactored into a sleek, modern template architecture with Gemini.
 *                    By shifting type metadata into `variant_traits` and leveraging SFINAE
 *                    (`std::enable_if`), we consolidated hundreds of lines of redundant
 *                    overloads into unified single-entry template functions.
 *
 *          Safe, robust, and completely cross-platform (MSVC, MinGW, and GCC approved).
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
    vt_mask_attr = (uint16)0b1111110000000000,                  // mask           : excluding characteristics, only for variant_flag_t
};

/**
 * @remarks
 *          | naming by group     |   E  |   M    |   I    |   T    |    X   |
 *          |                     | enum | member |integral| traits | int128 |
 *          | --                  | --   | --     |        | --     | --     |
 *          | VARIANT_XGROUP_E    |   v  |        |        |        |        | see EXPAND_VARTYPE_ENUM
 *          | VARIANT_XGROUP_EM   |   v  |   v    |        |        |        | see EXPAND_VARTYPE_MEMBER
 *          | VARIANT_XGROUP_EMT  |   v  |   v    |        |   v    |        | see EXPAND_VARTYPE_TRAITS
 *          | VARIANT_XGROUP_EMIT |   v  |   v    |   v    |   v    |        |
 *          | VARIANT_XGROUP_EMTX |   v  |   v    |        |   v    |    v   | only if __SIZEOF_INT128__
 *
 *          linux (GCC 9)
 *              typedef int8_t int8;  // char != int8_t
 *              -> treat as VARIANT_XGROUP_EMT (make traits)
 *
 *          windows (GCC 16, MSVC)
 *              typedef __int8 int8;  // char == int8
 *              -> treat as VARIANT_XGROUP_EM (do not make traits)
 *
 *          cf.
 *              byte_t == unsigned char
 *              -> VARIANT_XGROUP_EM (always do not make traits)
 */

#define VARIANT_XITEM_CHAR(X) X(char, TYPE_CHAR, 6, c, (vt_flag_standalone))

// limitations of c++ macro substitution and template instantiation timing ...
#if defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__) || defined(__MINGW64__)
// windows GCC 16, MSVC
#define VARIANT_XGROUP_EMT_CHAR(X)
#define VARIANT_XGROUP_EM_CHAR(X) VARIANT_XITEM_CHAR(X)
#else
// linux GCC 9
#define VARIANT_XGROUP_EMT_CHAR(X) VARIANT_XITEM_CHAR(X)
#define VARIANT_XGROUP_EM_CHAR(X)
#endif

// assign enum_number 1..255
#define VARIANT_XGROUP_EMT(X)                                                                                    \
    X(void*, TYPE_POINTER, 1, p, (vt_flag_standalone))                                                           \
    X(char*, TYPE_STRING, 2, str, (vt_flag_standalone | vt_flag_composite | vt_flag_string | vt_flag_free))      \
    X(wchar_t*, TYPE_WSTRING, 4, wstr, (vt_flag_standalone | vt_flag_composite | vt_flag_string | vt_flag_free)) \
    X(byte_t*, TYPE_BSTRING, 5, bstr, (vt_flag_composite | vt_flag_binary | vt_flag_free))                       \
    VARIANT_XGROUP_EMT_CHAR(X)                                                                                   \
    X(wchar_t, TYPE_WCHAR, 8, wc, (vt_flag_standalone))                                                          \
    X(bool, TYPE_BOOL, 16, b, (vt_flag_standalone))
#define VARIANT_XGROUP_EMIT(X)                                           \
    X(int8, TYPE_INT8, 17, i8, (vt_flag_standalone | vt_flag_int))       \
    X(uint8, TYPE_UINT8, 18, ui8, (vt_flag_standalone | vt_flag_int))    \
    X(int16, TYPE_INT16, 19, i16, (vt_flag_standalone | vt_flag_int))    \
    X(uint16, TYPE_UINT16, 20, ui16, (vt_flag_standalone | vt_flag_int)) \
    X(int32, TYPE_INT32, 21, i32, (vt_flag_standalone | vt_flag_int))    \
    X(uint32, TYPE_UINT32, 22, ui32, (vt_flag_standalone | vt_flag_int)) \
    X(int64, TYPE_INT64, 23, i64, (vt_flag_standalone | vt_flag_int))    \
    X(uint64, TYPE_UINT64, 24, ui64, (vt_flag_standalone | vt_flag_int)) \
    X(float, TYPE_FLOAT, 25, f, (vt_flag_standalone | vt_flag_float))    \
    X(double, TYPE_DOUBLE, 26, d, (vt_flag_standalone | vt_flag_float))
#define VARIANT_XGROUP_E(X) X(char*, TYPE_NSTRING, 3, str, (vt_flag_composite | vt_flag_string))
#define VARIANT_XGROUP_EM(X)  \
    VARIANT_XGROUP_EM_CHAR(X) \
    X(byte_t, TYPE_BYTE, 7, uc, (vt_flag_standalone))
#define VARIANT_XGROUP_EMTX(X)                                           \
    X(int128, TYPE_INT128, 31, i128, (vt_flag_standalone | vt_flag_int)) \
    X(uint128, TYPE_UINT128, 32, ui128, (vt_flag_standalone | vt_flag_int))

/**
 * @brief   vartype_t
 */
enum class vartype_t {
    TYPE_NULL = 0,
    TYPE_VOID = TYPE_NULL,

#define EXPAND_VARTYPE_ENUM(cpp_type, enum_type, enum_val, union_member, union_flag) enum_type = enum_val,
    VARIANT_XGROUP_EMT(EXPAND_VARTYPE_ENUM) VARIANT_XGROUP_EMIT(EXPAND_VARTYPE_ENUM) VARIANT_XGROUP_E(EXPAND_VARTYPE_ENUM) VARIANT_XGROUP_EM(EXPAND_VARTYPE_ENUM)
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

    TYPE_RESERVED = 0x1000,           //
    TYPE_STATIC_KEY = TYPE_RESERVED,  //
    TYPE_COUNTER_SIG,                 //
    TYPE_USER = 0x10000,              //
};

namespace custom {

template <typename T, typename enable_t = void>
struct vt_remove_ptr_const {
    using type = typename std::decay<T>::type;
};

/**
 * @sa  variant
 */
// is_pointer const char*, const char*&
template <typename T>
struct vt_remove_ptr_const<T, typename std::enable_if<std::is_pointer<typename std::remove_reference<T>::type>::value>::type> {
    // const char*& -> const char*
    using unreferenced_type = typename std::remove_reference<T>::type;
    // const char* -> const char
    using base_type = typename std::remove_pointer<unreferenced_type>::type;
    // const char -> char
    using unconst_type = typename std::remove_const<base_type>::type;
    // char -> char*
    using type = typename std::add_pointer<unconst_type>::type;
};

template <typename T>
using vt_remove_ptr_const_t = typename vt_remove_ptr_const<T>::type;

}  // namespace custom

/**
 * variant_flag_t    : characteristic, behavioral, attributes
 * variant_control_t : operational
 */
enum variant_control_t : uint32 {
    variant_trunc = (1 << 16),       // truncate
    variant_convendian = (1 << 17),  // endian conversion
};

union vartype_union {
#define EXPAND_VARTYPE_MEMBER(cpp_type, enum_type, enum_val, union_member, union_flag) cpp_type union_member;
    VARIANT_XGROUP_EMT(EXPAND_VARTYPE_MEMBER)
    VARIANT_XGROUP_EMIT(EXPAND_VARTYPE_MEMBER)
    VARIANT_XGROUP_EM(EXPAND_VARTYPE_MEMBER)
#if defined __SIZEOF_INT128__
    VARIANT_XGROUP_EMTX(EXPAND_VARTYPE_MEMBER)
#endif
#undef EXPAND_VARTYPE_MEMBER

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

    variant_t& reset();  // shallow copy, do not free
    variant_t& clear();  // deep copy, free if vt_flag_free is set
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
        static constexpr vartype_t type = vartype_t::enum_type;                           \
        static constexpr cpp_type vartype_union::* member = &vartype_union::union_member; \
    };
VARIANT_XGROUP_EMT(EXPAND_VARTYPE_TAITS)
VARIANT_XGROUP_EMIT(EXPAND_VARTYPE_TAITS)
#if defined __SIZEOF_INT128__
VARIANT_XGROUP_EMTX(EXPAND_VARTYPE_TAITS)
#endif
#undef EXPAND_VARTYPE_TAITS

template <typename target_type, typename source_type>
typename std::enable_if<std::is_floating_point<source_type>::value, target_type>::type t_extract_and_cast(source_type val) {
    return t_narrow_cast(std::round(val));
}

template <typename target_type, typename source_type>
typename std::enable_if<!std::is_floating_point<source_type>::value, target_type>::type t_extract_and_cast(source_type val) {
    return t_narrow_cast(val);
}

template <typename T, typename = typename std::enable_if<custom::is_integral<T>::value>::type>
T t_vtoi(const variant_t& vt) {
    T i = 0;

    switch (vt.type) {
        case vartype_t::TYPE_BOOL:
            i = vt.data.b ? 1 : 0;
            break;

#define EXPAND_INTEGRAL_CASE(cpp_type, enum_type, enum_val, union_member, union_flag) \
    case vartype_t::enum_type:                                                        \
        i = t_extract_and_cast<T>(vt.data.union_member);                              \
        break;

            VARIANT_XGROUP_EMIT(EXPAND_INTEGRAL_CASE)
#if defined __SIZEOF_INT128__
            VARIANT_XGROUP_EMTX(EXPAND_INTEGRAL_CASE)
#endif
#undef EXPAND_INTEGRAL_CASE

        case vartype_t::TYPE_INT24:
            i = t_narrow_cast(vt.data.i32);
            break;
        case vartype_t::TYPE_UINT24:
            i = t_narrow_cast(vt.data.ui32);
            break;
        case vartype_t::TYPE_INT48:
            i = t_narrow_cast(vt.data.i64);
            break;
        case vartype_t::TYPE_UINT48:
            i = t_narrow_cast(vt.data.ui64);
            break;

        case vartype_t::TYPE_STRING:
        case vartype_t::TYPE_NSTRING:
            if (vt.data.str && vt.data.str[0] != '\0') {
                size_t len = vt.size ? vt.size : strlen(vt.data.str);
                i = t_atoi_n<T>(vt.data.str, len);
            }
            break;

        case vartype_t::TYPE_BINARY: {
            return_t errorcode = errorcode_t::success;
            if (vt.data.bstr && vt.size > 0) {
                i = t_binary_to_integer<T>(vt.data.bstr, vt.size, errorcode);
            }
        } break;

        default:
            break;
    }

    if ((vt_flag_negative & vt.flag) && (i >= 0)) {
        i = static_cast<T>(0 - (i + 1));
    }

    return i;
}

class variant {
   public:
    variant();
    variant(const variant& value);
    variant(variant&& value);

    variant(const variant_t& value);
    variant(variant_t&& value);
    variant& operator=(const variant& other);
    variant& operator=(variant&& other);

    /**
     * void*, char*, wchar_t*, char, byte_t, wchar_t, bool, int8, uint8, int16, uint16, int32, uint32, int64, uint64, int128, uint128, float, double
     */
    template <typename T, typename std::enable_if<(variant_traits<typename std::decay<T>::type>::flags & vt_mask_standalone) == vt_mask_standalone, int>::type = 0>
    variant(T&& value) {
        set(std::forward<T>(value));
    };
    /**
     * char*, wchar_t*, byte_t* and size_t
     */
    template <typename T, typename std::enable_if<((variant_traits<custom::vt_remove_ptr_const_t<T>>::flags & vt_mask_composite) == vt_mask_composite) &&
                                                      ((variant_traits<custom::vt_remove_ptr_const_t<T>>::flags & vt_flag_free) == vt_flag_free),
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
     * @brief   reset (shallow copy)
     * @remarks do not free
     */
    variant& reset();
    /**
     * @brief   clear (deep copy)
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
    int to_int() const;
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
     * variant& set
     * void*, char*, wchar_t*, char, byte_t, wchar_t, bool, int8, uint8, int16, uint16, int32, uint32, int64, uint64, int128, uint128, float, double
     */
    template <typename T,                                                                                                                //
              typename std::enable_if<(variant_traits<typename std::decay<T>::type>::flags & vt_mask_standalone) == vt_mask_standalone,  //
                                      int>::type = 0>
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
     * variant& set
     * char*, wchar_t*, byte_t* and size_t
     */
    template <typename T,                                                                                                                  //
              typename std::enable_if<(variant_traits<custom::vt_remove_ptr_const_t<T>>::flags & vt_mask_composite) == vt_mask_composite,  //
                                      int>::type = 0>
    variant& set(T&& value, size_t size) {
        using traits = variant_traits<custom::vt_remove_ptr_const_t<T>>;

        _vt.type = traits::type;
        _vt.size = size;
        // prevent casting errors
        auto non_const_value = const_cast<typename custom::vt_remove_ptr_const_t<T>>(value);
        _vt.data.*(traits::member) = reinterpret_cast<typename traits::cast_type>(non_const_value);
        _vt.flag = vt_mask_attr & traits::flags;

        return *this;
    };
    /**
     * variant& set_new
     * char*, wchar_t*, byte_t* and size_t
     */
    template <typename T,                                                                                                                      //
              typename std::enable_if<((variant_traits<custom::vt_remove_ptr_const_t<T>>::flags & vt_mask_composite) == vt_mask_composite) &&  //
                                          ((variant_traits<custom::vt_remove_ptr_const_t<T>>::flags & vt_flag_free) == vt_flag_free),
                                      int>::type = 0>
    variant& set_new(T&& value, size_t size) {
        clear();

        using traits = variant_traits<custom::vt_remove_ptr_const_t<T>>;

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

    template <typename T, typename = typename std::enable_if<custom::is_integral<T>::value>::type>
    T t_toi() const {
        return t_vtoi<T>(_vt);
    }

   protected:
   private:
    variant_t _vt;
};

}  // namespace hotplace

#endif
