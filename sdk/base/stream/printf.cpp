/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/base16.hpp>
#include <sdk/base/basic/ieee754.hpp>
#include <sdk/base/basic/valist.hpp>
#include <sdk/base/pattern/aho_corasick.hpp>
#include <sdk/base/stream/printf.hpp>
#include <sdk/base/stream/tstring.hpp>
#include <sdk/base/string/string.hpp>

namespace hotplace {

typedef struct _variant_conversion_t {
    int type;
    const char* formatter;
} variant_conversion_t;

#if __cplusplus >= 201103L  // c++11
#define VARIANT_CONVERSION_ITEM(t, f) \
    {                                 \
        .type = t,                    \
        .formatter = f,               \
    }
#else
#define VARIANT_CONVERSION_ITEM(t, f) \
    {                                 \
        t,                            \
        f,                            \
    }
#endif

static variant_conversion_t type_formatter[] = {
    VARIANT_CONVERSION_ITEM(TYPE_CHAR, "%c"),   VARIANT_CONVERSION_ITEM(TYPE_BYTE, "%c"),    VARIANT_CONVERSION_ITEM(TYPE_SHORT, "%i"),
    VARIANT_CONVERSION_ITEM(TYPE_USHORT, "%i"), VARIANT_CONVERSION_ITEM(TYPE_INT32, "%i"),   VARIANT_CONVERSION_ITEM(TYPE_UINT32, "%i"),
    VARIANT_CONVERSION_ITEM(TYPE_INT64, "%li"), VARIANT_CONVERSION_ITEM(TYPE_UINT64, "%li"), VARIANT_CONVERSION_ITEM(TYPE_POINTER, "%p"),
    VARIANT_CONVERSION_ITEM(TYPE_STRING, "%s"), VARIANT_CONVERSION_ITEM(TYPE_FLOAT, "%f"),   VARIANT_CONVERSION_ITEM(TYPE_DOUBLE, "%lf"),
};
size_t size_type_formatter = sizeof(type_formatter) / sizeof(type_formatter[0]);

return_t sprintf(stream_t* stream, const char* fmt, valist va) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (nullptr == fmt) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        variant_t v;
        size_t i = 0;

        ansi_string formatter;
        formatter.write((void*)fmt, strlen(fmt));

#if 0

        // simple implementation to support only {1} {2} {3}
        // it can't be {3} {2} {1}

        for (i = 0; i != va.size (); i++) {
            va.at (i, v);
            int order = i + 1;
            for (size_t table_index = 0; table_index != RTL_NUMBER_OF (type_formatter); table_index++) {
                if (type_formatter[table_index].type == v.type) {
                    formatter.replace (format ("{%d}", order).c_str (), type_formatter[table_index].formatter);
                    break;
                }
            }
        }

        stream->vprintf ((char *) formatter.data (), va.get ());

#endif

        // Step1. check order using map ...
        typedef std::map<size_t, size_t> va_map_t;
        typedef std::list<int> va_array_t;
        va_map_t va_map; /* pair(position, {id}) */
        va_array_t va_array;
        t_aho_corasick<char> ac;
        for (i = 0; i < va.size(); i++) {
            auto pat = format("{%zi}", i + 1);
            ac.insert(pat.c_str(), pat.size());
        }
        ac.build();
        auto result = ac.search(formatter.c_str(), formatter.size());
        for (auto item : result) {
            const range_t& range = item.first;
            unsigned patid = item.second;
            va_map.insert({range.begin, patid});
        }

        // Step2. relocate valist, build list
        valist va_new;
        for (const auto& pair : va_map) {
            const auto& idx = pair.second;
            va.at(idx, v);
            va_new << v;
            va_array.push_back(idx);
        }

        // Step3. replace format specifier
        typedef std::map<size_t, std::string> formatter_map_t;
        formatter_map_t formats;
        for (i = 0; i < RTL_NUMBER_OF(type_formatter); i++) {
            variant_conversion_t* item = type_formatter + i;
            formats.insert(std::make_pair(item->type, item->formatter));
        }
        i = 0;
        for (const auto& idx : va_array) {
            va_new.at(i, v);
            formatter_map_t::iterator fmt_it = formats.find(v.type);
            if (formats.end() != fmt_it) {
                formatter.replace(format("{%i}", idx + 1).c_str(), fmt_it->second.c_str(), 0, bufferio_flag_t::run_once);
            }
            i++;
        }

        stream->vprintf((char*)formatter.data(), va_new.get());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

template <typename T1, typename T2>
void vprintf_floating_point(T1 t1, T2 t2, stream_t* stream, vtprintf_style_t style) {
    ieee754_typeof_t t = ieee754_typeof(t1);
    switch (t) {
        case ieee754_typeof_t::ieee754_nan:
            if (vtprintf_style_cbor == style) {
                stream->printf("NaN");
            } else {
                stream->printf("nan");
            }
            break;
        case ieee754_typeof_t::ieee754_ninf:
            stream->printf("-");
        case ieee754_typeof_t::ieee754_pinf:
            if (vtprintf_style_cbor == style) {
                stream->printf("Infinity");
            } else {
                stream->printf("inf");
            }
            break;
        default:
            stream->printf("%g", t2);
            break;
    }
}

return_t vtprintf(stream_t* stream, const variant_t& vt, vtprintf_style_t style) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        constexpr char constexpr_false[] = "false";
        constexpr char constexpr_null[] = "null";
        constexpr char constexpr_true[] = "true";

        switch (vt.type) {
            case TYPE_NULL:
                stream->printf(constexpr_null);
                break;
            case TYPE_BOOL:
                stream->printf("%s", vt.data.b ? constexpr_true : constexpr_false);
                break;
            case TYPE_INT8:
                stream->printf("%i", vt.data.i8);
                break;
            case TYPE_UINT8:
                stream->printf("%u", vt.data.ui8);
                break;
            case TYPE_INT16:
                stream->printf("%i", vt.data.i16);
                break;
            case TYPE_UINT16:
                stream->printf("%u", vt.data.ui16);
                break;
            case TYPE_INT32:
                stream->printf("%i", vt.data.i32);
                break;
            case TYPE_UINT32:
                stream->printf("%u", vt.data.ui32);
                break;
            case TYPE_INT64:
                stream->printf("%I64i", vt.data.i64);
                break;
            case TYPE_UINT64:
                stream->printf("%I64u", vt.data.ui64);
                break;
#if defined __SIZEOF_INT128__
            case TYPE_INT128:
                stream->printf("%I128i", vt.data.i128);
                break;
            case TYPE_UINT128:
                stream->printf("%I128u", vt.data.ui128);
                break;
#endif
            case TYPE_FP16:
                vprintf_floating_point<uint16, float>(vt.data.ui16, float_from_fp16(vt.data.ui16), stream, style);
                break;
            case TYPE_FLOAT:
                vprintf_floating_point<float, float>(vt.data.f, vt.data.f, stream, style);
                break;
            case TYPE_DOUBLE:
                vprintf_floating_point<double, double>(vt.data.d, vt.data.d, stream, style);
                break;
#if defined __SIZEOF_INT128__
            case TYPE_FP128:  // not implemented
                break;
#endif
            case TYPE_POINTER:
                stream->printf("%s", vt.data.p);
                break;
            case TYPE_STRING:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_cbor:
                        stream->printf("\"%s\"", vt.data.str);
                        break;
                    case vtprintf_style_t::vtprintf_style_base16:
                        stream->printf("%s", base16_encode(vt.data.str).c_str());
                        break;
                    case vtprintf_style_t::vtprintf_style_normal:
                    default:
                        stream->printf("%s", vt.data.str);
                        break;
                }
                break;
            case TYPE_NSTRING:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_cbor:
                        stream->printf("\"%.*s\"", vt.size, vt.data.str);
                        break;
                    case vtprintf_style_t::vtprintf_style_base16:
                        stream->printf("%s", base16_encode((byte_t*)vt.data.str, vt.size).c_str());
                        break;
                    case vtprintf_style_t::vtprintf_style_normal:
                    default:
                        stream->printf("%.*s", vt.size, vt.data.str);
                        break;
                }
                break;
            case TYPE_BINARY: {
                std::string temp;
                base16_encode(vt.data.bstr, vt.size, temp);
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_cbor:
                        stream->printf("h'%s'", temp.c_str());
                        break;
                    case vtprintf_style_t::vtprintf_style_base16:
                        stream->printf("%s", base16_encode(vt.data.bstr, vt.size).c_str());
                        break;
                    case vtprintf_style_t::vtprintf_style_normal:
                    default:
                        stream->printf("%s", temp.c_str());
                        break;
                }
            } break;
            default:
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t vtprintf(stream_t* stream, const variant& vt, vtprintf_style_t style) { return vtprintf(stream, vt.content(), style); }

}  // namespace hotplace
