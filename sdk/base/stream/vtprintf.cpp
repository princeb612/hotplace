/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   vtprintf.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2017.07.26   Soo Han, Kim        sprintf support {1} {2} ... using valist (codename.grape Revision 371)
 */

#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/pattern/aho_corasick.hpp>
#include <hotplace/sdk/base/stream/types.hpp>
#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>
#include <hotplace/sdk/base/system/ieee754.hpp>

namespace hotplace {

template <typename T1, typename T2>
void vprintf_floating_point(T1 t1, T2 t2, stream_t* stream, vtprintf_style_t style) {
    ieee754_typeof_t t = ieee754_typeof(t1);
    switch (t) {
        case ieee754_typeof_t::ieee754_nan:
            switch (style) {
                case vtprintf_style_t::vtprintf_style_asn1:
                    stream->printf("NOT-A-NUMBER");
                    break;
                case vtprintf_style_t::vtprintf_style_cbor:
                    stream->printf("NaN");
                    break;
                default:
                    stream->printf("nan");
                    break;
            }
            break;
        case ieee754_typeof_t::ieee754_ninf:
            switch (style) {
                case vtprintf_style_t::vtprintf_style_asn1:
                    stream->printf("MINUS-INFINITY");
                    break;
                case vtprintf_style_t::vtprintf_style_cbor:
                    stream->printf("-Infinity");
                    break;
                default:
                    stream->printf("-inf");
                    break;
            }
            break;
        case ieee754_typeof_t::ieee754_pinf:
            switch (style) {
                case vtprintf_style_t::vtprintf_style_asn1:
                    stream->printf("PLUS-INFINITY");
                    break;
                case vtprintf_style_t::vtprintf_style_cbor:
                    stream->printf("Infinity");
                    break;
                default:
                    stream->printf("inf");
                    break;
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

        constexpr char constexpr_lfalse[] = "false";
        constexpr char constexpr_ufalse[] = "FALSE";
        constexpr char constexpr_lnull[] = "null";
        constexpr char constexpr_unull[] = "NULL";
        constexpr char constexpr_ltrue[] = "true";
        constexpr char constexpr_utrue[] = "TRUE";

        switch (vt.type) {
            case vartype_t::TYPE_NULL:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_asn1:
                        stream->printf(constexpr_unull);
                        break;
                    default:
                        stream->printf(constexpr_lnull);
                        break;
                }
                break;
            case vartype_t::TYPE_BOOL:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_asn1:
                        stream->printf("%s", vt.data.b ? constexpr_utrue : constexpr_ufalse);
                        break;
                    default:
                        stream->printf("%s", vt.data.b ? constexpr_ltrue : constexpr_lfalse);
                        break;
                }
                break;
            case vartype_t::TYPE_INT8:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("0x%02x (%i)", vt.data.i8, vt.data.i8);
                        break;
                    default:
                        stream->printf("%i", vt.data.i8);
                        break;
                }
                break;
            case vartype_t::TYPE_UINT8:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_cbor: {
                        bignumber bn(vt.data.ui8);
                        if (vt.flag & vt_flag_negative) {
                            bn += 1;
                            bn.neg();
                        }
                        stream->printf("%s", bn.str().c_str());
                    } break;
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("0x%02x (%u)", vt.data.ui8, vt.data.ui8);
                        break;
                    default:
                        stream->printf("%u", vt.data.ui8);
                        break;
                }
                break;
            case vartype_t::TYPE_INT16:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("0x%04x (%i)", vt.data.i16, vt.data.i16);
                        break;
                    default:
                        stream->printf("%i", vt.data.i16);
                        break;
                }
                break;
            case vartype_t::TYPE_UINT16:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_cbor: {
                        bignumber bn(vt.data.ui16);
                        if (vt.flag & vt_flag_negative) {
                            bn += 1;
                            bn.neg();
                        }
                        stream->printf("%s", bn.str().c_str());
                    } break;
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("0x%04x (%u)", vt.data.ui16, vt.data.ui16);
                        break;
                    default:
                        stream->printf("%u", vt.data.ui16);
                        break;
                }
                break;
            case vartype_t::TYPE_INT32:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("0x%08x (%i)", vt.data.i32, vt.data.i32);
                        break;
                    default:
                        stream->printf("%i", vt.data.i32);
                        break;
                }
                break;
            case vartype_t::TYPE_UINT32:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_cbor: {
                        bignumber bn(vt.data.ui32);
                        if (vt.flag & vt_flag_negative) {
                            bn += 1;
                            bn.neg();
                        }
                        stream->printf("%s", bn.str().c_str());
                    } break;
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("0x%08x (%u)", vt.data.ui32, vt.data.ui32);
                        break;
                    default:
                        stream->printf("%u", vt.data.ui32);
                        break;
                }
                break;
            case vartype_t::TYPE_INT64:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("0x%0I64x (%I64i)", vt.data.i64, vt.data.i64);
                        break;
                    default:
                        stream->printf("%I64i", vt.data.i64);
                        break;
                }
                break;
            case vartype_t::TYPE_UINT64:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_cbor: {
                        bignumber bn(vt.data.ui64);
                        if (vt.flag & vt_flag_negative) {
                            bn += 1;
                            bn.neg();
                        }
                        stream->printf("%s", bn.str().c_str());
                    } break;
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("0x%0I64x (%I64u)", vt.data.ui64, vt.data.ui64);
                        break;
                    default:
                        stream->printf("%I64u", vt.data.ui64);
                        break;
                }
                break;
#if defined __SIZEOF_INT128__
            case vartype_t::TYPE_INT128:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("0x%0I128x (%I128i)", vt.data.i128, vt.data.i128);
                        break;
                    default:
                        stream->printf("%I128i", vt.data.i128);
                        break;
                }
                break;
            case vartype_t::TYPE_UINT128:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_cbor: {
                        bignumber bn(vt.data.ui128);
                        if (vt.flag & vt_flag_negative) {
                            bn += 1;
                            bn.neg();
                        }
                        stream->printf("%s", bn.str().c_str());
                    } break;
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("0x%0I128x (%I128u)", vt.data.ui128, vt.data.ui128);
                        break;
                    default:
                        stream->printf("%I128u", vt.data.ui128);
                        break;
                }
                break;
#endif
            case vartype_t::TYPE_FP16:
                vprintf_floating_point<uint16, float>(vt.data.ui16, float_from_fp16(vt.data.ui16), stream, style);
                break;
            case vartype_t::TYPE_FLOAT:
                vprintf_floating_point<float, float>(vt.data.f, vt.data.f, stream, style);
                break;
            case vartype_t::TYPE_DOUBLE:
                vprintf_floating_point<double, double>(vt.data.d, vt.data.d, stream, style);
                break;
#if defined __SIZEOF_INT128__
            case vartype_t::TYPE_FP128:  // not implemented
                break;
#endif
            case vartype_t::TYPE_POINTER:
                stream->printf("%s", vt.data.p);
                break;
            case vartype_t::TYPE_STRING:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_asn1:
                    case vtprintf_style_t::vtprintf_style_cbor:
                        stream->printf(R"("%s")", vt.data.str ? vt.data.str : "");
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
            case vartype_t::TYPE_NSTRING:
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_asn1:
                    case vtprintf_style_t::vtprintf_style_cbor:
                        stream->printf(R"("%.*s")", vt.size, vt.data.str);
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
            case vartype_t::TYPE_BINARY: {
                std::string temp;
                base16_encode(vt.data.bstr, vt.size, temp);
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_cbor:
                        stream->printf("h'%s'", temp.c_str());
                        break;
                    case vtprintf_style_t::vtprintf_style_base16:
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("%s", base16_encode(vt.data.bstr, vt.size).c_str());
                        break;
                    case vtprintf_style_t::vtprintf_style_normal:
                    default:
                        stream->printf("%s", temp.c_str());
                        break;
                }
            } break;
            case vartype_t::TYPE_BIGNUMBER: {
                bignumber bn(vt.data.bstr, vt.size);
                switch (style) {
                    case vtprintf_style_t::vtprintf_style_cbor:
                        if (vt_flag_negative & vt.flag) {
                            bn += 1;
                        }
                        stream->printf("%s%s", (vt_flag_negative & vt.flag) ? "-" : "", bn.str().c_str());
                        break;
                    case vtprintf_style_t::vtprintf_style_debugmode:
                        stream->printf("%s (%s%s)", bn.hex().c_str(), (vt_flag_negative & vt.flag) ? "-" : "", bn.str().c_str());
                        break;
                    default:
                        stream->printf("%s%s", (vt_flag_negative & vt.flag) ? "-" : "", bn.str().c_str());
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
