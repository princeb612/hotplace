/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sprintf.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2017.07.26   Soo Han, Kim        sprintf support {1} {2} ... using valist (codename.grape Revision 371)
 */

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/pattern/aho_corasick.hpp>
#include <hotplace/sdk/base/stream/printf.hpp>
#include <hotplace/sdk/base/stream/tstring.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>
#include <hotplace/sdk/base/system/ieee754.hpp>

namespace hotplace {

typedef struct _variant_conversion_t {
    int type;
    const char* formatter;
} variant_conversion_t;

static variant_conversion_t type_formatter[] = {
    {TYPE_CHAR, "%c"},   {TYPE_BYTE, "%c"},    {TYPE_SHORT, "%i"},   {TYPE_USHORT, "%d"}, {TYPE_INT32, "%i"}, {TYPE_UINT32, "%u"},
    {TYPE_INT64, "%li"}, {TYPE_UINT64, "%lu"}, {TYPE_POINTER, "%p"}, {TYPE_STRING, "%s"}, {TYPE_FLOAT, "%f"}, {TYPE_DOUBLE, "%lf"},
};
size_t size_type_formatter = RTL_NUMBER_OF(type_formatter);

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
        typedef std::list<size_t> va_array_t;
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
            auto patid = item.second;
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

}  // namespace hotplace
