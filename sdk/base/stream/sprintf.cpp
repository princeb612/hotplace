/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sprintf.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2017.07.26   Soo Han, Kim        sprintf support {1} {2} ... using valist (codename.grape Revision 371)
 * 2024.09.13   Soo Han, Kim        Aho-Corasick algorithm applied (codename.hotplace Revision 607)
 * 2026.05.06   Soo Han, Kim        format string syntax e.g. {1:02x} {1:3d} {2:-10s} (codename.hotplace Revision 977)
 * 2026.05.20   Soo Han, Kim        the format specifier 's' in TYPE_BINARY, it outputs a character if it is printable, and '.' otherwise.
 * 2026.06.10   Soo Han, Kim        the format specifier 'x' in TYPE_BINARY, base16 encoding.
 */

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/pattern/aho_corasick.hpp>
#include <hotplace/sdk/base/pattern/regex.hpp>
#include <hotplace/sdk/base/stream/ansi_string.hpp>
#include <hotplace/sdk/base/stream/sprintf.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>
#include <hotplace/sdk/base/system/ieee754.hpp>

namespace hotplace {

typedef struct _variant_conversion_t {
    vartype_t type;
    const char* formatter;
} variant_conversion_t;

static variant_conversion_t type_formatter[] = {
    {vartype_t::TYPE_CHAR, "%c"},    {vartype_t::TYPE_BYTE, "%c"},   {vartype_t::TYPE_INT8, "%i"},   {vartype_t::TYPE_UINT8, "%d"},   {vartype_t::TYPE_INT16, "%i"},
    {vartype_t::TYPE_UINT16, "%d"},  {vartype_t::TYPE_INT32, "%i"},  {vartype_t::TYPE_UINT32, "%u"}, {vartype_t::TYPE_INT64, "%li"},  {vartype_t::TYPE_UINT64, "%lu"},
    {vartype_t::TYPE_POINTER, "%p"}, {vartype_t::TYPE_STRING, "%s"}, {vartype_t::TYPE_FLOAT, "%f"},  {vartype_t::TYPE_DOUBLE, "%lf"}, {vartype_t::TYPE_BINARY, "%p"},
};
size_t size_type_formatter = RTL_NUMBER_OF(type_formatter);

return_t sprintf(stream_t* stream, const char* fmt, valist va) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == stream || nullptr == fmt) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        variant_t v;
        size_t i = 0;

        ansi_string formatter;
        formatter.write((void*)fmt, strlen(fmt));

        typedef std::map<vartype_t, std::string> formatter_map_t;
        formatter_map_t fmtspec;  // format specifier
        for (i = 0; i < size_type_formatter; i++) {
            variant_conversion_t* item = type_formatter + i;
            fmtspec.emplace(item->type, item->formatter);
        }

        {
            /**
             * format string syntax
             * regular expression based
             *
             * {1:08x} {2:-15s} {3:10d}
             * {1:08x} {1} {3:08x}
             */

            ansi_string formatter;
            formatter.write((void*)fmt, strlen(fmt));
            valist va_new;

            const char* expr = R"(\{(\d+):?([^}]*)\})";
            size_t pos = 0;
            std::list<std::map<size_t, range_t>> tokens;
            std::list<std::pair<std::string, std::string>> fmtlist;

            regex_tokens(formatter.c_str(), formatter.size(), expr, pos, tokens);

            for (auto matchit = tokens.begin(); matchit != tokens.end(); ++matchit) {
                auto match = *matchit;

                // param id
                auto param_range = match[1];
                auto param_id = t_atoi_n<int>(formatter.c_str() + param_range.begin, param_range.end - param_range.begin);
                if ((0 == param_id) || (size_t(param_id) > va.size())) {
                    continue;
                }

                size_t idx = param_id - 1;
                auto v = va[idx];
                auto vtype = v.type;
                auto vflag = v.flag;
                variant vtemp;

                // full match
                auto range = match[0];
                std::string src(formatter.c_str() + range.begin, range.end - range.begin);

                // format specifier
                std::string dest;
                auto fmtovl = match[2];
                if (fmtovl.begin != fmtovl.end) {
                    std::string temp(formatter.c_str() + fmtovl.begin, fmtovl.end - fmtovl.begin);
                    char b = temp[0];
                    char r = *temp.rbegin();
                    if (b == '%') { /* do nothing */
                    } else {
                        if (vt_flag_int & vflag) {
                            switch (r) {
                                case 'd':
                                case 'i':
                                    dest = std::move(temp);
                                    dest.insert(dest.begin(), '%');
                                    break;
                                case 'x':  // 0x
                                    dest = std::move(temp);
                                    dest.insert(dest.begin(), '%');
                                    dest.insert(dest.begin(), 'x');
                                    dest.insert(dest.begin(), '0');
                                    break;
                            }
                        } else if (vt_flag_string & vflag) {
                            switch (r) {
                                case 's':
                                    dest = std::move(temp);
                                    dest.insert(dest.begin(), '%');
                                    break;
                            }
                        } else if (vt_flag_float & vflag) {
                            switch (r) {
                                case 'e':
                                case 'f':
                                case 'g':
                                    dest = std::move(temp);
                                    dest.insert(dest.begin(), '%');
                                    break;
                            }
                        } else if (vt_flag_binary & vflag) {
                            switch (r) {
                                case 's': {
                                    auto len = v.size;
                                    std::string str;
                                    str.reserve(len + 1);

                                    // printable data (TYPE_BINARY)
                                    std::transform(v.data.bstr, v.data.bstr + len, std::back_inserter(str),
                                                   [](unsigned char c) { return std::isprint(c) ? static_cast<char>(c) : '.'; });

                                    variant t(str);
                                    vtemp = std::move(t);

                                    dest = std::move(temp);
                                    dest.insert(dest.begin(), '%');
                                } break;
                                case 'x':
                                    dest = std::move(base16_encode(v.data.bstr, v.size));
                                    break;
                            }
                        }
                    }
                }
                if (dest.empty()) {
                    auto it = fmtspec.find(vtype);
                    if (fmtspec.end() != it) {
                        dest = it->second;
                    }
                }

                if (vartype_t::TYPE_NULL == vtemp.type()) {
                    va_new << v;
                } else {
                    va_new << std::move(vtemp.get());
                    vtemp.reset();
                }
                fmtlist.push_back({std::move(src), std::move(dest)});
            }

            for (auto item : fmtlist) {
                formatter.replace(item.first.c_str(), item.second.c_str(), 0, bufferio_flag_t::run_once);
            }

            stream->vprintf((char*)formatter.data(), va_new.get());
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace hotplace
