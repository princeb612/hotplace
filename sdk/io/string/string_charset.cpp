/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/string/string.hpp>
#include <string.h>
#include <list>
#include <string>

namespace hotplace {
namespace io {

#if defined _MBCS || defined MBCS
void replace (std::string& source, std::string a, std::string b)
#elif defined _UNICODE || defined UNICODE
void replace (std::wstring& source, std::wstring a, std::wstring b)
#endif
{
    size_t i = source.find (a);

    while (std::string::npos != i) {
        source.replace (i, a.size (), b);
        i = source.find (a, i + b.size ());
    }
}

#if defined _MBCS || defined MBCS
std::string tokenize (std::string source, std::string tokens, size_t& pos)
#elif defined _UNICODE || defined UNICODE
std::wstring tokenize (std::wstring source, std::wstring tokens, size_t& pos)
#endif
{
#if defined _MBCS || defined MBCS
    std::string ret_value;
    size_t npos = std::string::npos;
#elif defined _UNICODE || defined UNICODE
    std::wstring ret_value;
    size_t npos = std::wstring::npos;
#endif
    size_t startpos = 0;
    std::list < size_t > tokenpos;
    size_t sizetoken = tokens.size ();

    if ((npos != pos) || (pos < source.size ())) {
        tokenpos.clear ();
        startpos = pos;
        // find first token
        for (size_t i = 0; i < sizetoken; i++) {
            size_t temppos = source.find_first_of (tokens[i], startpos);
            if ((size_t) -1 == temppos) {
                continue;
            }

            tokenpos.push_back (temppos);
        }

        // search first token
        tokenpos.sort ();

        if (tokenpos.empty ()) {
            if (startpos < source.size ()) {
                ret_value.assign (source.substr (startpos));
            }
            pos = (size_t) (-1);
        } else {
            size_t first = tokenpos.front ();
            if (first == startpos) {
                pos++;
                ret_value = tokenize (source, tokens, pos);
            } else {
                ret_value.assign (source.substr (startpos, first - startpos));
                pos = startpos + (first - startpos) + 1;
            }
        }
    }

    return ret_value;
}

#if defined _MBCS || defined MBCS
bool gettoken (std::string source, std::string token, size_t index, std::string& value)
#elif defined _UNICODE || defined UNICODE
bool gettoken (std::wstring source, std::wstring token, size_t index, std::wstring& value)
#endif
{
    bool ret = false;
    size_t pos = 0;

#if defined _MBCS || defined MBCS
    std::string item;
#elif defined _UNICODE || defined UNICODE
    std::wstring item;
#endif
    value.clear ();

    for (size_t i = 0;; i++) {
        item = tokenize (source, token, pos);
        if (index == i) {
            value = item;
            ret = true;
            break;
        }
        if ((size_t) -1 == pos) {
            break;
        }
    }
    return ret;
}

#if defined _MBCS || defined MBCS
return_t scan (const char* stream, size_t sizestream, size_t startpos, size_t *brk, int (*func)(int))
#elif defined _UNICODE || defined UNICODE
return_t scan (const wchar_t* stream, size_t sizestream, size_t startpos, size_t *brk, int (*func)(int))
#endif
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == stream || nullptr == brk || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
        if (startpos >= sizestream) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }

        const TCHAR* pos = stream + startpos;
        const TCHAR* epos = stream + sizestream;
        const TCHAR* p = stream + startpos;

        while (0 == (*func)(*p) && p < epos) {
            p++;
        }
        *brk = startpos + p - pos + 1;
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

#if defined _MBCS || defined MBCS
return_t scan (const char* stream, size_t sizestream, size_t startpos, size_t *brk, const char* match)
#elif defined _UNICODE || defined UNICODE
return_t scan (const wchar_t* stream, size_t sizestream, size_t startpos, size_t *brk, const wchar_t* match)
#endif
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == stream || nullptr == brk || nullptr == match) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
        if (startpos >= sizestream) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }

        const TCHAR* pos = stream + startpos;
        const TCHAR* epos = stream + sizestream;
        const TCHAR* p = stream + startpos;

#if defined _MBCS || defined MBCS
        size_t sizetoken = strlen (match);
        while ((0 != strnicmp (match, p, sizetoken)) && p < epos) {
            p++;
        }
#elif defined _UNICODE || defined UNICODE
        size_t sizetoken = wcslen (match);
        while ((0 != wcsnicmp (match, p, sizetoken)) && p < epos) {
            p++;
        }
#endif

        if (p < epos) {
            *brk = startpos + p - pos + 1;
        } else {
            ret = errorcode_t::not_found;
        }
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

#if defined _MBCS || defined MBCS
return_t getline (const char* stream, size_t sizestream, size_t startpos, size_t *brk)
#elif defined _UNICODE || defined UNICODE
return_t getline (const wchar_t* stream, size_t sizestream, size_t startpos, size_t *brk)
#endif
{
    return scan (stream, sizestream, startpos, brk, _T ("\n"));
}

}
}  // namespace
