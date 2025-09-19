/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_TSTRING__
#define __HOTPLACE_SDK_BASE_STREAM_TSTRING__

#include <hotplace/sdk/base/charset.hpp>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/bufferio.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <ostream>

namespace hotplace {

class ansi_string : public stream_t {
   public:
    ansi_string();
    ansi_string(const char* data);
    ansi_string(const ansi_string& rhs);
    ansi_string(ansi_string&& rhs);
    virtual ~ansi_string();

    virtual byte_t* data() const;
    virtual uint64 size() const;
    virtual return_t write(const void* data, size_t size);
    virtual return_t fill(size_t l, char c);
    virtual return_t clear();

    virtual bool empty();
    virtual bool occupied();

    virtual return_t printf(const char* buf, ...);
    virtual return_t vprintf(const char* buf, va_list ap);
#if defined _WIN32 || defined _WIN64
    return_t printf(const wchar_t* buf, ...);
    return_t vprintf(const wchar_t* buf, va_list ap);
#endif

    return_t vprintf(const char* fmt, valist ap);

    const char* c_str() const;
    size_t find(char* data);

    /**
     * @brief replace
     * @param const char* from [in]
     * @param const char* to [in]
     * @param size_t begin [inopt]
     * @param int flag [inopt] bufferio_flag_t::run_once
     */
    return_t replace(const char* from, const char* to, size_t begin = 0, int flag = 0);
    ansi_string substr(size_t begin, size_t len);
    return_t cut(size_t begin, size_t len);
    return_t trim();
    return_t ltrim();
    return_t rtrim();
    /* std::string::find */
    size_t find_first_of(const char* find, size_t offset = 0);
    size_t find_not_first_of(const char* find, size_t offset = 0);
    /* std::string::rfind */
    size_t find_last_of(const char* find);
    size_t find_not_last_of(const char* find);
    /**
     * @brief
     * @param size_t pos [in] current position
     * @param size_t* brk [out] next line position
     * @param ansi_string& line [out] temporary
     * @example
     *        size_t pos = 0;
     *        size_t brk = 0;
     *        while (1)
     *        {
     *          ret = stream.getline(pos, &brk, line);
     *          if (errorcode_t::success != ret)
     *            break;
     *          printf("%s\n", line.c_str());
     *          pos = brk;
     *        }
     */
    return_t getline(size_t pos, size_t* brk, ansi_string& line);

    ansi_string& operator=(const char* buf);
#if defined _WIN32 || defined _WIN64
    ansi_string& operator=(const wchar_t* buf);
#endif
    ansi_string& operator=(char buf);
    ansi_string& operator=(byte_t buf);
    ansi_string& operator=(uint16 buf);
    ansi_string& operator=(uint32 buf);
    ansi_string& operator=(uint64 buf);
    ansi_string& operator=(float buf);
    ansi_string& operator=(double buf);
    ansi_string& operator=(const ansi_string& rhs);
    ansi_string& operator=(ansi_string&& rhs);

    ansi_string& operator+=(const char* buf);
#if defined _WIN32 || defined _WIN64
    ansi_string& operator+=(const wchar_t* buf);
#endif
    ansi_string& operator+=(char buf);
    ansi_string& operator+=(byte_t buf);
    ansi_string& operator+=(uint16 buf);
    ansi_string& operator+=(uint32 buf);
    ansi_string& operator+=(uint64 buf);
    ansi_string& operator+=(float buf);
    ansi_string& operator+=(double buf);
    ansi_string& operator+=(const ansi_string& buf);

    ansi_string& operator<<(const char* buf);
#if defined _WIN32 || defined _WIN64
    ansi_string& operator<<(const wchar_t* buf);
#endif
    ansi_string& operator<<(char buf);
    ansi_string& operator<<(byte_t buf);
    ansi_string& operator<<(uint16 buf);
    ansi_string& operator<<(uint32 buf);
    ansi_string& operator<<(uint64 buf);
    ansi_string& operator<<(float buf);
    ansi_string& operator<<(double buf);
    ansi_string& operator<<(const ansi_string& buf);

#if defined __SIZEOF_INT128__
    ansi_string& operator=(uint128 buf);
    ansi_string& operator+=(uint128 buf);
    ansi_string& operator<<(uint128 buf);
#endif

    int compare(const ansi_string& buf);
    static int compare(const ansi_string& lhs, const ansi_string& rhs);

    bool operator<(const ansi_string& buf) const;
    bool operator>(const ansi_string& buf) const;

    bool operator==(const ansi_string& buf) const;
    bool operator!=(const ansi_string& buf) const;

    bool operator==(const char* input);
    bool operator!=(const char* input);

    friend std::string& operator+=(std::string& lhs, const ansi_string& rhs);
    friend std::string& operator<<(std::string& lhs, const ansi_string& rhs);
    friend std::ostream& operator<<(std::ostream& lhs, const ansi_string& rhs);

    virtual void autoindent(uint8 indent);

   protected:
   private:
    bufferio _bio;
    bufferio_context_t* _handle;
};

#if defined _WIN32 || defined _WIN64
class wide_string : public stream_t {
   public:
    wide_string();
    wide_string(const wchar_t* data);
    wide_string(const wide_string& rhs);
    wide_string(wide_string&& rhs);
    virtual ~wide_string();

    virtual byte_t* data() const;
    virtual uint64 size() const;
    virtual return_t write(const void* data, size_t size);
    virtual return_t fill(size_t l, char c);
    virtual return_t clear();

    virtual bool empty();
    virtual bool occupied();

    virtual return_t printf(const char* buf, ...);
    virtual return_t vprintf(const char* buf, va_list ap);
    return_t printf(const wchar_t* buf, ...);
    return_t vprintf(const wchar_t* buf, va_list ap);

    const wchar_t* c_str() const;
    size_t find(wchar_t* data);

    /**
     * @brief replace
     * @param const wchar_t* from [in]
     * @param const wchar_t* to [in]
     * @param size_t begin [inopt]
     * @param int flag [inopt] bufferio_flag_t::run_once
     */
    return_t replace(const wchar_t* from, const wchar_t* to, size_t begin = 0, int flag = 0);
    wide_string substr(size_t begin, size_t len);

    return_t cut(size_t begin, size_t len);
    return_t trim();
    return_t ltrim();
    return_t rtrim();

    /* std::string::find */
    size_t find_first_of(const wchar_t* find, size_t offset = 0);
    size_t find_not_first_of(const wchar_t* find, size_t offset = 0);
    /* std::string::rfind */
    size_t find_last_of(const wchar_t* find);
    size_t find_not_last_of(const wchar_t* find);

    /**
     * @brief
     * @param size_t pos [in] current position
     * @param size_t* brk [out] next line position
     * @param wide_string& line [out] temporary
     * @example
     *        size_t pos = 0;
     *        size_t brk = 0;
     *        while (1)
     *        {
     *          ret = stream.getline(pos, &brk, line);
     *          if (errorcode_t::success != ret)
     *            break;
     *          printf(L"%s\n", line.c_str());
     *          pos = brk;
     *        }
     */
    return_t getline(size_t pos, size_t* brk, wide_string& line);

    wide_string& operator=(const char* buf);
    wide_string& operator=(const wchar_t* buf);
    wide_string& operator=(wchar_t buf);
    wide_string& operator=(byte_t buf);
    wide_string& operator=(uint16 buf);
    wide_string& operator=(uint32 buf);
    wide_string& operator=(uint64 buf);
    wide_string& operator=(float buf);
    wide_string& operator=(double buf);
    wide_string& operator=(const wide_string& buf);
    wide_string& operator=(wide_string&& buf);

    wide_string& operator+=(const char* buf);
    wide_string& operator+=(const wchar_t* buf);
    wide_string& operator+=(wchar_t buf);
    wide_string& operator+=(byte_t buf);
    wide_string& operator+=(uint16 buf);
    wide_string& operator+=(uint32 buf);
    wide_string& operator+=(uint64 buf);
    wide_string& operator+=(float buf);
    wide_string& operator+=(double buf);
    wide_string& operator+=(const wide_string& buf);

    wide_string& operator<<(const char* buf);
    wide_string& operator<<(const wchar_t* buf);
    wide_string& operator<<(wchar_t buf);
    wide_string& operator<<(byte_t buf);
    wide_string& operator<<(uint16 buf);
    wide_string& operator<<(uint32 buf);
    wide_string& operator<<(uint64 buf);
    wide_string& operator<<(float buf);
    wide_string& operator<<(double buf);
    wide_string& operator<<(const wide_string& buf);

#if defined __SIZEOF_INT128__
    wide_string& operator=(uint128 buf);
    wide_string& operator+=(uint128 buf);
    wide_string& operator<<(uint128 buf);
#endif

    int compare(const wide_string& buf);
    static int compare(const wide_string& lhs, const wide_string& rhs);

    bool operator<(const wide_string& buf) const;
    bool operator>(const wide_string& buf) const;

    bool operator==(const wide_string& buf) const;
    bool operator!=(const wide_string& buf) const;

    bool operator==(const wchar_t* input);
    bool operator!=(const wchar_t* input);

    friend std::wstring& operator+=(std::wstring& lhs, const wide_string& rhs);
    friend std::wstring& operator<<(std::wstring& lhs, const wide_string& rhs);
    friend std::ostream& operator<<(std::ostream& lhs, const wide_string& rhs);

    virtual void autoindent(uint8 indent);

   protected:
   private:
    bufferio _bio;
    bufferio_context_t* _handle;
};
#endif

return_t W2A(ansi_string& target, const wchar_t* source, uint32 codepage = 0);
#if defined _WIN32 || defined _WIN64
return_t A2W(wide_string& target, const char* source, uint32 codepage = 0);
#endif

#if defined _WIN32 || defined _WIN64
return_t A2W(stream_t* stream, const char* source, uint32 codepage = 0);

return_t W2A(stream_t* stream, const wchar_t* source, uint32 codepage = 0);
#endif

}  // namespace hotplace

#endif
