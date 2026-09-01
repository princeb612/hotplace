/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   valist.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2016.02.19   Soo Han, Kim        dynamic_va_list (codename.merlin Revision 3152)
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_VALIST__
#define __HOTPLACE_SDK_BASE_BASIC_VALIST__

#include <stdarg.h>

#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/stream/types.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <utility>
#include <vector>

namespace hotplace {

typedef struct _valist_gcc_x64_t {
    unsigned int gp_offset;
    unsigned int fp_offset;
    void* overflow_arg_area;
    void* reg_save_area;
} valist_gcc_x64_t[1];

typedef struct _valist_t {
    union {
        va_list ap;   /* va_list type */
        void* va_ptr; /* linux, windows */

#if defined __linux__
#if __WORDSIZE == 64
        valist_gcc_x64_t gcc_va_list64; /* gcc 64bits */
#endif
#endif
    };
} valist_t;

/**
 * @brief create va_list dynamically
 *        original idea from http://stackoverflow.com/questions/11695237/creating-va-list-dynamically-in-gcc-can-it-be-done
 * @remarks
 *          tested in gcc x86/x86_64, msvc x86/x86_64
 * @example
 *          valist va;
 *          va << 42 << "hello\n";
 *          vprintf("format string %d %s", va.get ()));
 *          va.clear();
 *          va << 43 << "welcome\n";
 *          vprintf("format string %d %s", va.get ()));
 * @sa
 *          function  sprintf
 *          prototype return_t sprintf (stream_t* stream, const char* fmt, valist va);
 *          snippet
 *              valist va;
 *              basic_stream bs;
 *              va << 1 << 3.141592 << "hello"; // make_valist (va, 1, 3.141592, "hello");
 *              sprintf (&bs, "value1={2} value2={1} value3={3}", va);
 *
 *          function  vprintf
 *          prototype template<class ... Args> return_t vprintf (stream_t* stream, const char* fmt, Args... args) // c++14
 *          snippet
 *              valist va;
 *              basic_stream bs;
 *              vprintf (&bs, "param1 {1} param2 {2} param3 {3}\n", 1, 3.141592, "hello");
 *
 */
class valist {
   public:
    valist();
    valist(const valist& object);
    valist(valist&& object) noexcept;
    ~valist();

    valist& assign(const valist& object);
    valist& assign(const std::vector<variant_t>& args);

    valist& operator=(const valist& object);
    valist& operator=(valist&& object) noexcept;

    /* primitive & pointer types */
    valist& operator<<(bool value);
    valist& operator<<(char value);
    valist& operator<<(unsigned char value);
    valist& operator<<(short value);
    valist& operator<<(unsigned short value);
    valist& operator<<(int value);
    valist& operator<<(unsigned int value);
    valist& operator<<(long value);
    valist& operator<<(unsigned long value);
    valist& operator<<(long long value);
    valist& operator<<(unsigned long long value);
    valist& operator<<(float value);
    valist& operator<<(double value);
    valist& operator<<(void* value);
    valist& operator<<(const char* value);
    valist& operator<<(const std::string& value);
    valist& operator<<(const basic_stream& value);
    valist& operator<<(const binary_t& value);
    valist& operator<<(const variant_t& v);
    valist& operator<<(variant_t&& v);
    /**
     * @brief clear
     */
    void clear();

    /**
     * @brief size
     */
    size_t size() const;
    /**
     * @brief at
     * @param size_t index [in]
     * @param variant_t& v [out]
     * @return error code (see error.hpp)
     */
    return_t at(size_t index, variant_t& v) const;
    variant_t& operator[](size_t index);

    /**
     * @brief return va_list
     */
    va_list& get();

   protected:
    /**
     * @brief build va_list
     */
    void build();
    /**
     * @brief insert
     * @param variant_t& v [in]
     */
    void insert(const variant_t& v);
    void insert(variant_t&& v);

   private:
    template <typename T>
    valist& append(T&& value) {
        variant v(std::forward<T>(value));
        insert(std::move(v.get()));
        return *this;
    }

    typedef std::vector<variant_t> args_t;

    valist_t _type;
    void* _va_internal;
    bool _modified;

    mutable critical_section _lock;
    args_t _args;
};

}  // namespace hotplace

#endif
