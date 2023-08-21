/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_STRING_VALIST__
#define __HOTPLACE_SDK_IO_STRING_VALIST__

#include <hotplace/sdk/base.hpp>
#include <vector>

namespace hotplace {
namespace io {

typedef struct _GCC_VA_LIST64 {
    unsigned int gp_offset;
    unsigned int fp_offset;
    void* overflow_arg_area;
    void* reg_save_area;
} GCC_VA_LIST64[1];

typedef struct VA_LIST {
    /*
     * @brief va_list to va_list
     *
     * 1. operator =
     *    cf. gcc do not work
     *    e.g. union { va_list ap; void* ptr; } u; u.ptr = ptr; va_list ap = u.ap;
     * 2. treat a pointer
     *    cf. msc do not work
     *    e.g. union { va_list ap; void* ptr; } u; u.ptr = ptr; va_list ap; *ap = *u.ap;
     * 3. va_copy
     *    cf. The va_start(), va_arg(), and va_end() macros conform to C89.  C99 defines the va_copy() macro.
     *    e.g. union { va_list ap; void* ptr; } u; u.ptr = ptr; va_list ap; va_copy(ap, u.ap);
     */
    union {
        va_list ap;             /* va_list type */
        void* va_ptr;           /* linux, windows */

#if defined __linux__
    #if __WORDSIZE == 64
        GCC_VA_LIST64 gcc_va_list64;             /* gcc 64bits */
    #endif
#endif
    };
} VA_LIST;

//#define GET_VA_LIST(vl) (vl).ap

/*
 * @brief create va_list dynamically
 *        original idea from http://stackoverflow.com/questions/11695237/creating-va-list-dynamically-in-gcc-can-it-be-done
 * @remarks
 *          tested in gcc x86/x86_64, msvc x86/x86_64
 * @sample
 *          valist va;
 *          va << 42 << "hello\n";
 *          vprintf("format string %d %s", va.data()));
 *          va.clear();
 *          va << 43 << "welcome\n";
 *          vprintf("format string %d %s", va.data()));
 */
class valist
{
public:
    valist ();
    valist (const valist& object);
    ~valist ();

    /*
     * @brief assign
     * @param const valist& object [in]
     * @return *this
     */
    valist& assign (const valist& object);
    valist& assign (std::vector<variant_t> args);

    valist& operator << (bool value);
    valist& operator << (char value);
    valist& operator << (unsigned char value);
    valist& operator << (short value);
    valist& operator << (unsigned short value);
    valist& operator << (int value);
    valist& operator << (unsigned int value);
    valist& operator << (long value);
    valist& operator << (unsigned long value);
    valist& operator << (long long value);
    valist& operator << (unsigned long long value);
    valist& operator << (float value);
    valist& operator << (double value);
    valist& operator << (void* value);
    valist& operator << (const char* value);
    valist& operator << (variant_t v);
    valist& operator << (const valist& object);
    /*
     * @brief clear
     */
    void clear ();

    /*
     * @brief size
     */
    size_t size ();
    /*
     * @brief at
     * @param size_t index [in]
     * @param variant_t& v [out]
     * @return error code (see error.hpp)
     */
    return_t at (size_t index, variant_t& v);

    /*
     * @brief return va_list
     */
    va_list& get ();

protected:
    /*
     * @brief build va_list
     */
    void build ();
    /*
     * @brief insert
     * @param variant_t& v [in]
     */
    void insert (variant_t& v);

    typedef std::vector<variant_t> args_t;

    VA_LIST _type;
    void* _va_internal;
    bool _modified;

    critical_section _lock;
    args_t _args;
};

}
}  // namespace

#endif
