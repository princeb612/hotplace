/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   valist.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2016.02.19   Soo Han, Kim        dynamic_va_list (codename.merlin Revision 3152)
 */

#include <assert.h>

#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>

namespace hotplace {

valist::valist() : _va_internal(nullptr), _modified(false) {}

valist::valist(const valist& object) : _va_internal(nullptr), _modified(false) { assign(object); }

valist::valist(valist&& object) noexcept : _va_internal(nullptr), _modified(false) { *this = std::move(object); }

valist::~valist() { clear(); }

valist& valist::assign(const valist& object) {
    critical_section_guard guard(_lock);

    _args = object._args;  // copy vector
    _modified = true;

    return *this;
}

valist& valist::operator=(const valist& object) { return assign(object); }

valist& valist::operator=(valist&& object) noexcept {
    if (this == &object) {
        return *this;
    }

    critical_section_guard guard(_lock);
    critical_section_guard guard_obj(object._lock);

    clear();

    _args = std::move(object._args);
    _va_internal = object._va_internal;
    _modified = object._modified;

    object._va_internal = nullptr;
    object._modified = false;

    return *this;
}

/* operator<< delegation */
valist& valist::operator<<(bool value) { return append(value); }
valist& valist::operator<<(char value) { return append(value); }
valist& valist::operator<<(unsigned char value) { return append(value); }
valist& valist::operator<<(short value) {
#if defined __linux__
    return append((int32)value);
#elif defined _WIN32 || defined _WIN64
    return append(value);
#endif
}
valist& valist::operator<<(unsigned short value) { return append(value); }

valist& valist::operator<<(int value) {
    // sign-extension overflow problem (for example -2147483648 as -340282366920938463463374607429620727808)
    // PASS - TYPE_INT64, i64 = -2147483648 (p = 0xffffffff80000000)
    // FAIL - TYPE_INT32, i32 = -2147483648 (p = 0x80000000)
    if (-2147483648 == value)
        return append((int64)value);
    else
        return append((int32)value);
}

valist& valist::operator<<(unsigned int value) { return append((uint32)value); }

valist& valist::operator<<(long value) {
#if defined __linux__
#if __WORDSIZE == 64
    return append((int64)value);
#else
    return append((int32)value);
#endif
#elif defined _WIN32 || defined _WIN64
    return append((int32)value);
#endif
}

valist& valist::operator<<(unsigned long value) {
#if defined __linux__
#if __WORDSIZE == 64
    return append((uint64)value);
#else
    return append((uint32)value);
#endif
#elif defined _WIN32 || defined _WIN64
    return append((uint32)value);
#endif
}

valist& valist::operator<<(long long value) { return append((int64)value); }

valist& valist::operator<<(unsigned long long value) { return append((uint64)value); }

valist& valist::operator<<(float value) {
    /* default argument promotions
     * ¡®float¡¯ is promoted to ¡®double¡¯ when passed through ¡®...¡¯
     */
    return append((double)value);
}

valist& valist::operator<<(double value) { return append(value); }

valist& valist::operator<<(void* value) { return append(value); }

valist& valist::operator<<(const char* value) {
    if (nullptr == value) {
        return *this;
    }
    return append(value);
}

valist& valist::operator<<(const std::string& value) { return *this << value.c_str(); }

valist& valist::operator<<(const basic_stream& value) { return *this << value.c_str(); }

valist& valist::operator<<(const binary_t& value) { return append(value); }

valist& valist::operator<<(const variant_t& v) {
    insert(v);
    return *this;
}

valist& valist::operator<<(variant_t&& v) {
    insert(std::move(v));
    return *this;
}

void valist::clear() {
    critical_section_guard guard(_lock);

    _args.clear();
    _modified = true;
    if (nullptr != _va_internal) {
        free(_va_internal);
        _va_internal = nullptr;
    }
}

size_t valist::size() const {
    critical_section_guard guard(_lock);
    return _args.size();
}

return_t valist::at(size_t index, variant_t& v) const {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);

    if (index < size()) {
        v = _args[index];
    } else {
        ret = errorcode_t::out_of_range;
    }
    return ret;
}

variant_t& valist::operator[](size_t index) {
    critical_section_guard guard(_lock);

    if (index < size()) {
        return _args[index];
    } else {
        throw exception(errorcode_t::out_of_range);
    }
}

va_list& valist::get() {
    critical_section_guard guard(_lock);

    if (true == _modified || nullptr == _va_internal) {
        build();
        _modified = false;
    }

#if defined __linux__
#if __WORDSIZE == 64
    /*
     * #if (defined(__linux__) && defined(__x86_64__))
     *
     * va_args will read from the overflow area if the gp_offset is greater than or equal to
     * 48 (6 gp registers * 8 bits/register)
     * and the fp_offset is greater than or equal to
     * 304 (gp_offset + 16 fp register * 16 bits/register)
     */
    _type.gcc_va_list64[0].gp_offset = 48;
    _type.gcc_va_list64[0].fp_offset = 304;
    _type.gcc_va_list64[0].reg_save_area = nullptr;
    _type.gcc_va_list64[0].overflow_arg_area = _va_internal; /* arg here !*/
#else
    _type.va_ptr = _va_internal;
#endif
#else
    /*
     * va_list ap;
     * 1. ap = args->ap;
     * 2. *ap = *args->ap;
     * 3. va_copy(ap, args->ap);
     */
    _type.va_ptr = _va_internal;
#endif

    return _type.ap;
}

#if defined __linux__
#if (defined(__linux__) && defined(__x86_64__))
#define VLIST_CHUNK_SIZE 8
#else
#define VLIST_CHUNK_SIZE 4
#endif
#else
#define VLIST_CHUNK_SIZE sizeof(arch_t)
#endif

union va_union {
    va_list ap;
    void* ptr;
};

#define va_assign(lvalp, type, rval) \
    {                                \
        *((type*)lvalp) = rval;      \
        va_arg(lvalp, type);         \
    }

void valist::build() {
    int arg_list_size = 0;
    void* arg_list = nullptr;
    critical_section_guard guard(_lock);

    __try2 {
        for (const auto& vt : _args) {
            unsigned native_data_size = 0;
            unsigned padded_size = 0;

            switch (vt.type) {
                case vartype_t::TYPE_CHAR:
                case vartype_t::TYPE_BYTE:
                case vartype_t::TYPE_INT8:
                case vartype_t::TYPE_UINT8:
                    native_data_size = sizeof(char);
                    break;
                case vartype_t::TYPE_INT16:
                case vartype_t::TYPE_UINT16:
                    native_data_size = sizeof(int16);
                    break;
                case vartype_t::TYPE_INT32:
                case vartype_t::TYPE_UINT32:
                    native_data_size = sizeof(int32);
                    break;
                case vartype_t::TYPE_INT64:
                case vartype_t::TYPE_UINT64:
                    native_data_size = sizeof(int64);
                    break;
                case vartype_t::TYPE_FLOAT:
                case vartype_t::TYPE_DOUBLE:
                    native_data_size = sizeof(double);
                    break;
                case vartype_t::TYPE_POINTER:
                    native_data_size = sizeof(void*);
                    break;
                case vartype_t::TYPE_STRING:
                    native_data_size = sizeof(char*);
                    break;
                case vartype_t::TYPE_JBOOLEAN:
                    native_data_size = sizeof(byte_t);
                    break;
                case vartype_t::TYPE_JBYTE:
                    native_data_size = sizeof(char);
                    break;
                case vartype_t::TYPE_JCHAR:
                    native_data_size = sizeof(uint16);
                    break;
                case vartype_t::TYPE_JSTRING:
                    native_data_size = sizeof(void*);
                    break;
                default:
                    continue;
            }
            // if needed, pad the size we will use for the argument in the va_list
            for (padded_size = native_data_size; 0 != padded_size % VLIST_CHUNK_SIZE; padded_size++) {
                ;
            }

            // increment the amount of allocated space (to provide the correct offset and size for next time)
            arg_list_size += padded_size;
        }

        arg_list = (char*)malloc(arg_list_size);
        if (nullptr == arg_list) {
            __leave2;
        }

        /**
         * va_arg
         *                      linux   windows
         *  type promotion        O        O
         *  compiler warning      -        O
         */
#if defined __linux__
        // clang-format off
        #define va_assign_type_promotion_int(x) { int32 temp = x; native_data = &temp; native_data_size = sizeof(int32); }
        #define va_assign_type_promotion_uint(x) { uint32 temp = x; native_data = &temp; native_data_size = sizeof(uint32); }
        #define va_assign_type_promotion_double(x) { double temp = x; native_data = &temp; native_data_size = sizeof(double); }
        // clang-format on

        int pos = 0;
        for (const auto& vt : _args) {
            unsigned int native_data_size = 0;
            unsigned int padded_size = 0;
            const void* native_data = nullptr;
            void* vdata = nullptr;

            switch (vt.type) {
                case vartype_t::TYPE_BOOL:
                    native_data = &(vt.data.b);
                    native_data_size = sizeof(bool);
                    break;
                case vartype_t::TYPE_CHAR:
                case vartype_t::TYPE_INT8:
                    native_data = &(vt.data.c);
                    native_data_size = sizeof(char);
                    break;
                case vartype_t::TYPE_BYTE:
                case vartype_t::TYPE_UINT8:
                    native_data = &(vt.data.uc);
                    native_data_size = sizeof(uint8);
                    break;
                case vartype_t::TYPE_INT16:
                    native_data = &(vt.data.i16);
                    native_data_size = sizeof(int16);
                    break;
                case vartype_t::TYPE_UINT16:
                    native_data = &(vt.data.ui16);
                    native_data_size = sizeof(uint16);
                    break;
                case vartype_t::TYPE_INT32:
                    native_data = &(vt.data.i32);
                    native_data_size = sizeof(int32);
                    break;
                case vartype_t::TYPE_UINT32:
                    native_data = &(vt.data.ui32);
                    native_data_size = sizeof(uint32);
                    break;
                case vartype_t::TYPE_INT64:
                    native_data = &(vt.data.i64);
                    native_data_size = sizeof(int64);
                    break;
                case vartype_t::TYPE_UINT64:
                    native_data = &(vt.data.ui64);
                    native_data_size = sizeof(uint64);
                    break;
                case vartype_t::TYPE_FLOAT:
                case vartype_t::TYPE_DOUBLE:
                    native_data = &(vt.data.d);
                    native_data_size = sizeof(double);
                    break;
                case vartype_t::TYPE_POINTER:
                    native_data = &(vt.data.p);
                    native_data_size = sizeof(void*);
                    break;
                case vartype_t::TYPE_STRING:
                    native_data = &(vt.data.p);
                    native_data_size = sizeof(char*);
                    break;
                case vartype_t::TYPE_JBOOLEAN:
                    native_data = &(vt.data.jbool);
                    native_data_size = sizeof(byte_t);
                    break;
                case vartype_t::TYPE_JBYTE:
                    native_data = &(vt.data.jb);
                    native_data_size = sizeof(char);
                    break;
                case vartype_t::TYPE_JCHAR:
                    native_data = &(vt.data.jc);
                    native_data_size = sizeof(uint16);
                    break;
                case vartype_t::TYPE_JSTRING:
                    native_data = &(vt.data.p);
                    native_data_size = sizeof(char*);
                    break;
                default:
                    continue;
            }

            // if needed, pad the size we will use for the argument in the va_list
            for (padded_size = native_data_size; 0 != padded_size % VLIST_CHUNK_SIZE; padded_size++) {
                ;
            }

            // save a pointer to the beginning of the free space for this argument
            vdata = &(((char*)(arg_list))[pos]);

#if defined DEBUG
            uintptr_t addr = reinterpret_cast<uintptr_t>(vdata);
            assert((addr % VLIST_CHUNK_SIZE) == 0);  // misaligned
#endif

            // increment the amount of allocated space (to provide the correct offset and size for next time)
            pos += padded_size;

            // set full padded length to 0 and copy the actual data into the location
            memset(vdata, 0, padded_size);
            memcpy(vdata, native_data, native_data_size);
        }

#else

        // MSVC CRT
        // - va_assign
        // - va_assign_type_promotion_int
        // verification
        // - Application Verifier
        // - MSVC C++ Sanitizer(/fsanitize=address)

        va_list ap;
        union va_union u;

        u.ptr = arg_list;
        ap = u.ap;

        /* avoid compiler warning */
#define va_assign_type_promotion_int(x) int
#define va_assign_type_promotion_uint(x) uint
#define va_assign_type_promotion_double(x) double

        for (const auto& vt : _args) {
            switch (vt.type) {
                case vartype_t::TYPE_BOOL:
                    va_assign(ap, va_assign_type_promotion_int(bool), vt.data.b);
                    break;
                case vartype_t::TYPE_CHAR:
                case vartype_t::TYPE_INT8:
                    va_assign(ap, va_assign_type_promotion_int(char), vt.data.c);
                    break;
                case vartype_t::TYPE_BYTE:
                case vartype_t::TYPE_UINT8:
                    va_assign(ap, va_assign_type_promotion_uint(char), vt.data.ui8);
                    break;
                case vartype_t::TYPE_INT16:
                    va_assign(ap, va_assign_type_promotion_int(int16), vt.data.i16);
                    break;
                case vartype_t::TYPE_UINT16:
                    va_assign(ap, va_assign_type_promotion_uint(int16), vt.data.ui16);
                    break;
                case vartype_t::TYPE_INT32:
                    va_assign(ap, int32, vt.data.ui32);
                    break;
                case vartype_t::TYPE_UINT32:
                    va_assign(ap, uint32, vt.data.ui32);
                    break;
                case vartype_t::TYPE_INT64:
                    va_assign(ap, int64, vt.data.i64);
                    break;
                case vartype_t::TYPE_UINT64:
                    va_assign(ap, uint64, vt.data.ui64);
                    break;
                case vartype_t::TYPE_FLOAT:
                    va_assign(ap, va_assign_type_promotion_double(float), vt.data.f);
                    break;
                case vartype_t::TYPE_DOUBLE:
                    va_assign(ap, double, vt.data.d);
                    break;
                case vartype_t::TYPE_POINTER:
                    va_assign(ap, void*, vt.data.p);
                    break;
                case vartype_t::TYPE_STRING:
                    va_assign(ap, char*, vt.data.str);
                    break;
                case vartype_t::TYPE_JBOOLEAN:
                    va_assign(ap, va_assign_type_promotion_int(byte_t), vt.data.jbool);
                    break;
                case vartype_t::TYPE_JBYTE:
                    va_assign(ap, va_assign_type_promotion_int(char), vt.data.jb);
                    break;
                case vartype_t::TYPE_JCHAR:
                    va_assign(ap, va_assign_type_promotion_int(uint16), vt.data.jc);
                    break;
                case vartype_t::TYPE_JSTRING:
                    va_assign(ap, void*, vt.data.p);
                    break;
                default:
                    continue;
            }
        }

#endif
    }
    __finally2 {
        /* replace */
        if (_va_internal) {
            free(_va_internal);
        }

        _va_internal = arg_list;
    }
}

void valist::insert(const variant_t& v) {
    critical_section_guard guard(_lock);

    _args.push_back(v);
    _modified = true;
}

void valist::insert(variant_t&& v) {
    critical_section_guard guard(_lock);

    _args.push_back(std::move(v));
    _modified = true;
}

}  // namespace hotplace
