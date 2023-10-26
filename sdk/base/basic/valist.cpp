/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/valist.hpp>

namespace hotplace {

valist::valist() : _va_internal(nullptr), _modified(false) {
    // do nothing
}

valist::valist(const valist& object) : _va_internal(nullptr), _modified(false) { assign(object); }

valist::~valist() { clear(); }

valist& valist::assign(const valist& object) {
    _lock.enter();

    _args = object._args;  // copy vector
    _modified = true;

    _lock.leave();
    return *this;
}

valist& valist::assign(std::vector<variant_t> const& args) {
    _lock.enter();

    _args = args;  // copy vector
    _modified = true;

    _lock.leave();
    return *this;
}

valist& valist::operator<<(bool value) {
    variant_t v;

    v.type = TYPE_BOOLEAN;
    v.data.b = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(char value) {
    variant_t v;

    v.type = TYPE_CHAR;
    v.data.c = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(unsigned char value) {
    variant_t v;

    v.type = TYPE_BYTE;
    v.data.uc = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(short value) {
    variant_t v;

    v.type = TYPE_SHORT;
    v.data.i16 = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(unsigned short value) {
    variant_t v;

    v.type = TYPE_USHORT;
    v.data.ui16 = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(int value) {
    variant_t v;

    v.type = TYPE_INT;
    v.data.i32 = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(unsigned int value) {
    variant_t v;

    v.type = TYPE_UINT;
    v.data.i64 = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(long value) {
    variant_t v;

    v.type = TYPE_LONG;
#if defined __linux__
#if __WORDSIZE == 64
    v.data.i64 = value;
#else
    v.data.i32 = value;
#endif
#elif defined _WIN32 || defined _WIN64
    v.data.i32 = value;
#endif
    insert(v);
    return *this;
}

valist& valist::operator<<(unsigned long value) {
    variant_t v;

    v.type = TYPE_LONG;
#if defined __linux__
#if __WORDSIZE == 64
    v.data.ui64 = value;
#else
    v.data.ui32 = value;
#endif
#elif defined _WIN32 || defined _WIN64
    v.data.ui32 = value;
#endif

    insert(v);
    return *this;
}

valist& valist::operator<<(long long value) {
    variant_t v;

    v.type = TYPE_LONGLONG;
    v.data.i64 = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(unsigned long long value) {
    variant_t v;

    v.type = TYPE_ULONGLONG;
    v.data.ui64 = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(float value) {
    variant_t v;

    v.type = TYPE_FLOAT;
    v.data.f = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(double value) {
    variant_t v;

    v.type = TYPE_DOUBLE;
    v.data.d = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(void* value) {
    variant_t v;

    v.type = TYPE_POINTER;
    v.data.p = value;
    insert(v);
    return *this;
}

valist& valist::operator<<(const char* value) {
    variant_t v;

    v.type = TYPE_STRING;
    v.data.str = (char*)value;
    insert(v);
    return *this;
}

valist& valist::operator<<(variant_t const& v) {
    insert(v);
    return *this;
}

valist& valist::operator<<(const valist& object) { return assign(object); }

void valist::clear() {
    _lock.enter();
    _args.clear();
    _modified = true;
    if (nullptr != _va_internal) {
        free(_va_internal);
        _va_internal = nullptr;
    }
    _lock.leave();
}

size_t valist::size() { return _args.size(); }

return_t valist::at(size_t index, variant_t& v) {
    return_t ret = errorcode_t::success;

    _lock.enter();
    if (index < size()) {
        v = _args[index];
    } else {
        ret = errorcode_t::out_of_range;
    }
    _lock.leave();
    return ret;
}

va_list& valist::get() {
    _lock.enter();

    // va_list ap;
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

    _lock.leave();

    return _type.ap;
}

#if defined __linux__
#if (defined(__linux__) && defined(__x86_64__))
// AMD64 byte-aligns elements to 8 bytes
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

    __try2 {
        _lock.enter();

        for (args_t::iterator iter1 = _args.begin(); iter1 != _args.end(); iter1++) {
            variant_t vt = *iter1;
            unsigned native_data_size = 0;
            unsigned padded_size = 0;

            switch (vt.type) {
                case TYPE_CHAR:
                case TYPE_BYTE:
                    native_data_size = sizeof(char);
                    break;
                case TYPE_INT16:
                case TYPE_UINT16:
                    native_data_size = sizeof(int16);
                    break;
                case TYPE_INT32:
                case TYPE_UINT32:
                    native_data_size = sizeof(int32);
                    break;
                case TYPE_INT64:
                case TYPE_UINT64:
                    native_data_size = sizeof(int64);
                    break;
                case TYPE_FLOAT:
                    native_data_size = sizeof(float);
                    break;
                case TYPE_DOUBLE:
                    native_data_size = sizeof(double);
                    break;
                case TYPE_POINTER:
                    native_data_size = sizeof(void*);
                    break;
                case TYPE_STRING:
                    native_data_size = sizeof(char*);
                    break;
                case TYPE_JBOOLEAN:
                    native_data_size = sizeof(byte_t);
                    break;
                case TYPE_JBYTE:
                    native_data_size = sizeof(char);
                    break;
                case TYPE_JCHAR:
                    native_data_size = sizeof(uint16);
                    break;
                case TYPE_JSTRING:
                    native_data_size = sizeof(void*);
                    break;
                default:
                    // error handling
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

#if defined __linux__

        int pos = 0;
        for (args_t::iterator iter = _args.begin(); iter != _args.end(); iter++) {
            variant_t vt = *iter;
            unsigned int native_data_size = 0;
            unsigned int padded_size = 0;
            void* native_data = nullptr;
            void* vdata = nullptr;

            switch (vt.type) {
                case TYPE_CHAR:
                case TYPE_BYTE:
                    native_data = &(vt.data.c);
                    native_data_size = sizeof(char);
                    break;
                case TYPE_INT16:
                case TYPE_UINT16:
                    native_data = &(vt.data.i16);
                    native_data_size = sizeof(int16);
                    break;
                case TYPE_INT32:
                case TYPE_UINT32:
                    native_data = &(vt.data.i32);
                    native_data_size = sizeof(int32);
                    break;
                case TYPE_INT64:
                case TYPE_UINT64:
                    native_data = &(vt.data.i64);
                    native_data_size = sizeof(int64);
                    break;
                case TYPE_FLOAT:
                    native_data = &(vt.data.f);
                    native_data_size = sizeof(float);
                    break;
                case TYPE_DOUBLE:
                    native_data = &(vt.data.d);
                    native_data_size = sizeof(double);
                    break;
                case TYPE_POINTER:
                    native_data = &(vt.data.p);
                    native_data_size = sizeof(void*);
                    break;
                case TYPE_STRING:
                    native_data = &(vt.data.p);
                    native_data_size = sizeof(char*);
                    break;
                case TYPE_JBOOLEAN:
                    native_data = &(vt.data.jbool);
                    native_data_size = sizeof(byte_t);
                    break;
                case TYPE_JBYTE:
                    native_data = &(vt.data.jb);
                    native_data_size = sizeof(char);
                    break;
                case TYPE_JCHAR:
                    native_data = &(vt.data.jc);
                    native_data_size = sizeof(uint16);
                    break;
                case TYPE_JSTRING:
                    native_data = &(vt.data.p);
                    native_data_size = sizeof(char*);
                    break;
                default:
                    // error handling
                    continue;
            }

            // if needed, pad the size we will use for the argument in the va_list
            for (padded_size = native_data_size; 0 != padded_size % VLIST_CHUNK_SIZE; padded_size++) {
                ;
            }

            // save a pointer to the beginning of the free space for this argument
            vdata = &(((char*)(arg_list))[pos]);

            // increment the amount of allocated space (to provide the correct offset and size for next time)
            pos += padded_size;

            // set full padded length to 0 and copy the actual data into the location
            memset(vdata, 0, padded_size);
            memcpy(vdata, native_data, native_data_size);
        }

#else

        va_list ap;
        union va_union u;

        u.ptr = arg_list;
        ap = u.ap;

#define va_assign_type_promotion_int(x) int
#define va_assign_type_promotion_double(x) double

        for (args_t::iterator iter = _args.begin(); iter != _args.end(); iter++) {
            variant_t& vt = *iter;

            switch (vt.type) {
                case TYPE_CHAR:
                case TYPE_BYTE:
                    va_assign(ap, va_assign_type_promotion_int(char), vt.data.c);
                    break;
                case TYPE_INT16:
                case TYPE_UINT16:
                    va_assign(ap, va_assign_type_promotion_int(int16), vt.data.i16);
                    break;
                case TYPE_INT32:
                case TYPE_UINT32:
                    va_assign(ap, int32, vt.data.i32);
                    break;
                case TYPE_INT64:
                case TYPE_UINT64:
                    va_assign(ap, int64, vt.data.i64);
                    break;
                case TYPE_FLOAT:
                    va_assign(ap, va_assign_type_promotion_double(float), vt.data.f);
                    break;
                case TYPE_DOUBLE:
                    va_assign(ap, double, vt.data.d);
                    break;
                case TYPE_POINTER:
                    va_assign(ap, void*, vt.data.p);
                    break;
                case TYPE_STRING:
                    va_assign(ap, char*, vt.data.str);
                    break;
                case TYPE_JBOOLEAN:
                    va_assign(ap, va_assign_type_promotion_int(byte_t), vt.data.jbool);
                    break;
                case TYPE_JBYTE:
                    va_assign(ap, va_assign_type_promotion_int(char), vt.data.jb);
                    break;
                case TYPE_JCHAR:
                    va_assign(ap, va_assign_type_promotion_int(uint16), vt.data.jc);
                    break;
                case TYPE_JSTRING:
                    va_assign(ap, void*, vt.data.p);
                    break;
                default:
                    // error handling
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

        _lock.leave();
    }
}

void valist::insert(variant_t const& v) {
    _lock.enter();
    _args.push_back(v);
    _modified = true;
    _lock.leave();
}

}  // namespace hotplace
