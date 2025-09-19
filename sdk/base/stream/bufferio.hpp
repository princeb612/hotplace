/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_BUFFERIO__
#define __HOTPLACE_SDK_BASE_STREAM_BUFFERIO__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/stream/printf.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <list>

namespace hotplace {

/**
 * bufferio_context_t::flags
 */
enum bufferio_context_flag_t {
    memzero_free = (1 << 0),  // cleanse
};

/**
 * operation flags
 */
enum bufferio_flag_t {
    manual = (1 << 0),   /* extend method flag, don't pushback allocated bufferio_t into bufferio_queue */
    run_once = (1 << 1), /* replace just 1 time */
};

typedef struct _bufferio_t {
    byte_t* base_address;  ///<< base address
    size_t offset;         ///<< offset from base_address (always 0 <= offset <= limit)
    size_t limit;          ///<< limit
} bufferio_t;

typedef std::list<bufferio_t*> bufferin_queue_t;

#define BUFFERIO_CONTEXT_SIGNATURE 0x20080716

struct bufferio_context_t : printf_context_t {
    uint32 signature;
    uint32 block_size;  // block size
    byte_t pad_size;    // pad bytes
    uint32 flags;       // combination of bufferio_context_flag_t

    bufferin_queue_t bufferio_queue;  // in-queue
    critical_section bufferio_lock;   // lock
    size_t bufferio_size;             // data size

    bufferio_context_t() : printf_context_t() {}
};

class bufferio {
   public:
    bufferio();
    ~bufferio();

    /**
     * @brief open
     * @param bufferio_context_t** handle [OUT] handle
     * @param uint32 block_size [INOPT] block size
     * @param byte_t pad_size [INOPT] pad bytes
     * @param uint32 flags [INOPT] see bufferio_context_flag_t
     * @return error code (see error.hpp)
     */
    return_t open(bufferio_context_t** handle, uint32 block_size = (1 << 10), byte_t pad_size = 0, uint32 flags = 0);
    /**
     * @brief close
     * @param bufferio_context_t* handle [IN] handle
     * @return error code (see error.hpp)
     */
    return_t close(bufferio_context_t* handle);

    /**
     * @brief write
     * @param bufferio_context_t* handle [IN] handle
     * @param const void* data [IN] data
     * @param size_t data_size [IN] size
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t write(bufferio_context_t* handle, const void* data, size_t data_size);
    /**
     * @brief printf
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* fmt [IN] printf format
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t printf(bufferio_context_t* handle, const char* fmt, ...);
    /**
     * @brief vprintf
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* fmt [IN] printf format
     * @param va_list ap [IN]
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t vprintf(bufferio_context_t* handle, const char* fmt, va_list ap);
#if defined _WIN32 || defined _WIN64
    /**
     * @brief printf
     * @param bufferio_context_t* handle [IN] handle
     * @param const wchar_t* fmt [IN] printf format
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t printf(bufferio_context_t* handle, const wchar_t* fmt, ...);
    /**
     * @brief vprintf
     * @param bufferio_context_t* handle [IN] handle
     * @param const wchar_t* fmt [IN] printf format
     * @param va_list ap [IN]
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t vprintf(bufferio_context_t* handle, const wchar_t* szFormat, va_list ap);
#endif
    /**
     * @brief clear
     * @param bufferio_context_t* handle [IN] handle
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t clear(bufferio_context_t* handle);
    /**
     * @brief empty
     * @return bool
     */
    bool empty(bufferio_context_t* handle);
    /**
     * @brief occupied
     * @return bool
     * @remarks
     *      negative sentense
     *          if (!bio.empty(handle)) { do something }
     *      positive sentense
     *          if (bio.occupied(handle)) { do something }
     */
    bool occupied(bufferio_context_t* handle);
    /**
     * @brief size only
     * @param bufferio_context_t* handle [IN] handle
     * @param size_t* contents_size [OUT] size
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t size(bufferio_context_t* handle, size_t* contents_size);
    /**
     * @brief data and size
     * @param bufferio_context_t* handle [IN] handle
     * @param void** contents [OUT] data
     * @param size_t* contents_size [OUT] size
     * @param uint32 flag [IN] flag
     * @return error code (see error.hpp)
     */
    return_t get(bufferio_context_t* handle, byte_t** contents, size_t* contents_size, uint32 flag = 0) const;
    /**
     * @brief compare
     * @param bufferio_context_t* handle [IN] handle
     * @param const void* data [IN] data
     * @param size_t data_size [IN] size
     * @return
     */
    bool compare(bufferio_context_t* handle, const void* data, size_t data_size);
    /**
     * @brief cut
     * @param bufferio_context_t* handle [IN] handle
     * @param uint32 begin_pos [IN] pos
     * @param uint32 length [IN] length
     * @return error code (see error.hpp)
     */
    return_t cut(bufferio_context_t* handle, uint32 begin_pos, uint32 length);
    /**
     * @brief insert
     * @param bufferio_context_t* handle [IN] handle
     * @param size_t      begin       [in]
     * @param void*       data        [in]
     * @param size_t      data_size   [in]
     * @return error code (see error.hpp)
     */
    return_t insert(bufferio_context_t* handle, size_t begin, const void* data, size_t data_size);
    /**
     * @brief find_first_of, find_not_first_of
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* find        [IN]
     * @param size_t      offset      [INOPT]
     * @return -1 if error
     * @remarks
     *              size_t find_position  = stream.find_first_of(stream_handle, find_text, 0);
     *              size_t ltrim_position = stream.find_first_of(stream_handle, isspace, 0);
     */
    size_t find_first_of(bufferio_context_t* handle, const char* find, size_t offset = 0);
    size_t find_first_of(bufferio_context_t* handle, int (*func)(int), size_t offset = 0);
#if defined _WIN32 || defined _WIN64
    size_t wfind_first_of(bufferio_context_t* handle, const wchar_t* find, size_t offset = 0);
    size_t wfind_first_of(bufferio_context_t* handle, int (*func)(wint_t), size_t offset = 0);
#endif
    /**
     * @brief find_first_of, find_not_first_of
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* find        [IN]
     * @param size_t      offset      [INOPT]
     * @return -1 if error
     * @remarks
     *      bio.printf (handle, "hello world");
     *      pos = bio.find_not_first_of (handle, "hello"); // 5
     */
    size_t find_not_first_of(bufferio_context_t* handle, const char* find, size_t offset = 0);
    size_t find_not_first_of(bufferio_context_t* handle, int (*func)(int), size_t offset = 0);
#if defined _WIN32 || defined _WIN64
    size_t wfind_not_first_of(bufferio_context_t* handle, const wchar_t* find, size_t offset = 0);
    size_t wfind_not_first_of(bufferio_context_t* handle, int (*func)(wint_t), size_t offset = 0);
#endif
    /**
     * @brief find_last_of, find_not_last_of
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* find        [IN]
     * @param size_t      offset      [INOPT]
     * @remarks
     *              size_t find_position  = stream.find_last_of(stream_handle, find_text, 0);
     *              size_t rtrim_position = stream.find_last_of(stream_handle, isspace, 0);
     */
    size_t find_last_of(bufferio_context_t* handle, const char* find);
    size_t find_last_of(bufferio_context_t* handle, int (*func)(int));
#if defined _WIN32 || defined _WIN64
    size_t wfind_last_of(bufferio_context_t* handle, const wchar_t* find);
    size_t wfind_last_of(bufferio_context_t* handle, int (*func)(wint_t));
#endif
    /**
     * @brief find_last_of, find_not_last_of
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* find        [IN]
     * @param size_t      offset      [INOPT]
     */
    size_t find_not_last_of(bufferio_context_t* handle, const char* find);
    size_t find_not_last_of(bufferio_context_t* handle, int (*func)(int));
#if defined _WIN32 || defined _WIN64
    size_t wfind_not_last_of(bufferio_context_t* handle, const wchar_t* find);
    size_t wfind_not_last_of(bufferio_context_t* handle, int (*func)(wint_t));
#endif

    /**
     * @brief replace
     * @param const wchar_t* from [in]
     * @param const wchar_t* to [in]
     * @param size_t begin [inopt]
     * @param int flag [inopt] replace a 1st case
     */
    return_t replace(bufferio_context_t* handle, const char* from, const char* to, size_t begin = 0, int flag = 0);
#if defined _WIN32 || defined _WIN64
    return_t wreplace(bufferio_context_t* handle, const wchar_t* from, const wchar_t* to, size_t begin = 0, int flag = 0);
#endif

    /**
     * @brief lock
     */
    return_t lock(bufferio_context_t* handle);
    /**
     * @brief unlock
     */
    return_t unlock(bufferio_context_t* handle);
    /**
     * @brief auto indent (text mode)
     */
    void autoindent(bufferio_context_t* handle, uint8 indent);

    /**
     * @brief in-class static const integral initializer
     * enum { npos = -1; }; // MSVC 6.0
     */
    // static const size_t npos = (size_t) - 1;

   protected:
    /**
     * @brief extend
     * @param bufferio_context_t* handle [IN] handle
     * @param size_t        alloc_size          [IN] allcation size
     * @param bufferio_t**  allocated_pointer   [OUT] allocated block
     * @param uint32        flag                [IN] see bufferio_flag_t
     * @return
     * @remarks
     */
    return_t extend(bufferio_context_t* handle, size_t alloc_size, bufferio_t** allocated_pointer, uint32 flag = 0) const;

    /**
     * @brief find
     * @param bufferio_context_t* handle [IN] handle
     * @param mode [in] 1 find_first_of, 0 find_not_first_of
     * @param const char* find [in]
     */
    size_t find_first_of_routine(bufferio_context_t* handle, int mode, const char* find, size_t offset = 0);
    size_t find_first_of_routine(bufferio_context_t* handle, int mode, int (*func)(int), size_t offset = 0);
#if defined _WIN32 || defined _WIN64
    size_t wfind_first_of_routine(bufferio_context_t* handle, int mode, const wchar_t* find, size_t offset = 0);
    size_t wfind_first_of_routine(bufferio_context_t* handle, int mode, int (*func)(wint_t), size_t offset = 0);
#endif
    /**
     * @brief find
     * @param bufferio_context_t* handle [IN] handle
     * @param mode [in] 1 find_last_of, 0 find_not_last_of
     * @param const char* find [in]
     */
    size_t find_last_of_routine(bufferio_context_t* handle, int mode, const char* find);
    size_t find_last_of_routine(bufferio_context_t* handle, int mode, int (*func)(int));
#if defined _WIN32 || defined _WIN64
    size_t wfind_last_of_routine(bufferio_context_t* handle, int mode, const wchar_t* find);
    size_t wfind_last_of_routine(bufferio_context_t* handle, int mode, int (*func)(wint_t));
#endif
};

}  // namespace hotplace

#endif
