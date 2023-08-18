/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.15   Soo han, Kim        fix : insert (lock)
                                    fix : find_not_first_of, replace
 *                                  removed : replace1
 */

#ifndef __GRAPE_SDK_IO_STREAM_BINARYSTREAM__
#define __GRAPE_SDK_IO_STREAM_BINARYSTREAM__

#include <hotplace/sdk/base.hpp>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <list>

namespace hotplace {
namespace io {

/**
 * bufferio_context_t::flags
 */
enum bufferio_context_flag_t {
    memzero_free = (1 << 0), // cleanse
};

/**
 * operation flags
 */
enum bufferio_flag_t {
    manual      = (1 << 0), /* extend method flag, don't pushback allocated bufferio_t into bufferio_queue */
    run_once    = (1 << 1), /* replace just 1 time */
};

typedef struct _bufferio_t {
    byte_t* base_address;   ///<< base address
    size_t offset;          ///<< offset from base_address (always 0 <= offset <= limit)
    size_t limit;           ///<< limit
} bufferio_t;

typedef std::list<bufferio_t*> bufferin_queue_t;

#define BUFFERIO_CONTEXT_SIGNATURE 0x20080716

typedef struct _bufferio_context_t {
    uint32 signature;
    uint32 block_size;                  // block size
    byte_t pad_size;                    // pad bytes
    uint32 flags;                       // combination of bufferio_context_flag_t

    bufferin_queue_t bufferio_queue;    // in-queue
    critical_section bufferio_lock;     // lock
    size_t bufferio_size;               // data size
} bufferio_context_t;

class file_stream;
class bufferio
{
public:
    bufferio ();
    ~bufferio ();

    /**
     * @brief open
     * @param bufferio_context_t** handle [OUT] handle
     * @param uint32 block_size [INOPT] block size
     * @param byte_t pad_size [INOPT] pad bytes
     * @param uint32 flags [INOPT] see bufferio_context_flag_t
     * @return error code (see error.hpp)
     */
    return_t open (bufferio_context_t** handle,
                   uint32 block_size = (1 << 10),
                   byte_t pad_size = 0,
                   uint32 flags = 0);
    /**
     * @brief close
     * @param bufferio_context_t* handle [IN] handle
     * @return error code (see error.hpp)
     */
    return_t close (bufferio_context_t* handle);

    /**
     * @brief write
     * @param bufferio_context_t* handle [IN] handle
     * @param const void* data [IN] data
     * @param size_t data_size [IN] size
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t write (bufferio_context_t* handle, const void* data, size_t data_size);

    /**
     * @brief printf
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* fmt [IN] printf format
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t printf (bufferio_context_t* handle, const char* fmt, ...);
    /**
     * @brief vprintf
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* fmt [IN] printf format
     * @param va_list ap [IN]
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t vprintf (bufferio_context_t* handle, const char* fmt, va_list ap);
#if defined _WIN32 || defined _WIN64
    /**
     * @brief printf
     * @param bufferio_context_t* handle [IN] handle
     * @param const wchar_t* fmt [IN] printf format
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t printf (bufferio_context_t* handle, const wchar_t* fmt, ...);
    /**
     * @brief vprintf
     * @param bufferio_context_t* handle [IN] handle
     * @param const wchar_t* fmt [IN] printf format
     * @param va_list ap [IN]
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t vprintf (bufferio_context_t* handle, const wchar_t* szFormat, va_list ap);
#endif
    /**
     * @brief clear
     * @param bufferio_context_t* handle [IN] handle
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t flush (bufferio_context_t* handle);

    /**
     * @brief size only
     * @param bufferio_context_t* handle [IN] handle
     * @param size_t* contents_size [OUT] size
     * @return error code (see error.hpp)
     * @remarks
     */
    return_t size (bufferio_context_t* handle, size_t* contents_size);
    /**
     * @brief data and size
     * @param bufferio_context_t* handle [IN] handle
     * @param void** contents [OUT] data
     * @param size_t* contents_size [OUT] size
     * @param uint32 flag [IN] flag
     * @return error code (see error.hpp)
     */
    return_t get (bufferio_context_t* handle, byte_t** contents, size_t* contents_size, uint32 flag = 0);
    /**
     * @brief compare
     * @param bufferio_context_t* handle [IN] handle
     * @param const void* data [IN] data
     * @param size_t data_size [IN] size
     * @return
     */
    bool compare (bufferio_context_t* handle, const void* data, size_t data_size);
    /**
     * @brief cut
     * @param bufferio_context_t* handle [IN] handle
     * @param uint32 begin_pos [IN] pos
     * @param uint32 length [IN] length
     * @return error code (see error.hpp)
     */
    return_t cut (bufferio_context_t* handle, uint32 begin_pos, uint32 length);
    /*
     * @brief insert
     * @param bufferio_context_t* handle [IN] handle
     * @param size_t      begin       [in]
     * @param void*       data        [in]
     * @param size_t      data_size   [in]
     * @return error code (see error.hpp)
     */
    return_t insert (bufferio_context_t* handle, size_t begin, const void* data, size_t data_size);
    /*
     * @brief find_first_of, find_not_first_of
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* find        [IN]
     * @param size_t      offset      [INOPT]
     * @return -1 if error
     * @remarks
     *              size_t find_position  = stream.find_first_of(stream_handle, find_text, 0);
     *              size_t ltrim_position = stream.find_first_of(stream_handle, isspace, 0);
     */
    size_t find_first_of (bufferio_context_t* handle, const char* find, size_t offset = 0);
    size_t find_first_of (bufferio_context_t* handle, int (*func)(int), size_t offset = 0);
#if defined _WIN32 || defined _WIN64
    size_t wfind_first_of (bufferio_context_t* handle, const wchar_t* find, size_t offset = 0);
    size_t wfind_first_of (bufferio_context_t* handle, int (*func)(wint_t), size_t offset = 0);
#endif
    /*
     * @brief find_first_of, find_not_first_of
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* find        [IN]
     * @param size_t      offset      [INOPT]
     * @return -1 if error
     * @remarks
     *      bio.printf (handle, "hello world");
     *      pos = bio.find_not_first_of (handle, "hello"); // 5
     */
    size_t find_not_first_of (bufferio_context_t* handle, const char* find, size_t offset = 0);
    size_t find_not_first_of (bufferio_context_t* handle, int (*func)(int), size_t offset = 0);
#if defined _WIN32 || defined _WIN64
    size_t wfind_not_first_of (bufferio_context_t* handle, const wchar_t* find, size_t offset = 0);
    size_t wfind_not_first_of (bufferio_context_t* handle, int (*func)(wint_t), size_t offset = 0);
#endif
    /*
     * @brief find_last_of, find_not_last_of
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* find        [IN]
     * @param size_t      offset      [INOPT]
     * @remarks
     *              size_t find_position  = stream.find_last_of(stream_handle, find_text, 0);
     *              size_t rtrim_position = stream.find_last_of(stream_handle, isspace, 0);
     */
    size_t find_last_of (bufferio_context_t* handle, const char* find);
    size_t find_last_of (bufferio_context_t* handle, int (*func)(int));
#if defined _WIN32 || defined _WIN64
    size_t wfind_last_of (bufferio_context_t* handle, const wchar_t* find);
    size_t wfind_last_of (bufferio_context_t* handle, int (*func)(wint_t));
#endif
    /*
     * @brief find_last_of, find_not_last_of
     * @param bufferio_context_t* handle [IN] handle
     * @param const char* find        [IN]
     * @param size_t      offset      [INOPT]
     */
    size_t find_not_last_of (bufferio_context_t* handle, const char* find);
    size_t find_not_last_of (bufferio_context_t* handle, int (*func)(int));
#if defined _WIN32 || defined _WIN64
    size_t wfind_not_last_of (bufferio_context_t* handle, const wchar_t* find);
    size_t wfind_not_last_of (bufferio_context_t* handle, int (*func)(wint_t));
#endif

    /*
     * @brief replace
     * @param const wchar_t* from [in]
     * @param const wchar_t* to [in]
     * @param size_t begin [inopt]
     * @param int flag [inopt] replace a 1st case
     */
    return_t replace (bufferio_context_t* handle, const char* from, const char* to,
                      size_t begin = 0,
                      int flag = 0);
#if defined _WIN32 || defined _WIN64
    return_t wreplace (bufferio_context_t* handle, const wchar_t* from, const wchar_t* to,
                       size_t begin = 0,
                       int flag = 0);
#endif

    /*
     * @brief lock
     */
    return_t lock (bufferio_context_t* handle);
    /*
     * @brief unlock
     */
    return_t unlock (bufferio_context_t* handle);

    /*
     * @brief in-class static const integral initializer
     * enum { npos = -1; }; // MSVC 6.0
     */
    //static const size_t npos = (size_t) - 1;

protected:

    /**
     * @brief operation 중 메모리가 추가로 필요할 때 호출된다.
     * @param bufferio_context_t* handle [IN] handle
     * @param size_t        alloc_size          [IN] 할당할 메모리 크기
     * @param bufferio_t**  allocated_pointer   [OUT] 할당된 메모리 블럭
     * @param uint32        flag                [IN] bufferio_flag_t 참고
     * @return
     * @remarks
     */
    return_t extend (bufferio_context_t* handle, size_t alloc_size, bufferio_t** allocated_pointer, uint32 flag = 0);

    /*
     * @brief find
     * @param bufferio_context_t* handle [IN] handle
     * @param mode [in] 1 find_first_of, 0 find_not_first_of
     * @param const char* find [in]
     */
    size_t find_first_of_routine (bufferio_context_t* handle, int mode, const char* find, size_t offset = 0);
    size_t find_first_of_routine (bufferio_context_t* handle, int mode, int (*func)(int), size_t offset = 0);
#if defined _WIN32 || defined _WIN64
    size_t wfind_first_of_routine (bufferio_context_t* handle, int mode, const wchar_t* find, size_t offset = 0);
    size_t wfind_first_of_routine (bufferio_context_t* handle, int mode, int (*func)(wint_t), size_t offset = 0);
#endif
    /*
     * @brief find
     * @param bufferio_context_t* handle [IN] handle
     * @param mode [in] 1 find_last_of, 0 find_not_last_of
     * @param const char* find [in]
     */
    size_t find_last_of_routine (bufferio_context_t* handle, int mode, const char* find);
    size_t find_last_of_routine (bufferio_context_t* handle, int mode, int (*func)(int));
#if defined _WIN32 || defined _WIN64
    size_t wfind_last_of_routine (bufferio_context_t* handle, int mode, const wchar_t* find);
    size_t wfind_last_of_routine (bufferio_context_t* handle, int mode, int (*func)(wint_t));
#endif
};

class bufferio_pair
{
public:
    bufferio_pair ();

    return_t pairing ();

private:
    bufferio_context_t* _bio_in;
    bufferio_context_t* _bio_out;
};

}
}  // namespace

#endif
