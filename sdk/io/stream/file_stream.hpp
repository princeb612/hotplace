/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_STREAM_FILESTREAM__
#define __HOTPLACE_SDK_IO_STREAM_FILESTREAM__

#include <stdarg.h>
#include <stdio.h>

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#if defined __linux__
#include <sys/file.h>  // flock
#include <sys/mman.h>  // mmap
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace hotplace {
namespace io {

/**
 * @brief filestream
 * @example
 *          file_stream fs;
 *          ret = fs.open ("filename", filestream_flag_t::open_write);
 *          if (errorcode_t::success == ret) {
 *              fs.seek (0, nullptr, FILE_END); // append
 *              fs.printf ("test");
 *              fs.close ();
 *          }
 */
class file_stream : public stream_t {
   public:
    /**
     * @brief constructor
     * @param
     * @return
     * @remarks
     * @sa
     */
    file_stream();
    /**
     * @brief constructor
     * @param const char* filename [in]
     * @param uint32 mode [in] see FILESTREAM_OPEN_FLAG
     */
    file_stream(const char* filename, uint32 mode = filestream_flag_t::open_existing);

    /**
     * @brief destructor
     * @param
     * @return
     * @remarks
     * @sa
     */
    virtual ~file_stream();

    /**
     * @brief getter
     * @return
     *          STREAM_TYPE_MEMORY  메모리
     *          STREAM_TYPE_FILE    파일
     * @remarks
     * @sa
     */
    int get_stream_type();

    /**
     * @brief data
     * @return
     * @remarks
     * @sa
     */
    virtual byte_t* data();
    /**
     * @brief size
     * @return
     * @remarks
     * @sa
     */
    virtual uint64 size();

    /**
     * @brief
     * @return
     * @remarks
     * @sa
     */
    bool is_open();
    /**
     * @brief open
     * @param   LPCTSTR filename    [IN] filename
     * @param   uint32 mode         [IN] see filestream_flag_t
     * @return error code (see error.hpp)
     * @remarks
     * @sa
     */
    return_t open(const char* filename, uint32 mode = filestream_flag_t::open_existing);
#if defined _WIN32 || defined _WIN64
    return_t open(const wchar_t* filename, uint32 mode = filestream_flag_t::open_existing);
#endif
    /**
     * @brief
     * @return error code (see error.hpp)
     * @remarks
     * @sa
     */
    return_t close();
    /**
     * @brief
     * @param
     * @return
     * @remarks
     * @sa
     */
    virtual return_t clear();
    /**
     * @brief
     * @param
     * @return
     * @remarks
     * @sa
     */
    virtual return_t flush();
    /**
     * @brief
     * @param
     * @return
     * @remarks
     * @sa
     */
    bool is_mmapped();
    /**
     * @brief mmap, filemap
     * @param
     * @return
     * @remarks
     * @sa
     */
    return_t begin_mmap(size_t additional_mapping_size = 0);
    /**
     * @brief munmap
     * @param
     * @return
     * @remarks
     * @sa
     */
    return_t end_mmap();
    /**
     * @brief truncate
     * @param
     * @return
     * @remarks
     * @sa
     */
    void truncate(int64 file_pos = 0, int64* ptr_file_pos = nullptr);
    /**
     * @brief seek
     * @param   int64     file_pos      [IN]  position
     * @param   int64*    ptr_file_pos  [OUT] position
     * @param   uint32    method        [IN]
     *                                      FILE_BEGIN
     *                                      FILE_CURRENT
     *                                      FILE_END
     * @return
     * @remarks
     *          replacement
     *          void Seek(LONG lPosLo, PLONG plPosLo, PLONG plPosHi, uint32 method);
     * @sa
     */
    void seek(int64 file_pos, int64* ptr_file_pos, uint32 method);
    /**
     * @brief printf
     * @param   LPCTSTR     fmt        [IN]
     * @return
     * @remarks
     * @sa
     */
    virtual return_t printf(const char* fmt, ...);

    /**
     * @brief vprintf
     * @param   LPCTSTR     fmt        [IN]
     * @param   va_list     ap         [IN]
     * @return
     * @remarks
     * @sa
     */
    virtual return_t vprintf(const char* fmt, va_list ap);

    /**
     * @brief write
     * @param   void*      data          [IN]
     * @param   size_t     size_data     [IN]
     * @return
     * @remarks
     *          in case of mmaped status, all write operation work up to (4G - 1) bytes
     * @sa
     */
    virtual return_t write(void* data, size_t size_data);
    virtual return_t fill(size_t l, char c);
    /**
     * @brief read
     * @param   void*      data          [IN]
     * @param   uint32     cbBuffer      [IN]
     * @param   uint32*    cbRead        [OUT]
     * @return
     * @remarks
     */
    return_t read(void* data, uint32 buffer, uint32* size_read);

#if 0
    /**
     * @brief
     * @param   FILETIME*   time_created        [OUT]
     * @param   FILETIME*   time_last_accessed  [OUT]
     * @param   FILETIME*   time_last_written   [OUT]
     */
    void get_filetime (FILETIME* time_created, FILETIME* time_last_accessed, FILETIME* time_last_written);
    /**
     * @brief
     * @param   FILETIME*   time_created        [IN]
     * @param   FILETIME*   time_last_accessed  [IN]
     * @param   FILETIME*   time_last_written   [IN]
     */
    void set_filetime (FILETIME* time_created, FILETIME* time_last_accessed, FILETIME* time_last_written);
#endif

    operator handle_t();

   protected:
    int _stream_type;
#if defined __linux__
    int _file_handle;
#elif defined _WIN32 || defined _WIN64
    HANDLE _file_handle;
#endif
    uint32 _mode;
    uint32 _access;
    uint32 _share;
    uint32 _create;
    void* _filemap_handle;
    byte_t* _file_data;
    uint32 _filesize_low;
    uint32 _filesize_high;
    uint32 _filepos_low;
    uint32 _filepos_high;
    size_t _mapping_size;

#if defined _WIN32 || defined _WIN64
    OVERLAPPED _win32_ov;
#endif
    uint32 _flags;
};

}  // namespace io
}  // namespace hotplace

#endif
