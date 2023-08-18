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

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <stdarg.h>
#include <stdio.h>
#if defined __linux__
    #include <sys/mman.h>   // mmap
    #include <sys/file.h>   // flock
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

namespace hotplace {
namespace io {

/**
 * @brief filestream
 * @sample
 *          file_stream fs;
 *          ret = fs.open ("filename", filestream_flag_t::open_write);
 *          if (errorcode_t::success == ret) {
 *              fs.seek (0, nullptr, FILE_END); // append
 *              fs.printf ("test");
 *              fs.close ();
 *          }
 */
class file_stream : public stream_interface
{
public:
    /**
     * @brief constructor
     * @param
     * @return
     * @remarks
     * @sa
     */
    file_stream ();
    /*
     * @brief constructor
     * @param const char* filename [in]
     * @param uint32 mode [in] see FILESTREAM_OPEN_FLAG
     */
    file_stream (const char* filename, uint32 mode = filestream_flag_t::open_existing);

    /**
     * @brief destructor
     * @param
     * @return
     * @remarks
     * @sa
     */
    virtual ~file_stream ();

    /**
     * @brief getter
     * @return
     *          STREAM_TYPE_MEMORY  메모리
     *          STREAM_TYPE_FILE    파일
     * @remarks
     * @sa
     */
    int get_stream_type ();

    /**
     * @brief data
     * @return
     * @remarks
     * @sa
     */
    virtual byte_t* data ();
    /**
     * @brief size
     * @return
     * @remarks
     * @sa
     */
    virtual uint64 size ();

    /**
     * @brief
     * @return
     * @remarks
     * @sa
     */
    bool is_open ();
    /**
     * @brief open
     * @param   LPCTSTR filename    [IN] filename
     * @param   uint32 mode         [IN] see filestream_flag_t
     * @return error code (see error.hpp)
     * @remarks
     * @sa
     */
    return_t open (const char* filename, uint32 mode = filestream_flag_t::open_existing);
    return_t open (const wchar_t* filename, uint32 mode = filestream_flag_t::open_existing);
    /**
     * @brief
     * @return error code (see error.hpp)
     * @remarks
     * @sa
     */
    return_t close ();
    /**
     * @brief
     * @param
     * @return
     * @remarks
     * @sa
     */
    virtual return_t flush ();
    /**
     * @brief
     * @param
     * @return
     * @remarks
     * @sa
     */
    bool is_mmapped ();
    /**
     * @brief mmap, filemap
     * @param
     * @return
     * @remarks
     * @sa
     */
    return_t begin_mmap (size_t dwAdditionalMappingSize = 0);
    /**
     * @brief munmap
     * @param
     * @return
     * @remarks
     * @sa
     */
    return_t end_mmap ();
    /**
     * @brief truncate
     * @param
     * @return
     * @remarks
     * @sa
     */
    void truncate (int64 lFilePos = 0,
                   int64* plFilePos = nullptr);
    /**
     * @brief seek
     * @param   int64     lFilePos    [IN]  position
     * @param   int64*    plFilePos   [OUT] position
     * @param   uint32       dwMethod    [IN]
     *                                      FILE_BEGIN
     *                                      FILE_CURRENT
     *                                      FILE_END
     * @return
     * @remarks
     *          replacement
     *          void Seek(LONG lPosLo, PLONG plPosLo, PLONG plPosHi, uint32 dwMethod);
     * @sa
     */
    void seek (int64 lFilePos, int64* plFilePos, uint32 dwMethod);
    /**
     * @brief printf
     * @param   LPCTSTR     szFormat        [IN]
     * @return
     * @remarks
     * @sa
     */
    virtual return_t printf (const char* szFormat, ...);

    /**
     * @brief vprintf
     * @param   LPCTSTR     szFormat        [IN]
     * @param   va_list     ap              [IN]
     * @return
     * @remarks
     * @sa
     */
    virtual return_t vprintf (const char* szFormat, va_list ap);

    /**
     * @brief write
     * @param   void*      lpData          [IN]
     * @param   size_t      sizeData        [IN]
     * @return
     * @remarks
     *          in case of mmaped status, all write operation work up to (4G - 1) bytes
     * @sa
     */
    virtual return_t write (void* lpData, size_t sizeData);
    virtual return_t fill (size_t l, char c);
    /**
     * @brief read
     * @param   void*      lpData          [IN]
     * @param   uint32       cbBuffer        [IN]
     * @param   uint32*      cbRead          [OUT]
     * @return
     * @remarks
     */
    return_t read (void* lpData, uint32 cbBuffer, uint32* cbRead);

#if 0
    /*
     * @brief
     * @param   FILETIME*   pCreationTime   [OUT]
     * @param   FILETIME*   pLastAccessTime [OUT]
     * @param   FILETIME*   pLastWriteTime  [OUT]
     */
    void get_filetime (FILETIME* pCreationTime, FILETIME* pLastAccessTime, FILETIME* pLastWriteTime);
    /*
     * @brief
     * @param   FILETIME*   pCreationTime   [IN]
     * @param   FILETIME*   pLastAccessTime [IN]
     * @param   FILETIME*   pLastWriteTime  [IN]
     */
    void set_filetime (FILETIME* pCreationTime, FILETIME* pLastAccessTime, FILETIME* pLastWriteTime);
#endif

    operator handle_t ();

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

    /* file lock - 파일을 열 수 있을 때까지 대기 */
#if defined _WIN32 || defined _WIN64
    OVERLAPPED _win32_ov;
#endif
    uint32 _flags;
};

}
}  // namespace

#endif

