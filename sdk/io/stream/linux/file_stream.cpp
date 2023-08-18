/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/stream/buffer_stream.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>
//#include <stdio.h>

namespace hotplace {
namespace io {

file_stream::file_stream ()
    :
    _file_handle (-1),
    _mode (0),
    _access (0),
    _share (0),
    _create (0),
    _filemap_handle (nullptr),
    _file_data (nullptr),
    _filesize_low (0),
    _filesize_high (0),
    _filepos_low (0),
    _filepos_high (0),
    _mapping_size (0),
    _stream_type (stream_type_t::file)
{
    // do nothing
}

file_stream::~file_stream ()
{
    close ();
}

file_stream::file_stream (const char* filename, uint32 mode)
    :
    _file_handle (-1),
    _mode (0),
    _access (0),
    _share (0),
    _create (0),
    _filemap_handle (nullptr),
    _file_data (nullptr),
    _filesize_low (0),
    _filesize_high (0),
    _filepos_low (0),
    _filepos_high (0),
    _mapping_size (0),
    _stream_type (stream_type_t::file)
{
    if (filename) {
        open (filename, mode);
    }
}

return_t file_stream::open (const char* file_name, uint32 flag)
{
    return_t ret = errorcode_t::success;
    int ret_stat = 0;

    __try2
    {
        close ();

        int mode = O_APPEND;
        if (filestream_flag_t::open_write & flag) {
            mode |= O_RDWR;
        } else {
            mode = O_RDONLY;
        }
        if (filestream_flag_t::flag_create_always & flag) {
            mode |= O_CREAT;
        }
        int retry = 0;

        _file_handle = ::open (file_name, mode, 0644);
        if (-1 == _file_handle) {
            if (flag & filestream_flag_t::flag_create_if_not_exist) {
                mode |= O_CREAT;
                retry = 1;
            }
            if (O_CREAT == (O_CREAT & mode)) {
                mode |= (O_CREAT | O_EXCL); /* fails if the file already exists */
                retry = 1;
            }
            if (0 != retry) {
                _file_handle = ::open (file_name, mode, 0644);
                if (-1 == _file_handle) {
                    ret = errno;
                }
            }
            if (errorcode_t::success != ret) {
                __leave2_trace (ret);
            }
        }

        if (filestream_flag_t::flag_create_always & flag) {
            truncate (0, nullptr);
        }

        if (flag & filestream_flag_t::flag_exclusive_flock) {
            flock (_file_handle, LOCK_EX);
        } else if (flag & filestream_flag_t::flag_share_flock) {
            flock (_file_handle, LOCK_SH);
        }

        struct stat sb;
        ret_stat = fstat (_file_handle, &sb);
        if (-1 == ret_stat) {
            ret = errno;
            __leave2;
        }

        _mode = mode;
        _flags = flag;
        _filesize_low = sb.st_size;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

bool file_stream::is_open ()
{
    return (-1 != _file_handle) ? true : false;
}

return_t file_stream::close ()
{
    return_t ret = errorcode_t::success;

    if (true == is_open ()) {
        end_mmap ();

        if (_flags & (filestream_flag_t::flag_exclusive_flock | filestream_flag_t::flag_share_flock)) {
            flock (_file_handle, LOCK_UN);
        }
        ::close (_file_handle);

        _file_handle = -1;
        _mode = 0;
        _access = 0;
        _share = 0;
        _create = 0;
        _filemap_handle = nullptr;
        _file_data = nullptr;
        _filesize_low = 0;
        _filesize_high = 0;
        _filepos_low = 0;
        _filepos_high = 0;
        _mapping_size = 0;
    }
    return ret;
}

bool file_stream::is_mmapped ()
{
    return nullptr != _filemap_handle && nullptr != _file_data;
}

return_t file_stream::begin_mmap (size_t dwAdditionalMappingSize)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (false == is_open ()) {
            ret = errorcode_t::not_open;
            __leave2_trace (ret);
        }
        if (true == is_mmapped ()) {
            __leave2;
        }
        /* dwAdditionalMappingSize do not work at mmap, unlike Windows API CreateFileMapping */
        if (dwAdditionalMappingSize) {
            ret = errorcode_t::not_supported;
            __leave2_trace (ret);
        }

        if (0 == _filesize_low) {
            __leave2;
        }

        int nprot = PROT_READ;
        if (O_RDWR == (_mode & O_RDWR)) {
            nprot |= PROT_WRITE;
        }
        _filemap_handle = mmap (0, _filesize_low + dwAdditionalMappingSize, nprot, MAP_SHARED, _file_handle, 0);
        if (MAP_FAILED == _filemap_handle) {
            ret = errno;
            __leave2_trace (ret);
        }
        _file_data = (byte_t *) _filemap_handle;
        _mapping_size = dwAdditionalMappingSize;
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            end_mmap ();
        }
    }
    return ret;
}

return_t file_stream::end_mmap ()
{
    return_t ret = errorcode_t::success;

    if (nullptr != _filemap_handle) {
        munmap (_filemap_handle, _filesize_low + _mapping_size);
        _filemap_handle = nullptr;
        _file_data = nullptr;
    }
    return ret;
}

int file_stream::get_stream_type ()
{
    return _stream_type;
}

byte_t* file_stream::data ()
{
    return _file_data;
}

uint64 file_stream::size ()
{
    // ~ 4GB
    //return _filesize_low;
    uint64 ret_value = 0;

    if (-1 != _file_handle) {
        struct stat st;
        fstat (_file_handle, &st);
        ret_value = st.st_size;
    }
    return ret_value;
}

void file_stream::truncate (int64 lFilePos, int64* plFilePos)
{
    if (true == is_open ()) {
        //::lseek(_file_handle, lFilePos, SEEK_SET);
        ::ftruncate (_file_handle, lFilePos);
        _filesize_low = lFilePos;
    }
}

void file_stream::seek (int64 lFilePos, int64* plFilePos, uint32 dwMethod)
{
    if (true == is_open ()) {
        LARGE_INTEGER li;
        li.QuadPart = lFilePos;

        if (true == is_mmapped ()) {
            switch (dwMethod) {
                case FILE_BEGIN:
                    _filepos_low = li.LowPart;
                    _filepos_high = li.HighPart;
                    break;
                case FILE_CURRENT:
                    break;
                case FILE_END:
                    _filepos_low = _filesize_low;
                    _filepos_high = _filesize_high;
                    break;
                    if (nullptr != plFilePos) {
                        li.LowPart = _filepos_low;
                        li.HighPart = _filepos_high;
                        *plFilePos = li.QuadPart;
                    }
            }
        } else {
            int ret_lseek = lseek (_file_handle, lFilePos, dwMethod);
            if (nullptr != plFilePos) {
                if (errorcode_t::success == errno) {
                    *plFilePos = ret_lseek;
                } else {
                    *plFilePos = 0;
                }
            }
        }
    }
}

return_t file_stream::write (void* lpData, size_t sizeData)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (true == is_open ()) {
            if (true == is_mmapped ()) {
                if ((_filepos_high > 0) || (((uint32) - 1 - _filepos_low) < sizeData)) {
                    ret = errorcode_t::not_supported;
                } else {
                    memcpy (reinterpret_cast<byte_t*>(lpData) + _filepos_low, lpData, sizeData);
                    uint32 dwSizeMask = ~_filepos_low;
                    if (dwSizeMask < sizeData) {
                        _filepos_high++;
                    }
                    _filepos_low += sizeData;
                }
            } else {
                byte_t* pMem = (byte_t *) lpData;
                uint32 dwIndex = 0;
                int len = 0;
                while (sizeData) {
                    len = ::write (_file_handle, pMem + dwIndex, sizeData);
                    if (-1 == len) {
                        ret = errno;
                        break;
                    }
                    sizeData -= len;
                    dwIndex += len;
                }
            }
        } else {
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t file_stream::fill (size_t l, char c)
{
    return_t ret = errorcode_t::success;
    buffer_stream stream;

    stream.fill (l, c);
    ret = write (stream.data (), stream.size ());
    return ret;
}

return_t file_stream::read (void* lpData, uint32 cbBuffer, uint32* cbRead)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == lpData || 0 == cbBuffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
        if (true == is_mmapped ()) {
            if ((_filepos_high > 0) || (-1 - _filepos_low < cbBuffer)) {
                ret = errorcode_t::not_supported;
            } else {
                memcpy (lpData, _file_data + _filepos_low, cbBuffer);
                if (nullptr != cbRead) {
                    *cbRead = cbBuffer;
                }
                _filepos_low += cbBuffer;
            }
        } else {
            int ret_readfile = ::read (_file_handle, lpData, cbBuffer);
            if (-1 == ret_readfile) {
                ret = errno;
                __leave2;
            }
            if (nullptr != cbRead) {
                *cbRead = ret_readfile;
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t file_stream::flush ()
{
    return errorcode_t::success;
}

#if 0
void file_stream::get_filetime (FILETIME* pCreationTime, FILETIME* pLastAccessTime, FILETIME* pLastWriteTime)
{
}

void file_stream::set_filetime (FILETIME* pCreationTime, FILETIME* pLastAccessTime, FILETIME* pLastWriteTime)
{
}
#endif

file_stream::operator handle_t ()
{
    return reinterpret_cast<handle_t>(_file_handle);
}

return_t file_stream::printf (const char* szFormat, ...)
{
    return_t ret = errorcode_t::success;
    bufferio io;
    bufferio_context_t* handle = nullptr;
    void* pData = nullptr;
    size_t cbData = 0;
    va_list ap;

    __try2
    {
        va_start (ap, szFormat);
        ret = io.open (&handle, (1 << 12));
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.vprintf (handle, szFormat, ap);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.get (handle, (byte_t**) &pData, &cbData, 0);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        va_end (ap);

        write (pData, cbData);
    }
    __finally2
    {
        io.close (handle);

        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

return_t file_stream::vprintf (const char* szFormat, va_list ap)
{
    return_t ret = errorcode_t::success;
    bufferio io;
    bufferio_context_t* handle = nullptr;
    void* pData = nullptr;
    size_t cbData = 0;

    __try2
    {
        ret = io.open (&handle, (1 << 12));
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.vprintf (handle, szFormat, ap);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.get (handle, (byte_t**) &pData, &cbData, 0);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        write (pData, cbData);
    }
    __finally2
    {
        io.close (handle);

        if (errorcode_t::success != ret) {
            // do nothing
        }
    }

    return ret;
}

}
}  // namespace
