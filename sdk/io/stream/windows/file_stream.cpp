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
#include <hotplace/sdk/io/string/string.hpp>
#include <stdio.h>

namespace hotplace {
namespace io {

file_stream::file_stream ()
    :
    _file_handle (INVALID_HANDLE_VALUE),
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
    _file_handle (INVALID_HANDLE_VALUE),
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

    __try2
    {
        if (nullptr == file_name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::wstring wfilename;
        wfilename = A2W (file_name);
        ret = open (wfilename.c_str (), flag);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t file_stream::open (const wchar_t* file_name, uint32 flag)
{
    return_t ret = errorcode_t::success;

    //int ret_stat = 0;

    __try2
    {
        close ();

        if (nullptr == file_name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int access = GENERIC_READ;
        int share = FILE_SHARE_READ;
        int create = OPEN_EXISTING;
        if (filestream_flag_t::open_write & flag) {
            access |= GENERIC_WRITE;
            share |= FILE_SHARE_WRITE;
        }
        if (filestream_flag_t::flag_create_always & flag) {
            create = CREATE_ALWAYS;
            access |= GENERIC_WRITE;
            share |= FILE_SHARE_WRITE;
        }
        int retry = 0;

        _file_handle = CreateFileW (file_name, access, share, nullptr, create, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (INVALID_HANDLE_VALUE == _file_handle) {
            if (filestream_flag_t::flag_create_if_not_exist & flag) {
                create = OPEN_ALWAYS;
                retry = 1;
            }
            if (OPEN_ALWAYS == (OPEN_ALWAYS & create)) {
                retry = 1;
            }
            if (0 != retry) {
                _file_handle = CreateFileW (file_name, access, share, nullptr, create, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (INVALID_HANDLE_VALUE == _file_handle) {
                    ret = GetLastError ();
                }
            }
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        if (filestream_flag_t::flag_create_always & flag) {
            truncate (0, nullptr);
        }

        memset (&_win32_ov, 0, sizeof (_win32_ov));
        if (filestream_flag_t::flag_exclusive_flock == (flag & filestream_flag_t::flag_exclusive_flock)) {
            LockFileEx (_file_handle, LOCKFILE_EXCLUSIVE_LOCK, 0, 0xFFFFFFFF, 0xFFFFFFFF, &_win32_ov);
        } else if (filestream_flag_t::flag_share_flock == (flag & filestream_flag_t::flag_share_flock)) {
        }

        BY_HANDLE_FILE_INFORMATION fi;
        GetFileInformationByHandle (_file_handle, &fi);

        _flags = flag;
        _filesize_low = fi.nFileSizeLow;
        _filesize_high = fi.nFileSizeHigh;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

bool file_stream::is_open ()
{
    return (INVALID_HANDLE_VALUE != _file_handle) ? true : false;
}

return_t file_stream::close ()
{
    return_t ret = errorcode_t::success;

    if (true == is_open ()) {
        end_mmap ();

        if (_flags & filestream_flag_t::flag_exclusive_flock) {
            UnlockFileEx (_file_handle, 0, 0xFFFFFFFF, 0xFFFFFFFF, &_win32_ov);
        }
        CloseHandle (_file_handle);

        _file_handle = INVALID_HANDLE_VALUE;
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
            __leave2;
        }
        if (true == is_mmapped ()) {
            __leave2;
        }

        uint32 protect = PAGE_READONLY;
        uint32 access = FILE_MAP_READ;

        if (GENERIC_WRITE == (access & GENERIC_WRITE)) {
            protect = PAGE_READWRITE;
            access |= FILE_MAP_WRITE;
        }

        BY_HANDLE_FILE_INFORMATION fi;
        GetFileInformationByHandle (_file_handle, &fi);

        _filesize_low = fi.nFileSizeLow;
        _filesize_high = fi.nFileSizeHigh;

        uint32 filesize_low = _filesize_low;
        //uint32 filesize_high = _filesize_high;

        uint32 sizemask = ~filesize_low;
        if (dwAdditionalMappingSize > sizemask) {
            _filesize_high++;
        }
        _filesize_low += dwAdditionalMappingSize;

        _filemap_handle = CreateFileMapping (_file_handle, nullptr, protect, _filesize_high, (uint32) _filesize_low, nullptr);
        if (nullptr == _filemap_handle) {
            ret = GetLastError ();
            __leave2;
        }
        _file_data = (byte_t *) MapViewOfFile (_filemap_handle, access, 0, 0, 0);
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
        if (nullptr != _file_data) {
            UnmapViewOfFile (_file_data);
        }
        CloseHandle (_filemap_handle);
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
    size_t ret_value = 0;

    if (INVALID_HANDLE_VALUE != _file_handle) {
        BY_HANDLE_FILE_INFORMATION fi;
        GetFileInformationByHandle (_file_handle, &fi);

        _filesize_low = fi.nFileSizeLow;
        _filesize_high = fi.nFileSizeHigh;
    }
    ret_value = _filesize_high;
    ret_value <<= 32;
    ret_value += _filesize_low;
    return ret_value;
}

void file_stream::truncate (int64 lfilepos, int64* ptrfilepos)
{
    UNREFERENCED_PARAMETER (ptrfilepos);
    if (true == is_open ()) {
        SetFilePointer (_file_handle, lfilepos, (PLONG) ptrfilepos, SEEK_SET);
        SetEndOfFile (_file_handle);
        size ();
    }
}

void file_stream::seek (int64 lfilepos, int64* ptrfilepos, uint32 method)
{
    if (true == is_open ()) {
        LARGE_INTEGER li;
        li.QuadPart = lfilepos;

        if (true == is_mmapped ()) {
            switch (method) {
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
                    if (nullptr != ptrfilepos) {
                        li.LowPart = _filepos_low;
                        li.HighPart = _filepos_high;
                        *ptrfilepos = li.QuadPart;
                    }
            }
        } else {
            int ret_lseek = SetFilePointer (_file_handle, li.LowPart, &li.HighPart, method);
            if (nullptr != ptrfilepos) {
                if (errorcode_t::success == GetLastError ()) {
                    *ptrfilepos = ret_lseek;
                } else {
                    *ptrfilepos = 0;
                }
            }
        }
    }
}

return_t file_stream::write (void* data, size_t size_data)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (true == is_open ()) {
            if (true == is_mmapped ()) {
                if ((_filepos_high > 0) || (-1 - _filepos_low < size_data)) {
                    ret = errorcode_t::not_supported;
                } else {
                    memcpy (reinterpret_cast<byte_t*>(data) + _filepos_low, data, size_data);
                    uint32 size_mask = ~_filepos_low;
                    if (size_mask < size_data) {
                        _filepos_high++;
                    }
                    _filepos_low += size_data;
                }
            } else {
                byte_t* mem = (byte_t *) data;
                uint32 idx = 0;
                while (size_data) {
                    DWORD written = 0;
                    BOOL test = WriteFile (_file_handle, mem + idx, size_data, &written, nullptr);
                    if (FALSE == test) {
                        ret = GetLastError ();
                        break;
                    }
                    size_data -= written;
                    idx += written;
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

return_t file_stream::read (void* data, uint32 size_data, uint32* size_read)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == data || 0 == size_data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (true == is_mmapped ()) {
            if ((_filepos_high > 0) || (-1 - _filepos_low < size_data)) {
                ret = errorcode_t::not_supported;
            } else {
                memcpy (data, _file_data + _filepos_low, size_data);
                if (nullptr != size_read) {
                    *size_read = size_data;
                }
                _filepos_low += size_data;
            }
        } else {
            int ret_readfile = ReadFile (_file_handle, data, size_data, (LPDWORD) size_read, nullptr);
            if (-1 == ret_readfile) {
                ret = GetLastError ();
                __leave2;
            }
            if (nullptr != size_read) {
                *size_read = ret_readfile;
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t file_stream::clear ()
{
    return errorcode_t::success;
}

return_t file_stream::flush ()
{
    if (is_mmapped ()) {
        FlushViewOfFile (_file_handle, 0);
    } else {
        FlushFileBuffers (_file_handle);
    }
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

file_stream::operator void* ()
{
    return _file_handle;
}

return_t file_stream::printf (const char* fmt, ...)
{
    return_t ret = errorcode_t::success;
    bufferio io;
    bufferio_context_t* handle = nullptr;
    void* data = nullptr;
    size_t data_size = 0;
    va_list ap;

    __try2
    {
        va_start (ap, fmt);
        ret = io.open (&handle);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.vprintf (handle, fmt, ap);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.get (handle, (byte_t**) &data, &data_size, 0);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        va_end (ap);

        write (data, data_size);
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

return_t file_stream::vprintf (const char* fmt, va_list ap)
{
    return_t ret = errorcode_t::success;
    bufferio io;
    bufferio_context_t* handle = nullptr;
    void* data = nullptr;
    size_t data_size = 0;

    __try2
    {
        ret = io.open (&handle);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.vprintf (handle, fmt, ap);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.get (handle, (byte_t**) &data, &data_size, 0);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        write (data, data_size);
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
