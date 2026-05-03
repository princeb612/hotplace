/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   file_stream.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>
#include <hotplace/sdk/io/string/string.hpp>

namespace hotplace {
namespace io {

file_stream::file_stream()
    : _stream_type(stream_type_t::file),
      _file_handle(INVALID_HANDLE_VALUE),
      _mode(0),
      _access(0),
      _share(0),
      _create(0),
      _filemap_handle(nullptr),
      _file_data(nullptr),
      _filesize_low(0),
      _filesize_high(0),
      _flags(0) {}

file_stream::file_stream(const char* filename, uint32 mode)
    : _stream_type(stream_type_t::file),
      _file_handle(INVALID_HANDLE_VALUE),
      _mode(0),
      _access(0),
      _share(0),
      _create(0),
      _filemap_handle(nullptr),
      _file_data(nullptr),
      _filesize_low(0),
      _filesize_high(0),
      _flags(0) {
    if (filename) {
        open(filename, mode);
    }
}

file_stream::~file_stream() { close(); }

return_t file_stream::open(const char* file_name, uint32 flag) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == file_name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::wstring wfilename;
        wfilename = A2W(file_name);
        ret = open(wfilename.c_str(), flag);
    }
    __finally2 {}
    return ret;
}

return_t file_stream::open(const wchar_t* file_name, uint32 flag) {
    return_t ret = errorcode_t::success;

    // int ret_stat = 0;

    __try2 {
        close();

        if (nullptr == file_name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 access = GENERIC_READ;    // 0x80000000L
        uint32 share = FILE_SHARE_READ;  // 0x00000001
        uint32 create = OPEN_EXISTING;   // 3
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

        _file_handle = CreateFileW(file_name, access, share, nullptr, create, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (INVALID_HANDLE_VALUE == _file_handle) {
            if (filestream_flag_t::flag_create_if_not_exist & flag) {
                create = OPEN_ALWAYS;
                retry = 1;
            }
            if (OPEN_ALWAYS == (OPEN_ALWAYS & create)) {
                retry = 1;
            }
            if (0 != retry) {
                _file_handle = CreateFileW(file_name, access, share, nullptr, create, FILE_ATTRIBUTE_NORMAL, nullptr);
            }
        }

        if (INVALID_HANDLE_VALUE == _file_handle) {
            ret = GetLastError();
            __leave2;
        }

        if (filestream_flag_t::flag_create_always & flag) {
            truncate(0);
        }

        memset(&_win32_ov, 0, sizeof(_win32_ov));
        if (filestream_flag_t::flag_exclusive_flock == (flag & filestream_flag_t::flag_exclusive_flock)) {
            LockFileEx(_file_handle, LOCKFILE_EXCLUSIVE_LOCK, 0, 0xFFFFFFFF, 0xFFFFFFFF, &_win32_ov);
        } else if (filestream_flag_t::flag_share_flock == (flag & filestream_flag_t::flag_share_flock)) {
        }

        BY_HANDLE_FILE_INFORMATION fi;
        GetFileInformationByHandle(_file_handle, &fi);

        _create = create;
        _access = access;
        _share = share;
        _flags = flag;
        _filesize_low = fi.nFileSizeLow;
        _filesize_high = fi.nFileSizeHigh;
    }
    __finally2 {}
    return ret;
}

bool file_stream::is_open() { return (INVALID_HANDLE_VALUE != _file_handle) ? true : false; }

return_t file_stream::close() {
    return_t ret = errorcode_t::success;

    if (true == is_open()) {
        end_mmap();

        if (_flags & filestream_flag_t::flag_exclusive_flock) {
            UnlockFileEx(_file_handle, 0, 0xFFFFFFFF, 0xFFFFFFFF, &_win32_ov);
        }
        CloseHandle(_file_handle);

        _file_handle = INVALID_HANDLE_VALUE;
        _mode = 0;
        _access = 0;
        _share = 0;
        _create = 0;
        _filemap_handle = nullptr;
        _file_data = nullptr;
        _filesize_low = 0;
        _filesize_high = 0;
        _flags = 0;
    }
    return ret;
}

bool file_stream::is_mmapped() { return nullptr != _filemap_handle && nullptr != _file_data; }

return_t file_stream::begin_mmap() {
    return_t ret = errorcode_t::success;

    __try2 {
        if (false == is_open()) {
            ret = errorcode_t::not_open;
            __leave2;
        }
        if (true == is_mmapped()) {
            __leave2;
        }

        uint32 protect = PAGE_READONLY;
        uint32 access = FILE_MAP_READ;

        if (GENERIC_WRITE == (_access & GENERIC_WRITE)) {
            protect = PAGE_READWRITE;
            access |= FILE_MAP_WRITE;
        }

        BY_HANDLE_FILE_INFORMATION fi;
        GetFileInformationByHandle(_file_handle, &fi);

        LARGE_INTEGER li;
        li.LowPart = fi.nFileSizeLow;
        li.HighPart = fi.nFileSizeHigh;

        _filemap_handle = CreateFileMapping(_file_handle, nullptr, protect, li.HighPart, li.LowPart, nullptr);
        if (nullptr == _filemap_handle) {
            ret = GetLastError();
        } else {
            _file_data = (byte_t*)MapViewOfFile(_filemap_handle, access, 0, 0, 0);
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            end_mmap();
        }
    }
    return ret;
}

return_t file_stream::end_mmap() {
    return_t ret = errorcode_t::success;

    if (nullptr != _filemap_handle) {
        if (nullptr != _file_data) {
            UnmapViewOfFile(_file_data);
        }
        CloseHandle(_filemap_handle);
        _filemap_handle = nullptr;
        _file_data = nullptr;
    }
    return ret;
}

int file_stream::get_stream_type() { return _stream_type; }

byte_t* file_stream::data() const { return _file_data; }

uint64 file_stream::size() const {
    LARGE_INTEGER li = {};

    if (INVALID_HANDLE_VALUE != _file_handle) {
        BY_HANDLE_FILE_INFORMATION fi;
        GetFileInformationByHandle(_file_handle, &fi);

        li.LowPart = fi.nFileSizeLow;
        li.HighPart = fi.nFileSizeHigh;
    }
    return li.QuadPart;
}

void file_stream::truncate(size_t lfilepos) {
    if (true == is_open()) {
        LARGE_INTEGER li;
        li.QuadPart = lfilepos;

        SetFilePointer(_file_handle, li.LowPart, (PLONG)&li.HighPart, SEEK_SET);
        SetEndOfFile(_file_handle);

        BY_HANDLE_FILE_INFORMATION fi;
        GetFileInformationByHandle(_file_handle, &fi);
        _filesize_low = fi.nFileSizeLow;
        _filesize_high = fi.nFileSizeHigh;
    }
}

void file_stream::seek(int64 lfilepos, uint32 method) {
    if (true == is_open()) {
        LARGE_INTEGER li = {};
        li.QuadPart = lfilepos;

        SetFilePointer(_file_handle, li.LowPart, &li.HighPart, method);
    }
}

return_t file_stream::write(const void* data, size_t size) {
    return_t ret = errorcode_t::success;

    // windows
    // handle = CreateFileMapping ( ..., filesize + tobewritten, ...);
    // fileptr = MapViewOfFile(handle)
    // memcpy (fileptr + filesize, data, tobewritten);

    // linux .. not work

    byte_t* mem = (byte_t*)data;
    size_t idx = 0;
    DWORD written = 0;
    while (size) {
        BOOL test = WriteFile(_file_handle, mem + idx, t_justdoit(size), &written, nullptr);
        if (FALSE == test) {
            ret = GetLastError();
            break;
        }
        size -= written;
        idx += written;
    }
    return ret;
}

return_t file_stream::fill(size_t l, char c) {
    return_t ret = errorcode_t::success;
    basic_stream stream;

    stream.fill(l, c);
    ret = write(stream.data(), stream.size());
    return ret;
}

return_t file_stream::read(void* data, size_t size, size_t* size_read) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == data || 0 == size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DWORD cbread = 0;
        int rc = ReadFile(_file_handle, data, (DWORD)size, &cbread, nullptr);
        if (-1 == rc) {
            ret = GetLastError();
            __leave2;
        }
        if (nullptr != size_read) {
            *size_read = cbread;
        }
    }
    __finally2 {}
    return ret;
}

return_t file_stream::clear() { return errorcode_t::success; }

bool file_stream::empty() { return 0 == size(); }

bool file_stream::occupied() { return 0 != size(); }

return_t file_stream::flush() {
    if (is_mmapped()) {
        FlushViewOfFile(_file_handle, 0);
    } else {
        FlushFileBuffers(_file_handle);
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

file_stream::operator void*() { return _file_handle; }

return_t file_stream::printf(const char* fmt, ...) {
    return_t ret = errorcode_t::success;
    bufferio io;
    bufferio_context_t* handle = nullptr;
    void* data = nullptr;
    size_t data_size = 0;
    va_list ap;

    __try2 {
        va_start(ap, fmt);
        ret = io.open(&handle);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.vprintf(handle, fmt, ap);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.get(handle, (byte_t**)&data, &data_size, 0);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        va_end(ap);

        write(data, data_size);
    }
    __finally2 { io.close(handle); }

    return ret;
}

return_t file_stream::vprintf(const char* fmt, va_list ap) {
    return_t ret = errorcode_t::success;
    bufferio io;
    bufferio_context_t* handle = nullptr;
    void* data = nullptr;
    size_t data_size = 0;

    __try2 {
        ret = io.open(&handle);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.vprintf(handle, fmt, ap);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = io.get(handle, (byte_t**)&data, &data_size, 0);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        write(data, data_size);
    }
    __finally2 { io.close(handle); }

    return ret;
}

void file_stream::autoindent(uint8 indent) {}

}  // namespace io
}  // namespace hotplace
