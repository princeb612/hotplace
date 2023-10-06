/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/buffer_stream.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>

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
                __leave2;
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

return_t file_stream::begin_mmap (size_t additional_mapping_size)
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
        /* additional_mapping_size do not work at mmap, unlike Windows API CreateFileMapping */
        if (additional_mapping_size) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (0 == _filesize_low) {
            __leave2;
        }

        int nprot = PROT_READ;
        if (O_RDWR == (_mode & O_RDWR)) {
            nprot |= PROT_WRITE;
        }
        _filemap_handle = mmap (0, _filesize_low + additional_mapping_size, nprot, MAP_SHARED, _file_handle, 0);
        if (MAP_FAILED == _filemap_handle) {
            ret = errno;
            __leave2;
        }
        _file_data = (byte_t *) _filemap_handle;
        _mapping_size = additional_mapping_size;
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

void file_stream::truncate (int64 file_pos, int64* ptr_file_pos)
{
    if (true == is_open ()) {
        //::lseek(_file_handle, file_pos, SEEK_SET);
        ::ftruncate (_file_handle, file_pos);
        _filesize_low = file_pos;
    }
}

void file_stream::seek (int64 file_pos, int64* ptr_file_pos, uint32 method)
{
    if (true == is_open ()) {
        LARGE_INTEGER li;
        li.QuadPart = file_pos;

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
                    if (nullptr != ptr_file_pos) {
                        li.LowPart = _filepos_low;
                        li.HighPart = _filepos_high;
                        *ptr_file_pos = li.QuadPart;
                    }
            }
        } else {
            int ret_lseek = lseek (_file_handle, file_pos, method);
            if (nullptr != ptr_file_pos) {
                if (errorcode_t::success == errno) {
                    *ptr_file_pos = ret_lseek;
                } else {
                    *ptr_file_pos = 0;
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
                if ((_filepos_high > 0) || (((uint32) - 1 - _filepos_low) < size_data)) {
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
                uint32 dwIndex = 0;
                int len = 0;
                while (size_data) {
                    len = ::write (_file_handle, (byte_t *) data + dwIndex, size_data);
                    if (-1 == len) {
                        ret = errno;
                        break;
                    }
                    size_data -= len;
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

return_t file_stream::read (void* data, uint32 buffer, uint32* size_read)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == data || 0 == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (true == is_mmapped ()) {
            if ((_filepos_high > 0) || (-1 - _filepos_low < buffer)) {
                ret = errorcode_t::not_supported;
            } else {
                memcpy (data, _file_data + _filepos_low, buffer);
                if (nullptr != size_read) {
                    *size_read = buffer;
                }
                _filepos_low += buffer;
            }
        } else {
            int ret_readfile = ::read (_file_handle, data, buffer);
            if (-1 == ret_readfile) {
                ret = errno;
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
    return errorcode_t::success;
}

#if 0
void file_stream::get_filetime (FILETIME* time_created, FILETIME* time_last_accessed, FILETIME* time_last_written)
{
}

void file_stream::set_filetime (FILETIME* time_created, FILETIME* time_last_accessed, FILETIME* time_last_written)
{
}
#endif

file_stream::operator handle_t ()
{
    return reinterpret_cast<handle_t>(_file_handle);
}

return_t file_stream::printf (const char* fmt, ...)
{
    return_t ret = errorcode_t::success;
    bufferio io;
    bufferio_context_t* handle = nullptr;
    byte_t* data = nullptr;
    size_t size_data = 0;
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
        ret = io.get (handle, &data, &size_data, 0);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        va_end (ap);

        write (data, size_data);
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
    size_t size_data = 0;

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
        ret = io.get (handle, (byte_t**) &data, &size_data, 0);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        write (data, size_data);
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
