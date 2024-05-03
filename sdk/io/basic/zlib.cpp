/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 1951 DEFLATE Compressed Data Format Specification version 1.3
 *  RFC 1952 GZIP file format specification version 4.3
 *  RFC 7520 Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
 *      5.9.  Compressed Content
 *          JOSE "zip":"DEF"
 *  RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
 *      3.5 Content Codings
 *          Content-Encoding: gzip
 *          Content-Encoding: compress
 *          Content-Encoding: deflate
 *
 * Revision History
 * Date         Name                Description
 */

#include <zlib.h>

#include <sdk/io/basic/zlib.hpp>

namespace hotplace {
namespace io {

return_t zlib_deflate(zlib_windowbits_t windowbits, const binary_t& input, binary_t& output) {
    return zlib_deflate(windowbits, &input[0], input.size(), output);
}

return_t zlib_inflate(zlib_windowbits_t windowbits, const binary_t& input, binary_t& output) {
    return zlib_inflate(windowbits, &input[0], input.size(), output);
}

return_t zlib_deflate(zlib_windowbits_t windowbits, byte_t const* input, size_t size, binary_t& output) {
    return_t dwRet = errorcode_t::success;

    __try2 {
        if (nullptr == input) {
            dwRet = errorcode_t::invalid_parameter;
            __leave2;
        }

        output.resize(0);

        int ret = Z_OK;
        uint32 cooltime = 0;
        binary_t buffer;
        z_stream defstream = {
            0,
        };
        defstream.zalloc = Z_NULL;
        defstream.zfree = Z_NULL;
        defstream.opaque = Z_NULL;
        defstream.avail_in = size;
        defstream.next_in = (byte_t*)input;

        buffer.resize(1 << 10);

        int wbit = MAX_WBITS;
        switch (windowbits) {
            case zlib_windowbits_t::windowbits_deflate:
                wbit = -MAX_WBITS;
                break;
            case zlib_windowbits_t::windowbits_gzip:
                wbit = MAX_WBITS + 16;
                break;
        }

        deflateInit2(&defstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, wbit, 8, Z_DEFAULT_STRATEGY);
        do {
            defstream.avail_out = buffer.size();
            defstream.next_out = &buffer[0];

            ret = deflate(&defstream, Z_FINISH);

            uint32 size = output.size();
            if (size < defstream.total_out) {
                output.insert(output.end(), &buffer[0], &buffer[0] + defstream.total_out - size);
            }
            // cooltime = zlib_get_cooltime ();
            // if (cooltime) {
            //    msleep (cooltime);
            //}
        } while (Z_OK == ret);
        deflateEnd(&defstream);
    }
    __finally2 {
        // do nothing
    }

    return dwRet;
}

return_t zlib_inflate(zlib_windowbits_t windowbits, byte_t const* input, size_t size, binary_t& output) {
    return_t dwRet = errorcode_t::success;

    __try2 {
        if (nullptr == input) {
            dwRet = errorcode_t::invalid_parameter;
            __leave2;
        }

        output.resize(0);

        int ret = Z_OK;
        uint32 cooltime = 0;
        binary_t buffer;
        z_stream infstream = {
            0,
        };
        infstream.zalloc = Z_NULL;
        infstream.zfree = Z_NULL;
        infstream.opaque = Z_NULL;
        infstream.avail_in = size;
        infstream.next_in = (byte_t*)input;

        buffer.resize(1 << 10);

        int wbit = MAX_WBITS;
        switch (windowbits) {
            case zlib_windowbits_t::windowbits_deflate:
                wbit = -MAX_WBITS;
                break;
            case zlib_windowbits_t::windowbits_gzip:
                wbit = MAX_WBITS + 16;
                break;
        }

        inflateInit2(&infstream, wbit);
        do {
            infstream.avail_out = buffer.size();
            infstream.next_out = &buffer[0];

            ret = inflate(&infstream, Z_NO_FLUSH);

            uint32 size = output.size();
            if (size < infstream.total_out) {
                output.insert(output.end(), &buffer[0], &buffer[0] + infstream.total_out - size);
            }
            // cooltime = zlib_get_cooltime ();
            // if (cooltime) {
            //    msleep (cooltime);
            //}
        } while (Z_OK == ret);
        inflateEnd(&infstream);
    }
    __finally2 {
        // do nothing
    }

    return dwRet;
}

return_t zlib_deflate(zlib_windowbits_t windowbits, const binary_t& input, stream_t* output) {
    return zlib_deflate(windowbits, &input[0], input.size(), output);
}

return_t zlib_inflate(zlib_windowbits_t windowbits, const binary_t& input, stream_t* output) {
    return zlib_inflate(windowbits, &input[0], input.size(), output);
}

return_t zlib_deflate(zlib_windowbits_t windowbits, byte_t const* input, size_t size, stream_t* output) {
    return_t dwRet = errorcode_t::success;

    __try2 {
        if (nullptr == input || nullptr == output) {
            dwRet = errorcode_t::invalid_parameter;
            __leave2;
        }

        output->clear();

        int ret = Z_OK;
        uint32 cooltime = 0;
        binary_t buffer;
        z_stream defstream = {
            0,
        };
        defstream.zalloc = Z_NULL;
        defstream.zfree = Z_NULL;
        defstream.opaque = Z_NULL;
        defstream.avail_in = size;
        defstream.next_in = (byte_t*)input;

        buffer.resize(1 << 10);

        int wbit = MAX_WBITS;
        switch (windowbits) {
            case zlib_windowbits_t::windowbits_deflate:
                wbit = -MAX_WBITS;
                break;
            case zlib_windowbits_t::windowbits_gzip:
                wbit = MAX_WBITS + 16;
                break;
        }

        deflateInit2(&defstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, wbit, 8, Z_DEFAULT_STRATEGY);
        do {
            defstream.avail_out = buffer.size();
            defstream.next_out = &buffer[0];

            ret = deflate(&defstream, Z_FINISH);

            uint32 size = output->size();
            if (size < defstream.total_out) {
                output->write(&buffer[0], defstream.total_out - size);
            }
            // cooltime = zlib_get_cooltime ();
            // if (cooltime) {
            //    msleep (cooltime);
            //}
        } while (Z_OK == ret);
        deflateEnd(&defstream);
    }
    __finally2 {
        // do nothing
    }

    return dwRet;
}

return_t zlib_inflate(zlib_windowbits_t windowbits, byte_t const* input, size_t size, stream_t* output) {
    return_t dwRet = errorcode_t::success;

    __try2 {
        if (nullptr == input || nullptr == output) {
            dwRet = errorcode_t::invalid_parameter;
            __leave2;
        }

        output->clear();

        int ret = Z_OK;
        uint32 cooltime = 0;
        binary_t buffer;
        z_stream infstream = {
            0,
        };
        infstream.zalloc = Z_NULL;
        infstream.zfree = Z_NULL;
        infstream.opaque = Z_NULL;
        infstream.avail_in = size;
        infstream.next_in = (byte_t*)input;

        buffer.resize(1 << 10);

        int wbit = MAX_WBITS;
        switch (windowbits) {
            case zlib_windowbits_t::windowbits_deflate:
                wbit = -MAX_WBITS;
                break;
            case zlib_windowbits_t::windowbits_gzip:
                wbit = MAX_WBITS + 16;
                break;
        }

        inflateInit2(&infstream, wbit);
        do {
            infstream.avail_out = buffer.size();
            infstream.next_out = &buffer[0];

            ret = inflate(&infstream, Z_NO_FLUSH);

            uint32 size = output->size();
            if (size < infstream.total_out) {
                output->write(&buffer[0], infstream.total_out - size);
            }
            // cooltime = zlib_get_cooltime ();
            // if (cooltime) {
            //    msleep (cooltime);
            //}
        } while (Z_OK == ret);
        inflateEnd(&infstream);
    }
    __finally2 {
        // do nothing
    }

    return dwRet;
}

return_t zlib_deflate(zlib_windowbits_t windowbits, stream_t const* input, stream_t* output) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == input || nullptr == output) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = zlib_deflate(windowbits, input->data(), input->size(), output);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t zlib_inflate(zlib_windowbits_t windowbits, stream_t const* input, stream_t* output) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == input || nullptr == output) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = zlib_inflate(windowbits, input->data(), input->size(), output);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

#define CHUNK 16384

int zlib_def(FILE* source, FILE* dest, int level) {
    int ret, flush;
    unsigned have;
    z_stream strm = {
        0,
    };
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit(&strm, level);
    if (ret != Z_OK) {
        return ret;
    }

    /* compress until end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);

        if (ferror(source)) {
            (void)deflateEnd(&strm);
            return Z_ERRNO;
        }
        flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = deflate(&strm, flush); /* no bad return value */
            // assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)deflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);
        // assert(strm.avail_in == 0);     /* all input will be used */

        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    // assert(ret == Z_STREAM_END);        /* stream will be complete */

    /* clean up and return */
    (void)deflateEnd(&strm);
    return Z_OK;
}

int zlib_inf(FILE* source, FILE* dest) {
    int ret = Z_OK;
    unsigned have = 0;
    z_stream strm = {
        0,
    };
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        return ret;
    }

    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)inflateEnd(&strm);
            return Z_ERRNO;
        }
        if (strm.avail_in == 0) {
            break;
        }
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            // assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            switch (ret) {
                case Z_NEED_DICT:
                    ret = Z_DATA_ERROR; /* and fall through */
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                    (void)inflateEnd(&strm);
                    return ret;
            }
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)inflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    (void)inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

}  // namespace io
}  // namespace hotplace
