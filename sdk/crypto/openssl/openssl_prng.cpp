/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/openssl/openssl_prng.hpp>

namespace hotplace {
namespace crypto {

openssl_prng::openssl_prng ()
{
    // do nothing
}

openssl_prng::~openssl_prng ()
{
    // do nothing
}

int32 openssl_prng::rand32 ()
{
    int32 val = 0;

    RAND_bytes ((unsigned char *) &val, sizeof (val));
    return val;
}

int64 openssl_prng::rand64 ()
{
    int64 val = 0;

    RAND_bytes ((unsigned char *) &val, sizeof (val));
    return val;
}

return_t openssl_prng::random (unsigned char* buf, size_t size)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == buf || 0 == size) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        RAND_bytes (buf, size);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t openssl_prng::random (binary_t& buffer, size_t size)
{
    return_t ret = errorcode_t::success;

    buffer.resize (size);
    RAND_bytes (&buffer[0], buffer.size ());
    return ret;
}

return_t openssl_prng::random (uint32& i, uint32 mask)
{
    return_t ret = errorcode_t::success;

    RAND_bytes ((byte_t*) &i, sizeof (i));
    i &= mask;
    return ret;
}

}
}  // namespace
