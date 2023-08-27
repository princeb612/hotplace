/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/hmac_otp.hpp>
#include <hotplace/sdk/io/system/types.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

#define HOTP_CONTEXT_SIGNATURE 0x20170701

typedef struct _hotp_context_t : public otp_context_t {
    uint32 _signature;
    hash_context_t* _hmac_context;
    unsigned int _digit_length;
    uint32 _counter;
    critical_section _lock;
    std::list<uint32> _window;
    unsigned int _window_size;
} hotp_context_t;

hmac_otp::hmac_otp ()
{
    // do nothing
}

hmac_otp::~hmac_otp ()
{
    // do nothing
}

uint32 hmac_otp::open (otp_context_t** handle, unsigned int digit_length, hash_algorithm_t algorithm, const byte_t* key_data, size_t key_size)
{
    uint32 ret = errorcode_t::success;
    hotp_context_t* context = nullptr;
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;

    __try2
    {
        if (nullptr == handle || nullptr == key_data || 0 == key_size) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        ret = hash.open (&hash_handle, algorithm, key_data, key_size);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }

        __try_new_catch (context, new hotp_context_t, ret, __leave2_trace (ret));

        context->_signature = HOTP_CONTEXT_SIGNATURE;
        context->_hmac_context = hash_handle;
        context->_counter = 0;
        context->_window_size = 10;
        if (digit_length > 9) {
            digit_length = 9;               /* internal rule */
        } else if (0 == digit_length) {
            digit_length = 6;
        }
        context->_digit_length = digit_length;

        *handle = context;
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (nullptr != hash_handle) {
                hash.close (hash_handle);
            }
            if (nullptr != context) {
                delete context;
            }
        }
    }

    return ret;
}

uint32 hmac_otp::close (otp_context_t* handle)
{
    uint32 ret = errorcode_t::success;
    hotp_context_t* context = static_cast<hotp_context_t*>(handle);
    openssl_hash hash;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        if (HOTP_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        hash.close (context->_hmac_context);
        delete context;
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

uint32 hmac_otp::set (otp_context_t* handle, uint32 count)
{
    uint32 ret = errorcode_t::success;
    hotp_context_t* context = static_cast<hotp_context_t*>(handle);

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
        if (HOTP_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        context->_counter = count;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

uint32 hmac_otp::get (otp_context_t* handle, uint32& code)
{
    uint32 ret = errorcode_t::success;
    hotp_context_t* context = static_cast<hotp_context_t*>(handle);

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
        if (HOTP_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        get (handle, context->_counter, code);
        context->_counter++;
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

uint32 hmac_otp::get (otp_context_t* handle, uint32 counter, uint32& code)
{
    uint64 c = htonll (counter);
    binary_t input;

    input.resize (sizeof (c));
    memcpy (&input[0], &c, input.size ());
    return get (handle, input, code);
}

uint32 hmac_otp::get (otp_context_t* handle, binary_t counter, uint32& code)
{
    uint32 ret = errorcode_t::success;
    hotp_context_t* context = static_cast<hotp_context_t*>(handle);
    openssl_hash hash;
    byte_t* output_allocated = nullptr;
    size_t output_size = 0;
    int digit[] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 };

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
        if (HOTP_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        /* HS = HMAC(K, C) */

        hash.init (context->_hmac_context);

        ret = hash.update (context->_hmac_context, &counter[0], counter.size ());
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }
        ret = hash.finalize (context->_hmac_context, &output_allocated, &output_size);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }

        /* Sbits = DT(HS) - Dynamic Truncate */
        int offset = output_allocated[output_size - 1] & 0x0f;
        /* Snum = StToNum(Sbits) */
        uint32 value = ((output_allocated[offset] & 0x7f) << 24) |
                       ((output_allocated[offset + 1] & 0xff) << 16) |
                       ((output_allocated[offset + 2] & 0xff) << 8) |
                       ((output_allocated[offset + 3] & 0xff));
        /* D = Snum mo 10^Digit */
        value %= digit[context->_digit_length];
        code = value;
    }
    __finally2
    {
        if (nullptr != output_allocated) {
            hash.free_data (output_allocated);
        }
    }

    return ret;
}

uint32 hmac_otp::verify (otp_context_t* handle, uint32 counter, uint32 code)
{
    uint32 ret = errorcode_t::success;
    hotp_context_t* context = static_cast<hotp_context_t*>(handle);

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
        if (HOTP_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        uint32 result = 0;
        ret = get (handle, counter, result);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }
        if (code != result) {
            ret = errorcode_t::mismatch;
            __leave2_trace (ret);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}  // namespace
