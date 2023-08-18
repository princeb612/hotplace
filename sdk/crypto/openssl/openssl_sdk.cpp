/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/openssl/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/openssl/openssl_sdk.hpp>
#include <hotplace/sdk/io/string/string.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

void openssl_startup_implementation ()
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_init_ssl (0, nullptr);
    OPENSSL_init_ssl (OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    #ifdef OPENSSL_LOAD_CONF
    OPENSSL_init_crypto (OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CONFIG, nullptr);
    #else
    OPENSSL_init_crypto (OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
    #endif
#else
    SSL_library_init ();
    SSL_load_error_strings ();
    OpenSSL_add_all_algorithms ();
#endif
}

void openssl_cleanup_implementation ()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    //FIPS_mode_set (0); // memory leak

    ERR_remove_state (0); // for each thread - see openssl_thread_end

    SSL_COMP_free_compression_methods ();

    ENGINE_cleanup ();

    CONF_modules_free ();
    CONF_modules_unload (1);

    COMP_zlib_cleanup (); // if built with zlib

    ERR_free_strings ();

    EVP_cleanup ();

    CRYPTO_cleanup_all_ex_data ();
#endif
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L

    #if defined __linux__ || defined __APPLE__
static pthread_mutex_t * openssl_threadsafe = nullptr;
    #elif defined _WIN32 || defined _WIN64
static HANDLE * openssl_threadsafe = nullptr;
    #endif

    #if defined __linux__ || defined __APPLE__
static unsigned long UNREFERENCED (get_thread_id_callback) (){
    return (unsigned long) pthread_self ();
}
    #endif
static void UNREFERENCED (opensslthread_locking_callback) (int mode, int type, const char *file, int line);

/* openssl-0.9.8 thread-safe */
void openssl_thread_setup_implementation (void)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr != openssl_threadsafe) {
            ret = ERROR_ALREADY_INITIALIZED;
            __leave2_trace (ret);
        }

    #if defined __linux__ || defined __APPLE__
        openssl_threadsafe = (pthread_mutex_t *) OPENSSL_malloc (CRYPTO_num_locks () * sizeof (pthread_mutex_t));
    #elif defined _WIN32 || defined _WIN64
        openssl_threadsafe = (HANDLE *) OPENSSL_malloc (CRYPTO_num_locks () * sizeof (HANDLE));
    #endif
        if (nullptr == openssl_threadsafe) {
            ret = ERROR_OUTOFMEMORY;
            __leave2_trace (ret);
        }
        for (int i = 0; i < CRYPTO_num_locks (); i++) {
    #if defined __linux__ || defined __APPLE__
            pthread_mutex_init (&openssl_threadsafe[i], nullptr);
    #elif defined _WIN32 || defined _WIN64
            openssl_threadsafe[i] = CreateMutex (nullptr, FALSE, nullptr);
    #endif
        }

    #if defined __linux__ || defined __APPLE__
        CRYPTO_set_id_callback (get_thread_id_callback);
    #endif
        CRYPTO_set_locking_callback ((void (*)(int, int, const char *, int))opensslthread_locking_callback);
        /* id callback defined */
    }
    __finally2
    {
        // do nothing
    }
}

/* openssl-0.9.8 thread-safe */
void openssl_thread_cleanup_implementation (void)
{
    if (nullptr != openssl_threadsafe) {
        CRYPTO_set_locking_callback (nullptr);
        for (int i = 0; i < CRYPTO_num_locks (); i++) {
    #if defined __linux__ || defined __APPLE__
            pthread_mutex_destroy (&openssl_threadsafe[i]);
    #elif defined _WIN32 || defined _WIN64
            CloseHandle (openssl_threadsafe[i]);
    #endif
        }
        OPENSSL_free (openssl_threadsafe);
        openssl_threadsafe = nullptr;
    }
}

/* openssl-0.9.8 thread-safe */
void opensslthread_locking_callback (int mode, int type, const char *file, int line)
{
    UNREFERENCED_PARAMETER (file);
    UNREFERENCED_PARAMETER (line);

    assert (nullptr != openssl_threadsafe);

    if (mode & CRYPTO_LOCK) {
    #if defined __linux__ || defined __APPLE__
        pthread_mutex_lock (&openssl_threadsafe[type]);
    #elif defined _WIN32 || defined _WIN64
        WaitForSingleObject (openssl_threadsafe[type], INFINITE);
    #endif
    } else {
    #if defined __linux__ || defined __APPLE__
        pthread_mutex_unlock (&openssl_threadsafe[type]);
    #elif defined _WIN32 || defined _WIN64
        ReleaseMutex (openssl_threadsafe[type]);
    #endif
    }
}
#else
/*
 * openssl/crypto.h (1.x)
 * #  define CRYPTO_THREADID_set_numeric(id, val)
 * #  define CRYPTO_THREADID_set_pointer(id, ptr)
 * #  define CRYPTO_THREADID_set_callback(threadid_func)   (0)
 * #  define CRYPTO_THREADID_get_callback()                (nullptr)
 * #  define CRYPTO_THREADID_current(id)
 * #  define CRYPTO_THREADID_cmp(a, b)                     (-1)
 * #  define CRYPTO_THREADID_cpy(dest, src)
 * #  define CRYPTO_THREADID_hash(id)                      (0UL)
 * #  if OPENSSL_API_COMPAT < 0x10000000L
 * #   define CRYPTO_set_id_callback(func)
 * #   define CRYPTO_get_id_callback()                     (nullptr)
 * #   define CRYPTO_thread_id()                           (0UL)
 * #  endif
 */
#endif // #if OPENSSL_VERSION_NUMBER < 0x10100000L

critical_section openssl_lock;
int openssl_refcount = 0;
/* openssl-0.9.8 thread-safe */
critical_section openssl_threadsafe_lock;
int openssl_threadsafe_refcount = 0;

void openssl_startup ()
{
    openssl_lock.enter ();
    if (0 == openssl_refcount) {
        openssl_startup_implementation ();
    }
    openssl_refcount++;
    openssl_lock.leave ();
}

void openssl_cleanup ()
{
    openssl_lock.enter ();
    if (openssl_refcount > 0) {
        openssl_refcount--;
        if (0 == openssl_refcount) {
            openssl_cleanup_implementation ();
        }
    }
    openssl_lock.leave ();
}

void openssl_thread_setup ()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* openssl-0.9.8 thread-safe */
    if (0 == openssl_threadsafe_refcount) {
        openssl_threadsafe_lock.enter ();
        if (0 == openssl_threadsafe_refcount) {
            openssl_thread_setup_implementation ();
        }
        openssl_threadsafe_refcount++;
        openssl_threadsafe_lock.leave ();
    }
#endif
}

void openssl_thread_cleanup ()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* openssl-0.9.8 thread-safe */
    if (openssl_threadsafe_refcount > 0) {
        openssl_threadsafe_lock.enter ();
        if (openssl_threadsafe_refcount > 0) {
            openssl_threadsafe_refcount--;
            if (0 == openssl_threadsafe_refcount) {
                openssl_thread_cleanup_implementation ();
            }
        }
        openssl_threadsafe_lock.leave ();
    }
#endif
}

void openssl_error_string (std::string& str)
{
    unsigned long l = 0;
    char buf[256];

    std::string bio;
    const char *file = nullptr;
    const char *data = nullptr;
    int line = 0;
    int flags = 0;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    while (0 != (l = ERR_get_error_all (&file, &line, nullptr, &data, &flags))) {
#else
    while (0 != (l = ERR_get_error_line_data (&file, &line, &data, &flags))) {
#endif
        bio += "\n";
        ERR_error_string_n (l, buf, sizeof (buf));
        bio += format ("[%s @ %d] %s", file, line, buf);
    }

    str = bio;
}

return_t trace_openssl (return_t openssl_error)
{
    return_t ret = errorcode_t::success;

    std::string msg;

    openssl_error_string (msg);
    __trace (openssl_error, msg.data ());
    return ret;
}

void openssl_thread_end (void)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ERR_remove_state (0);
#endif
}

static uint32 ossl_cooltime = 0;
static uint32 ossl_cooltime_max = 1000;
static uint32 ossl_cooltime_unitsize = 4096;

return_t ossl_set_cooltime (uint32 ms)
{
    return_t ret = errorcode_t::success;

    if (ms < ossl_cooltime_max) {
        ossl_cooltime = ms;
    } else {
        ret = errorcode_t::out_of_range;
    }
    return ret;
}

return_t ossl_set_cooltime_max (uint32 ms)
{
    return_t ret = errorcode_t::success;

    if (0 == ms) {
        ret = errorcode_t::invalid_parameter;
    } else if (ossl_cooltime <= ms) {
        ossl_cooltime_max = ms;
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

uint32 ossl_get_cooltime ()
{
    return ossl_cooltime;
}

return_t ossl_set_unitsize (uint32 size)
{
    return_t ret = errorcode_t::success;

    if (0 == size) {
        ret = errorcode_t::invalid_parameter;
    } else {
        ossl_cooltime_unitsize = (size + 7) & ~7;
    }
    return ret;
}

uint32 ossl_get_unitsize ()
{
    if (ossl_cooltime_unitsize) {
        return ossl_cooltime_unitsize;
    } else {
        return 1; // safe coding
    }
}

return_t nidof_evp_pkey (const EVP_PKEY* pkey, uint32& nid)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        nid = 0;

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        nid = EVP_PKEY_id ((EVP_PKEY *) pkey);
        if (EVP_PKEY_EC == nid) {
            EC_KEY* ec = EVP_PKEY_get1_EC_KEY ((EVP_PKEY*) pkey);
            if (ec) {
                const EC_GROUP* group = EC_KEY_get0_group (ec);
                nid = EC_GROUP_get_curve_name (group);
                //cprintf (1, 33, "nid %d\n", nid);
                EC_KEY_free (ec);
            }
        }
        if (0 == nid) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

bool kindof_ecc (const EVP_PKEY* pkey)
{
    bool test = false;

    if (pkey) {
        int type = EVP_PKEY_id (pkey);
        test = ((EVP_PKEY_EC == type) || (EVP_PKEY_ED25519 == type) || (EVP_PKEY_ED448 == type)
                || (EVP_PKEY_X25519 == type) || (EVP_PKEY_X448 == type));
    }
    return test;
}

crypto_key_t typeof_crypto_key (const EVP_PKEY* pkey)
{
    crypto_key_t kty = CRYPTO_KEY_NONE;
    int type = EVP_PKEY_id ((EVP_PKEY *) pkey);

    switch (type) {
        case EVP_PKEY_HMAC:
            kty = CRYPTO_KEY_HMAC;
            break;
        case EVP_PKEY_RSA:
            kty = CRYPTO_KEY_RSA;
            break;
        case EVP_PKEY_EC:
            kty = CRYPTO_KEY_EC;
            break;
        case EVP_PKEY_X25519:
        case EVP_PKEY_X448:
        case EVP_PKEY_ED25519:
        case EVP_PKEY_ED448:
            kty = CRYPTO_KEY_OKP;
            break;
        default:
            break;
    }
    return kty;
}

return_t is_private_key (const EVP_PKEY* pkey, bool& result)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        result = false;

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        EVP_PKEY* key = (EVP_PKEY*) (pkey);
        int type = EVP_PKEY_id (key);

        if (EVP_PKEY_RSA == type) {
            if (nullptr != RSA_get0_d (EVP_PKEY_get0_RSA (key))) {
                result = true;
            }
        } else if (EVP_PKEY_EC == type) {
            const BIGNUM* bn = EC_KEY_get0_private_key (EVP_PKEY_get0_EC_KEY (key));
            if (nullptr != bn) {
                result = true;
            }
        } else if (EVP_PKEY_HMAC == type) {
            result = true;
        } else {
            ret = errorcode_t::not_supported;
            __leave2;
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
