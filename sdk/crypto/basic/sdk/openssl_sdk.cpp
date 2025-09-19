/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

void openssl_startup_implementation() {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_init_ssl(0, nullptr);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
// int legacyValue = OSSL_PROVIDER_available (nullptr, "legacy");
// OSSL_PROVIDER* legacy_provider = OSSL_PROVIDER_try_load (nullptr, "legacy", 1);
// OSSL_PROVIDER* default_provider = OSSL_PROVIDER_try_load (nullptr, "default", 1);
// OSSL_PROVIDER* legacy_provider = OSSL_PROVIDER_load(nullptr, "legacy");
// if (legacy == nullptr) {
// }
#endif

#else
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();
    OpenSSL_add_all_algorithms();
#endif
}

void openssl_cleanup_implementation() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    // FIPS_mode_set (0); // memory leak

    ERR_remove_state(0);  // for each thread - see openssl_thread_end

    SSL_COMP_free_compression_methods();

    ENGINE_cleanup();

    CONF_modules_free();
    CONF_modules_unload(1);

    COMP_zlib_cleanup();  // if built with zlib

    ERR_free_strings();

    EVP_cleanup();

    CRYPTO_cleanup_all_ex_data();
#endif
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#if defined __linux__
static pthread_mutex_t *openssl_threadsafe = nullptr;
#elif defined _WIN32 || defined _WIN64
static HANDLE *openssl_threadsafe = nullptr;
#endif

#if defined __linux__
static unsigned long(get_thread_id_callback)() { return (unsigned long)pthread_self(); }
#endif
static void(opensslthread_locking_callback)(int mode, int type, const char *file, int line);

/* openssl-0.9.8 thread-safe */
void openssl_thread_setup_implementation(void) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr != openssl_threadsafe) {
            __leave2;
        }

#if defined __linux__
        openssl_threadsafe = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
#elif defined _WIN32 || defined _WIN64
        openssl_threadsafe = (HANDLE *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
#endif
        if (nullptr == openssl_threadsafe) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }
        for (int i = 0; i < CRYPTO_num_locks(); i++) {
#if defined __linux__
            pthread_mutex_init(&openssl_threadsafe[i], nullptr);
#elif defined _WIN32 || defined _WIN64
            openssl_threadsafe[i] = CreateMutex(nullptr, FALSE, nullptr);
#endif
        }

#if defined __linux__
        CRYPTO_set_id_callback(get_thread_id_callback);
#endif
        CRYPTO_set_locking_callback((void (*)(int, int, const char *, int))opensslthread_locking_callback);
        /* id callback defined */
    }
    __finally2 {}
}

/* openssl-0.9.8 thread-safe */
void openssl_thread_cleanup_implementation(void) {
    if (nullptr != openssl_threadsafe) {
        CRYPTO_set_locking_callback(nullptr);
        for (int i = 0; i < CRYPTO_num_locks(); i++) {
#if defined __linux__
            pthread_mutex_destroy(&openssl_threadsafe[i]);
#elif defined _WIN32 || defined _WIN64
            CloseHandle(openssl_threadsafe[i]);
#endif
        }
        OPENSSL_free(openssl_threadsafe);
        openssl_threadsafe = nullptr;
    }
}

/* openssl-0.9.8 thread-safe */
void opensslthread_locking_callback(int mode, int type, const char *file, int line) {
    assert(nullptr != openssl_threadsafe);

    if (mode & CRYPTO_LOCK) {
#if defined __linux__
        pthread_mutex_lock(&openssl_threadsafe[type]);
#elif defined _WIN32 || defined _WIN64
        WaitForSingleObject(openssl_threadsafe[type], INFINITE);
#endif
    } else {
#if defined __linux__
        pthread_mutex_unlock(&openssl_threadsafe[type]);
#elif defined _WIN32 || defined _WIN64
        ReleaseMutex(openssl_threadsafe[type]);
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
#endif  // #if OPENSSL_VERSION_NUMBER < 0x10100000L

critical_section openssl_lock;
int openssl_refcount = 0;
/* openssl-0.9.8 thread-safe */
critical_section openssl_threadsafe_lock;
int openssl_threadsafe_refcount = 0;

void openssl_startup() {
    critical_section_guard guard(openssl_lock);
    if (0 == openssl_refcount) {
        openssl_startup_implementation();
    }
    openssl_refcount++;

    openssl_thread_setup();
}

void openssl_cleanup() {
    openssl_thread_cleanup();

    critical_section_guard guard(openssl_lock);
    if (openssl_refcount > 0) {
        openssl_refcount--;
        if (0 == openssl_refcount) {
            openssl_cleanup_implementation();
        }
    }
}

void openssl_thread_setup() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* openssl-0.9.8 thread-safe */
    critical_section_guard guard(openssl_threadsafe_lock);
    if (0 == openssl_threadsafe_refcount) {
        openssl_thread_setup_implementation();
    }
    openssl_threadsafe_refcount++;
#endif
}

void openssl_thread_cleanup() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* openssl-0.9.8 thread-safe */
    critical_section_guard guard(openssl_threadsafe_lock);
    if (openssl_threadsafe_refcount > 0) {
        openssl_threadsafe_refcount--;
        if (0 == openssl_threadsafe_refcount) {
            openssl_thread_cleanup_implementation();
        }
    }
#endif
}

void openssl_thread_end(void) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    ERR_remove_state(0);
#endif
}

return_t read_bio(stream_t *stream, BIO *bio) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream || nullptr == bio) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t buf;
        buf.resize(64);
        int len = 0;
        while (1) {
            len = BIO_read(bio, &buf[0], buf.size());
            if (0 >= len) {
                break;
            }
            stream->write(&buf[0], len);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
