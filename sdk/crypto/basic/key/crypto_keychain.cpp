/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <fstream>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/io/stream/file_stream.hpp>

namespace hotplace {
namespace crypto {

crypto_keychain::crypto_keychain() {
    // do nothing
}

crypto_keychain::~crypto_keychain() {
    // do nothing
}

return_t crypto_keychain::load(crypto_key* cryptokey, keyflag_t mode, const char* buffer, size_t size, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        switch (mode) {
            case key_pemfile:
                ret = load_pem(cryptokey, buffer, size, desc, flags);
                break;
            case key_certfile:
                ret = load_cert(cryptokey, buffer, size, desc, flags);
                break;
            case key_derfile:
                ret = load_der(cryptokey, (byte_t*)buffer, size, desc, flags);
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::load_pem(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    /**
     * RFC 7468 Textual Encodings of PKIX, PKCS, and CMS Structures
     */
    BIO* bio_pub = nullptr;
    BIO* bio_priv = nullptr;

    __try2 {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bio_pub = BIO_new(BIO_s_mem());
        bio_priv = BIO_new(BIO_s_mem());
        if (nullptr == bio_pub || nullptr == bio_priv) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIO_write(bio_pub, buffer, size);
        BIO_write(bio_priv, buffer, size);

        while (1) {
            EVP_PKEY* pkey_pub = nullptr;
            pkey_pub = PEM_read_bio_PUBKEY(bio_pub, nullptr, nullptr, nullptr);
            if (pkey_pub) {
                crypto_key_object key(pkey_pub, desc);
                cryptokey->add(key);
            } else {
                break;
            }
        }

        while (1) {
            EVP_PKEY* pkey_priv = nullptr;
            pkey_priv = PEM_read_bio_PrivateKey(bio_priv, nullptr, nullptr, nullptr);
            if (pkey_priv) {
                crypto_key_object key(pkey_priv, desc);
                cryptokey->add(key);
            } else {
                break;
            }
        }
        ERR_clear_error();
    }
    __finally2 {
        if (bio_pub) {
            BIO_free_all(bio_pub);
        }
        if (bio_priv) {
            BIO_free_all(bio_priv);
        }
    }
    return ret;
}

return_t crypto_keychain::load_cert(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    X509* cert = nullptr;
    BIO* bio = nullptr;
    EVP_PKEY* pkey = nullptr;
    __try2 {
        if (nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bio = BIO_new(BIO_s_mem());
        if (nullptr == bio) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIO_write(bio, buffer, size);
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (nullptr == cert) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        pkey = X509_get_pubkey(cert);
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        crypto_key_object key(pkey, desc);
        cryptokey->add(key);

        ERR_clear_error();
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
        if (bio) {
            BIO_free(bio);
        }
        if (cert) {
            X509_free(cert);
        }
    }
    return ret;
}

return_t crypto_keychain::load_der(crypto_key* cryptokey, const byte_t* buffer, size_t size, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    X509* x509 = nullptr;
    BIO* bio = nullptr;
    EVP_PKEY* pkey = nullptr;
    __try2 {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bio = BIO_new(BIO_s_mem());
        if (nullptr == bio) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIO_write(bio, buffer, size);
        const byte_t* p = buffer;
        // The letters i and d in i2d_TYPE() stand for "internal" (that is, an internal C structure) and "DER" respectively.
        // So i2d_TYPE() converts from internal to DER. d2i_ vice versa
        pkey = d2i_PrivateKey_bio(bio, nullptr);
        if (nullptr == pkey) {
            x509 = d2i_X509(nullptr, &p, size);
            pkey = X509_get_pubkey(x509);
        }
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        crypto_key_object key(pkey, desc);
        cryptokey->add(key);

        ERR_clear_error();
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
        if (bio) {
            BIO_free(bio);
        }
        if (x509) {
            X509_free(x509);
        }
    }
    return ret;
}

return_t crypto_keychain::write(crypto_key* cryptokey, keyflag_t mode, stream_t* stream, int flag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        switch (mode) {
            case key_pemfile:
                ret = write_pem(cryptokey, stream, flag);
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::write_pem(crypto_key* cryptokey, stream_t* stream, int flag) {
    return_t ret = errorcode_t::success;
    BIO* out = nullptr;

    __try2 {
        if (nullptr == cryptokey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        stream->clear();

        out = BIO_new(BIO_s_mem());
        if (nullptr == out) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        auto lambda = [](crypto_key_object* key, void* param) -> void { dump_pem(key->get_pkey(), (BIO*)param); };

        cryptokey->for_each(lambda, (void*)out);

        binary_t buf;
        buf.resize(64);
        int len = 0;
        while (1) {
            len = BIO_read(out, &buf[0], buf.size());
            if (0 >= len) {
                break;
            }
            stream->write(&buf[0], len);
        }
    }
    __finally2 {
        if (out) {
            BIO_free_all(out);
        }
    }
    return ret;
}

return_t crypto_keychain::load_file(crypto_key* cryptokey, keyflag_t mode, const char* filename, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == filename) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        file_stream fs;
        ret = fs.open(filename);
        if (errorcode_t::success == ret) {
            fs.begin_mmap();
            ret = load(cryptokey, mode, (char*)fs.data(), fs.size(), desc, flags);
            fs.close();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::write_file(crypto_key* cryptokey, keyflag_t mode, const char* filename, int flag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == filename) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        basic_stream bs;
        ret = write(cryptokey, mode, &bs, flag);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        std::ofstream file(filename, std::ios::trunc);
        file.write(bs.c_str(), bs.size());
        file.close();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
