/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <fstream>
#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>

namespace hotplace {
namespace crypto {

crypto_keychain::crypto_keychain() {}

crypto_keychain::~crypto_keychain() {}

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
    __finally2 {}
    return ret;
}

return_t crypto_keychain::load_pem(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    /**
     * RFC 7468 Textual Encodings of PKIX, PKCS, and CMS Structures
     */

    __try2 {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        BIO_CHAIN_ptr bio_pub(BIO_new(BIO_s_mem()));
        BIO_CHAIN_ptr bio_priv(BIO_new(BIO_s_mem()));
        if (nullptr == bio_pub.get() || nullptr == bio_priv.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIO_write(bio_pub.get(), buffer, size);
        BIO_write(bio_priv.get(), buffer, size);

        while (1) {
            EVP_PKEY_ptr pkey_pub(PEM_read_bio_PUBKEY(bio_pub.get(), nullptr, nullptr, nullptr));
            if (pkey_pub.get()) {
                crypto_key_object key(pkey_pub.get(), desc);
                auto test = cryptokey->add(key);
                if (errorcode_t::success == test) {
                    pkey_pub.release();  // cryptokey own pkey_pub
                }
            } else {
                break;
            }
        }

        while (1) {
            EVP_PKEY_ptr pkey_priv(PEM_read_bio_PrivateKey(bio_priv.get(), nullptr, nullptr, nullptr));
            if (pkey_priv.get()) {
                crypto_key_object key(pkey_priv.get(), desc);
                auto test = cryptokey->add(key);
                if (errorcode_t::success == test) {
                    pkey_priv.release();  // cryptokey own pkey_priv
                }
            } else {
                break;
            }
        }
        ERR_clear_error();
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::load_cert(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        BIO_ptr bio(BIO_new(BIO_s_mem()));
        if (nullptr == bio.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIO_write(bio.get(), buffer, size);
        X509_ptr cert(PEM_read_bio_X509(bio.get(), NULL, NULL, NULL));
        if (nullptr == cert.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_ptr pkey(X509_get_pubkey(cert.get()));
        if (nullptr == pkey.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        crypto_key_object key(pkey.get(), cert.get(), desc);
        ret = cryptokey->add(key);
        if (errorcode_t::success == ret) {
            pkey.release();  // cryptokey own pkey
            cert.release();  // cryptokey own cert
        }

        ERR_clear_error();
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::load_der(crypto_key* cryptokey, const byte_t* buffer, size_t size, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        X509_ptr x509;
        BIO_ptr bio(BIO_new(BIO_s_mem()));
        if (nullptr == bio.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIO_write(bio.get(), buffer, size);
        const byte_t* p = buffer;
        // The letters i and d in i2d_TYPE() stand for "internal" (that is, an internal C structure) and "DER" respectively.
        // So i2d_TYPE() converts from internal to DER. d2i_ vice versa
        EVP_PKEY_ptr pkey(d2i_PrivateKey_bio(bio.get(), nullptr));
        if (nullptr == pkey.get()) {
            x509 = std::move(X509_ptr(d2i_X509(nullptr, &p, size)));
            pkey = std::move(EVP_PKEY_ptr(X509_get_pubkey(x509.get())));
        }
        if (nullptr == pkey) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

#if defined DEBUG
        if (istraceable(trace_category_internal, loglevel_debug)) {
            trace_debug_event(trace_category_internal, trace_event_internal, [&](basic_stream& dbs) -> void {
                BIO_ptr dbio(BIO_new(BIO_s_mem()));
                X509_print(dbio.get(), x509.get());  // x509 -> dbio
                read_bio(&dbs, dbio.get());          // dbio -> dbs
            });
        }
#endif

        crypto_key_object key(pkey.get(), x509.get(), desc);
        ret = cryptokey->add(key);
        if (errorcode_t::success == ret) {
            pkey.release();  // cryptokey own pkey
            x509.release();  // cryptokey own x509
        }

        ERR_clear_error();
    }
    __finally2 {}
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
    __finally2 {}
    return ret;
}

return_t crypto_keychain::write_pem(crypto_key* cryptokey, stream_t* stream, int flag) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        stream->clear();

        BIO_CHAIN_ptr out(BIO_new(BIO_s_mem()));
        if (nullptr == out.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        auto lambda = [](crypto_key_object* key, void* param) -> void { dump_pem(key->get_pkey(), (BIO*)param); };

        cryptokey->for_each(lambda, (void*)out.get());

        binary_t buf;
        buf.resize(64);
        int len = 0;
        while (1) {
            len = BIO_read(out.get(), buf.data(), buf.size());
            if (0 >= len) {
                break;
            }
            stream->write(buf.data(), len);
        }
    }
    __finally2 {}
    return ret;
}

template <typename TYPE>
return_t crypto_keychain::t_write_der(const X509* x509, TYPE& buffer, std::function<void(const byte_t*, int, TYPE&)> func) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == x509 || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        BIO_CHAIN_ptr out(BIO_new(BIO_s_mem()));
        if (nullptr == out.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        i2d_X509_bio(out.get(), (X509*)x509);

        binary_t buf;
        buf.resize(64);
        int len = 0;
        while (1) {
            len = BIO_read(out.get(), buf.data(), buf.size());
            if (0 >= len) {
                break;
            }

            func(buf.data(), len, buffer);
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::write_der(const X509* x509, stream_t* stream) {
    return_t ret = errorcode_t::success;
    ret = t_write_der<stream_t*>(x509, stream, [&](const byte_t* source, int len, stream_t*& target) -> void { target->write(source, len); });
    return ret;
}

return_t crypto_keychain::write_der(const X509* x509, binary_t& bin) {
    return_t ret = errorcode_t::success;
    ret = t_write_der<binary_t>(x509, bin, [&](const byte_t* source, int len, binary_t& target) -> void { binary_append(target, source, len); });
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
    __finally2 {}
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
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add(crypto_key* cryptokey, uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto kty = ktyof_nid(nid);
        switch (kty) {
            case kty_dh: {
                ret = add_dh(cryptokey, nid, desc);
            } break;
            case kty_dsa: {
                ret = add_dsa(cryptokey, nid, desc);
            } break;
            case kty_ec: {
                ret = add_ec(cryptokey, nid, desc);
            } break;
            case kty_okp: {
                ret = add_okp(cryptokey, nid, desc);
            } break;
            case kty_rsa: {
                ret = add_rsa(cryptokey, nid, 2048, desc);
            } break;
            case kty_mlkem: {
                ret = add_mlkem(cryptokey, nid, desc);
            } break;
            default: {
                ret = not_supported;
            } break;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
