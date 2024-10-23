/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.27   Soo Han, Kim        get_crl - temporary disabled, under construction
 */

#include <map>
#include <sdk/base/string/string.hpp>
#include <sdk/base/system/thread.hpp>
#include <sdk/crypto/authenticode/authenticode_plugin_pe.hpp>
#include <sdk/crypto/authenticode/authenticode_verifier.hpp>
#include <sdk/crypto/authenticode/sdk.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/io/system/sdk.hpp>
#include <set>

namespace hotplace {
using namespace io;
namespace crypto {

#define AUTHENTICODE_CONTEXT_SIGNATURE 0x20170710

typedef std::set<std::string> authenticode_signer_set_t; /* signer */
typedef std::map<std::string, std::string> authenticode_trusted_cert_map_t;
typedef std::map<std::string, X509_CRL*> authenticode_crl_map_t;        /* pair(crl distribution point, X509_CRL pointer) */
typedef std::map<int, authenticode_plugin*> authenticode_engines_map_t; /* pair of authenticode_engine_id_t and authenticode_plugin* */
typedef struct _authenticode_context_t {
    uint32 signature;       //<<< AUTHENTICODE_CONTEXT_SIGNATURE
    critical_section lock;  //<< lock
    authenticode_engines_map_t engines;
    uint32 flags;                      //<<< AUTHENTICODE_FLAG
    authenticode_signer_set_t signer;  //<<< signer
    authenticode_trusted_cert_map_t trusted_cert;

    int load_root_cert;
    int crl_download;
    int crl_download_timeout;
    int crl_download_retry;
    critical_section crl_lock;
    authenticode_crl_map_t crl_map;

    std::string proxy_url;
    std::string proxy_user;
    std::list<std::string> digicert_path;
    std::string crl_path;
    bool gender;

    _authenticode_context_t() : load_root_cert(0), crl_download(1), crl_download_timeout(3), crl_download_retry(1), gender(false) {}
} authenticode_context_t;

typedef std::map<arch_t, authenticode_context_t*> authenticode_contexts_map_t;
typedef std::pair<authenticode_contexts_map_t::iterator, bool> authenticode_contexts_map_pib_t;
typedef std::list<authenticode_plugin*> authenticode_engine_list_t;
critical_section _contexts_lock;
authenticode_contexts_map_t _contexts;

/*
 * get_crl
 * @param authenticode_context_t* context [in]
 * @param X509* cert [in]
 * @param authenticode_crl_map_t& crl_map [out] do not call clear_crl
 * @remarks
 *        read crl distribution point from X509 certificate
 *        insert into context-level crl map (context->crl_map)
 *        insert into file-level crl map (crl_map parameter)
 */
static return_t get_crl(authenticode_context_t* context, X509* cert, authenticode_crl_map_t& crl_map);
/*
 * clear_crl
 * @param authenticode_context_t* context [in]
 */
static return_t clear_crl(authenticode_context_t* context);

authenticode_verifier::authenticode_verifier() { openssl_startup(); }

authenticode_verifier::~authenticode_verifier() { openssl_cleanup(); }

return_t authenticode_verifier::add_engine(authenticode_context_t* handle, authenticode_plugin* engine) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (AUTHENTICODE_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        if (nullptr == engine) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(handle->lock);
        std::pair<authenticode_engines_map_t::iterator, bool> result;
        result = handle->engines.insert(std::make_pair(engine->id(), engine));
        if (false == result.second) {
            ret = errorcode_t::already_exist;
            engine->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_verifier::load_engines(authenticode_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (AUTHENTICODE_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        critical_section_guard guard(handle->lock);
        handle->engines.insert(std::make_pair(authenticode_engine_id_pe, new authenticode_plugin_pe()));
        // handle->engines.insert (std::make_pair (authenticode_engine_id_msi, new authenticode_plugin_msi ()));
        // handle->engines.insert (std::make_pair (authenticode_engine_id_cab, new authenticode_plugin_cabinet ()));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_verifier::free_engines(authenticode_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (AUTHENTICODE_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        critical_section_guard guard(handle->lock);
        for (auto& pair : handle->engines) {
            authenticode_plugin* engine = pair.second;
            engine->release();  // free
        }
        handle->engines.clear();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_verifier::open(authenticode_context_t** handle) {
    return_t ret = errorcode_t::success;
    authenticode_context_t* context = nullptr;

    __try2 {
        __try_new_catch(context, new authenticode_context_t, ret, __leave2);

        context->signature = AUTHENTICODE_CONTEXT_SIGNATURE;

        load_engines(context);

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != context) {
                delete context;
            }
        }
    }
    return ret;
}

return_t authenticode_verifier::set(authenticode_context_t* handle, int option, void* data, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (AUTHENTICODE_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        critical_section_guard guard(handle->lock);

        switch (option) {
            case authenticode_ctrl_t::set_proxy:
                if (nullptr == data) {
                    ret = errorcode_t::invalid_parameter;
                } else {
                    handle->proxy_url = std::string((char*)data, size);
                }
                break;
            case authenticode_ctrl_t::set_proxy_user:
                if (nullptr == data) {
                    ret = errorcode_t::invalid_parameter;
                } else {
                    handle->proxy_user = std::string((char*)data, size);
                }
                break;
            case authenticode_ctrl_t::set_gen_der:
                if ((nullptr != data) && (sizeof(bool) == size)) {
                    handle->gender = *(bool*)data;
                } else {
                    ret = errorcode_t::invalid_parameter;
                }
                break;
            case authenticode_ctrl_t::set_crl:
                if ((nullptr != data) && (sizeof(int) == size)) {
                    handle->crl_download = *(int*)data;
                } else {
                    ret = errorcode_t::invalid_parameter;
                }
                break;
            case authenticode_ctrl_t::reset_digicert_path:
                handle->digicert_path.clear();
                break;
            case authenticode_ctrl_t::set_digicert_path:
                if (nullptr == data) {
                    ret = errorcode_t::invalid_parameter;
                } else {
                    handle->digicert_path.push_back(std::string((char*)data, size));
                }
                break;
            case authenticode_ctrl_t::set_crl_path:
                if (nullptr == data) {
                    ret = errorcode_t::invalid_parameter;
                } else {
                    handle->crl_path = std::string((char*)data, size);
                }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_verifier::verify(authenticode_context_t* handle, const char* file_name, uint32 flags, uint32& result, uint32* engine_id) {
    return_t ret = errorcode_t::success;
    file_stream filestream;
    authenticode_plugin* engine_matched = nullptr;

    __try2 {
        result = 0;
        if (nullptr == handle || nullptr == file_name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (AUTHENTICODE_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = filestream.open(file_name, filestream_flag_t::open_existing);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        //__trace (0, "-- verify %s", file_name);

        binary_t binary;
        {
            critical_section_guard guard(handle->lock);

            for (auto& pair : handle->engines) {
                authenticode_plugin* engine = pair.second;
                if ((true == engine->is_kind_of(&filestream)) && (false == engine->separated())) {
                    engine->addref();
                    engine_matched = engine;
                    break;
                }
            }
        }

        if (nullptr == engine_matched) {
            ret = errorcode_t::bad_format;
        } else {
            ret = engine_matched->extract(&filestream, binary);
        }

        if (errorcode_t::success != ret) {
            if (authenticode_flag_t::flag_separated & flags) {
                ret = verify_separated(handle, file_name, authenticode_flag_t::flag_separated, result);
            }
            __leave2;
        }

        /*
         * openssl asn1parse -inform der -i -in bCerficiate.saved
         * openssl pkcs7 -inform DER -print_certs -text -in bCerficiate.saved
         */
        if (handle->gender) {
            file_stream bin;
            bin.open(format("%s.der", file_name).c_str(), filestream_flag_t::open_create_always);
            bin.write(&binary[0], binary.size());
            bin.close();
        }

        PKCS7* pkcs7 = nullptr;
        BIO* in = nullptr;
        __try2 {
            in = BIO_new(BIO_s_mem());
            BIO_write(in, &binary[0], binary.size());
            /*
             * openssl asn1parse -inform der -i -in bCerficiate.saved
             * openssl pkcs7 -inform DER -print_certs -text -in bCerficiate.saved
             */
            pkcs7 = d2i_PKCS7_bio(in, nullptr);
            if (nullptr == pkcs7) {
                ret = errorcode_t::bad_format;
                __leave2;
            }

            std::string md;
            binary_t pkcs7_digest;
            binary_t md_digest;
            ret = pkcs7_digest_info(pkcs7, md, pkcs7_digest);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            engine_matched->digest(&filestream, md.c_str(), md_digest);

            if (authenticode_engine_id_msi != engine_matched->id()) {
                if (pkcs7_digest != md_digest) {
                    ret = errorcode_t::error_digest;
                    __leave2;
                }
            }

            ret = verify_pkcs7(handle, pkcs7, flags, result);
        }
        __finally2 {
            if (nullptr != in) {
                BIO_free(in);
            }
            if (nullptr != pkcs7) {
                PKCS7_free(pkcs7);
            }
        }
    }
    __finally2 {
        // do nothing
        if (engine_matched) {
            if (nullptr != engine_id) {
                *engine_id = engine_matched->id();
            }
            engine_matched->release();
        }
    }
    return ret;
}

return_t authenticode_verifier::verify_separated(authenticode_context_t* handle, const char* file_name, uint32 flags, uint32& result) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (AUTHENTICODE_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = errorcode_t::error_verify;
        result = authenticode_verify_t::verify_unknown;

        if (authenticode_flag_t::flag_separated & flags) {
            authenticode_engine_list_t engines;
            {
                critical_section_guard guard(handle->lock);

                for (auto& pair : handle->engines) {
                    authenticode_plugin* engine = pair.second;
                    if (true == engine->separated()) {
                        engine->addref();
                        engines.push_back(engine);
                        break;
                    }
                }
            }

            for (authenticode_plugin* engine : engines) {
                std::list<std::string> filelist;

                /* search a case-sensitive filename
                 * MpSetup.ini
                 *   MpSetup.ini.ahc
                 *   mpsetup.ini.ahc
                 */
                {
                    critical_section_guard guard(handle->lock);
                    engine->find_if_separated(file_name, handle->digicert_path, filelist);
                }

                /* found - filename.ahc */
                return_t ret_file = errorcode_t::success;

                for (const auto& file : filelist) {
                    uint32 sep_result = authenticode_verify_t::verify_unknown;

                    ret_file = verify(handle, file.c_str(), 0, sep_result);
                    if (errorcode_t::success == ret_file) {
                        ret_file = engine->verify_if_separated(file_name, file, &sep_result);
                        if (authenticode_verify_t::verify_ok == sep_result) {
                            ret = errorcode_t::success;
                            result = authenticode_verify_t::verify_ok;
                            break;
                        }
                    }
                }

                engine->release();
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_verifier::close(authenticode_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (AUTHENTICODE_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        clear_crl(handle);

        free_engines(handle);

        delete handle;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_verifier::add_trusted_signer(authenticode_context_t* handle, const char* signer) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == signer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (AUTHENTICODE_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        critical_section_guard guard(handle->lock);

        handle->signer.insert(std::string(signer));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_verifier::remove_trusted_signer(authenticode_context_t* handle, const char* signer) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == signer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (AUTHENTICODE_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        critical_section_guard guard(handle->lock);

        authenticode_signer_set_t::iterator iter = handle->signer.find(std::string(signer));
        if (handle->signer.end() == iter) {
            ret = errorcode_t::not_found;
        } else {
            handle->signer.erase(iter);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_verifier::remove_all_trusted_signer(authenticode_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (AUTHENTICODE_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        critical_section_guard guard(handle->lock);
        handle->signer.clear();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_verifier::add_trusted_rootcert(authenticode_context_t* handle, const char* file, const char* path) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == file && nullptr == path) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (AUTHENTICODE_CONTEXT_SIGNATURE != handle->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        critical_section_guard guard(handle->lock);
        handle->trusted_cert.insert(std::make_pair(file ? file : "", path ? path : ""));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

static unsigned int asn1_simple_hdr_len(const unsigned char* p, unsigned int len) {
    // indirect data content
    // uint8* oid = pkcs7->d.sign->contents->type->data;
    // compare oid
    // uint8* p = pkcs7->d.sign->contents->d.other->value.asn1_string->data
    // if (0 == (p[1] & 0x80)) { (content length < 128) ; size = p[1] & 0x7f; (p[0..1] : len = 2) }
    // else if (0x81 == (p[1] & 0x81)) { (128 <= content length < 255; size = p[2] ; (p[0..2] : len = 3) };
    // else if (0x82 == (p[1] & 0x82)) { (content length > 255); size = (p[2] << 8) + p[3]; (p[0..3] : len = 4) };
    if (len <= 2 || p[0] > 0x31) {
        return 0;
    }
    // 7&8 = 0, f&1 = 1, f&2 = 2, and then 81 => 1, 82 = > 2
    // return (p[1] & 0x80) ? (2 + (p[1] & 0x7f)) : 2;
    unsigned int ret = 2;

    if (0x81 == (0x81 & p[1])) {
        ret = 3;
    } else if (0x82 == (0x82 & p[1])) {
        ret = 4;
    }
    return ret;
}

int verify_callback(int ok, X509_STORE_CTX* ctx) {
    char buf[256];

    X509* err_cert = X509_STORE_CTX_get_current_cert(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);

    // PKCS7_verify use iter's own X509_STORE_CTX
    // authenticode_context_t* context = (authenticode_context_t*)X509_STORE_CTX_get_ex_data(ctx, 0);

    std::string subject;

    X509_NAME_to_string(X509_get_subject_name(err_cert), subject);

    //__trace (0, format ("#depth=%d %s", depth, subject.c_str ()).c_str ());

    if (0 == depth) {
        // find the thread-specified authenticode_context_t
        authenticode_context_t* context = nullptr;
        {
            critical_section_guard guard(_contexts_lock);
            authenticode_contexts_map_t::iterator iter = _contexts.find(get_thread_id());
            context = iter->second;
        }

        if (nullptr != context) {
            critical_section_guard guard(context->lock);
            if (false == context->signer.empty()) {
                bool match = false;
                for (const auto& cn : context->signer) {
                    std::string find = format("CN=%s", cn.c_str());
                    size_t pos = subject.find(find);

                    if (std::string::npos != pos) {
                        if (0 == strcmp(subject.substr(pos).c_str(), find.c_str())) {
                            match = true;
                            break;
                        }
                    }
                }  // for
                if (false == match) {
                    ok = 0;
                    err = X509_V_ERR_CERT_UNTRUSTED;
                    X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_UNTRUSTED);
                }
            }
        }
    }

    if (!ok) {
        //__trace (0, format ("#verify error:num=%d:%s", err, X509_verify_cert_error_string (err)).c_str ());
    }
    switch (err) {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:          // (2)
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:  // (20)
        {
            X509* cert = X509_STORE_CTX_get_current_cert(ctx);
            X509_NAME_oneline(X509_get_issuer_name(cert), buf, 256);
            //__trace (0, format ("#issuer= %s", buf).c_str ());
        } break;
        case X509_V_ERR_UNABLE_TO_GET_CRL:               // (3)
        case X509_V_ERR_CERT_NOT_YET_VALID:              // (9)
        case X509_V_ERR_CERT_HAS_EXPIRED:                // (10)
        case X509_V_ERR_CRL_NOT_YET_VALID:               // (11)
        case X509_V_ERR_CRL_HAS_EXPIRED:                 // (12)
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:  // (13)
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:   // (14)
            // pass through
            // force X509_V_OK
            // additional error codes
            //      case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: // (15)
            //      case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: // (16)
            // if need time check ...
            //      printf("#notBefore=");
            //      ASN1_UTCTIME_print(bio_err,X509_get_notBefore(ctx->current_cert));
            //      printf("#notAfter=");
            //      ASN1_UTCTIME_print(bio_err,X509_get_notAfter(ctx->current_cert));
            //      printf("\n");
            X509_STORE_CTX_set_error(ctx, X509_V_OK);
            ok = 1;
            break;
        case 0:
            break;
        default:
            // printf("#error %d\n", err);
            break;
    }
    if (!ok) {
        // constexpr char constexpr_errmsg[] = "#verify error:num=";
        //__trace(errorcode_t::internal_error, format("%s%d:%s", constexpr_errmsg, err, X509_verify_cert_error_string(err)).c_str());
    }
    //__trace(0, format("#verify return:%d",ok).c_str());
    // ok = 1;
    return ok;
}

return_t authenticode_verifier::verify_pkcs7(authenticode_context_t* handle, void* pkcs7_pointer, uint32 flags, uint32& result) {
    return_t ret = errorcode_t::success;
    // result = authenticode_verify_t::verify_unknown;

    int ret_verify = 0;
    PKCS7* pkcs7 = reinterpret_cast<PKCS7*>(pkcs7_pointer);
    X509_STORE_CTX* store_context = nullptr;
    X509_STORE* store = nullptr;

    // STACK_OF(X509)* chain = nullptr;
    BIO* bio = nullptr;
    authenticode_contexts_map_pib_t pib;

    __try2 {
        if (nullptr == handle || nullptr == pkcs7) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        {
            critical_section_guard guard(_contexts_lock);
            pib = _contexts.insert(std::make_pair(get_thread_id(), handle));
        }

        /* check if it's PKCS#7 signed data */
        if (0 == PKCS7_type_is_signed(pkcs7)) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        authenticode_crl_map_t crl_map;

        {
            int i = 0;
            STACK_OF(X509)* signers = PKCS7_get0_signers(pkcs7, nullptr, 0);
            for (i = 0; i < sk_X509_num(signers); i++) {
                X509* cert = sk_X509_value(signers, i);
                get_crl(handle, cert, crl_map);
            }
            sk_X509_free(signers);

            for (i = 0; i < sk_X509_num(pkcs7->d.sign->cert); i++) {
                X509* cert = sk_X509_value(pkcs7->d.sign->cert, i);
                get_crl(handle, cert, crl_map);
            }
        }

#if 0
        int i = 0;
        STACK_OF (X509) * signers = PKCS7_get0_signers (pkcs7, nullptr, 0);
        printf ("\nNumber of signers: %d\n", sk_X509_num (signers));
        for (i = 0; i < sk_X509_num (signers); i++) {
            X509* cert = sk_X509_value (signers, i);
            printf ("Signer %d\n", i);
            print_x509 (cert);

            std::set<std::string> crls;
            crl_distribution_point (cert, crls);
            __for (std::set<std::string>::iterator, it, crls) {
                std::string item = iter_value (it);

                printf ("CRL : %s\n", item.c_str ());
            }
            // openssl crl -inform DER -text -noout -in sf.crl
        }
        sk_X509_free (signers);

        printf ("\nNumber of certificates: %d\n", sk_X509_num (pkcs7->d.sign->cert));
        for (i = 0; i < sk_X509_num (pkcs7->d.sign->cert); i++) {
            X509 *cert = sk_X509_value (pkcs7->d.sign->cert, i);
            printf ("Certificate %d\n", i);
            print_x509 (cert);
        }
#endif

        int seqhdrlen = asn1_simple_hdr_len(pkcs7->d.sign->contents->d.other->value.sequence->data, pkcs7->d.sign->contents->d.other->value.sequence->length);
        bio = BIO_new_mem_buf(pkcs7->d.sign->contents->d.other->value.sequence->data + seqhdrlen,
                              pkcs7->d.sign->contents->d.other->value.sequence->length - seqhdrlen);

        store = X509_STORE_new();
        X509_STORE_set_default_paths(store);
        // X509_STORE_load_locations(store, nullptr, "/etc/pki/tls/certs/");
        // prevent error 20
        // X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        // unable to get local issuer certificate
        // X509_STORE_load_locations(store, "trust.crt", nullptr);

        {
            critical_section_guard guard(handle->lock);
            for (const auto& pair : handle->trusted_cert) {
                const std::string& cert_file = pair.first;
                const std::string& cert_path = pair.second;
                // X509_STORE_load_locations (store, cert_file.empty () ? nullptr : cert_file.c_str (),
                //                           cert_path.empty () ? nullptr : cert_path.c_str ());
                // load cert wo path
                if (cert_file.size()) {
                    X509_LOOKUP* lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
                    X509_load_cert_file(lookup, cert_file.c_str(), X509_FILETYPE_PEM);
                }
            }
        }

        X509_STORE_set_verify_cb_func(store, verify_callback);
        ERR_clear_error();

        // chain = sk_X509_new_null();

        // prevent error 26
        // X509_V_ERR_INVALID_PURPOSE
        // unsupported certificate purpose
        // http://securitypad.blogspot.kr/2017/01/openssl-pkcs7-verification-unsupported.html
        store_context = X509_STORE_CTX_new();
        X509_STORE_CTX_init(store_context, store, nullptr, nullptr);
        X509_VERIFY_PARAM* vparam = X509_STORE_CTX_get0_param(store_context);
        int purpose = X509_PURPOSE_ANY;
        X509_VERIFY_PARAM_set_purpose(vparam, purpose);
        X509_STORE_set1_param(store, vparam);

        // PKCS7_verify use it's own X509_STORE_CTX
        // X509_STORE_CTX_set_ex_data(store_context, 0, handle);

        for (auto& pair : crl_map) {
            X509_CRL* crl = pair.second;
            if (crl) {
                X509_STORE_add_crl(store, crl);
                X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
            }
        }

        int flag = 0;
        ret_verify = PKCS7_verify(pkcs7, pkcs7->d.sign->cert, store, bio, nullptr, flag);
        //__trace(0, format("PKCS7_verify %d", ret_verify).c_str());
        // printf("Signature verification: %s\n\n", ret_verify ? "ok" : "failed");
        if (ret_verify < 1) {
            ret = errorcode_t::error_verify;
            __leave2_trace_openssl(ret);
        }
    }
    __finally2 {
        // if (nullptr != chain)
        //{
        //  sk_X509_free(chain);
        //}
        if (nullptr != bio) {
            BIO_free(bio);
        }
        if (nullptr != store) {
            X509_STORE_free(store);
        }
        if (nullptr != store_context) {
            X509_STORE_CTX_free(store_context);
        }
        if (nullptr != handle) {
            critical_section_guard guard(_contexts_lock);
            if (true == pib.second) {
                _contexts.erase(pib.first);
            }
        }

        // do nothing
    }

    return ret;
}

typedef struct _AUTHENTICODE_RESULT {
    uint32 engine_id;
    uint32 result;
} AUTHENTICODE_RESULT;
typedef std::map<std::string, AUTHENTICODE_RESULT> authenticode_filelist_map_t;
typedef std::map<std::string, std::string> authenticode_index_map_t;  // lower-case
typedef struct _AUTHENTICODE_VERIFY_CONTEXT {
    authenticode_filelist_map_t filelist;
    authenticode_index_map_t index;
} AUTHENTICODE_VERIFY_CONTEXT;

static return_t get_crl(authenticode_context_t* context, X509* cert, authenticode_crl_map_t& crl_map) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == context || nullptr == cert) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == context->crl_download) {
            __leave2;
        }

        std::string context_crl_path = context->crl_path;

        std::set<std::string> crls;
        crl_distribution_point(cert, crls);
        for (const auto& crl_url : crls) {
            url_info_t url_info;

            split_url(crl_url.c_str(), &url_info);
            std::string crl_path = format("%s/%s/%s", context_crl_path.c_str(), url_info.host.c_str(), url_info.uripath.c_str());
            std::string crl_file = format("%s/%s%s", context_crl_path.c_str(), url_info.host.c_str(), url_info.uri.c_str());

            //__vtrace(0, "CRL : %s", crl_url.c_str());

            {
                critical_section_guard guard(context->crl_lock);

                authenticode_crl_map_t::iterator crl_it = context->crl_map.find(crl_url);
                if (context->crl_map.end() != crl_it) {
                    // no matter what crl is null or not
                    crl_map.insert(std::make_pair(crl_it->first, crl_it->second));
                    __leave2;
                }

#if 0
                Process process;
                // wget --connect-timeout=3 -t 1
                std::string cmdline_proxy;
                if (false == context->proxy_url.empty ()) {
                    cmdline_proxy += "-e use_proxy=yes ";
                    if (context->proxy_user.empty ()) {
                        cmdline_proxy += format ("-e http_proxy=%s ", context->proxy_url.c_str ());
                    } else {
                        url_info_t url;
                        split_url (context->proxy_url.c_str (), &url);
                        cmdline_proxy += format ("-e http_proxy=%s://%s@%s:%d/ ",
                                                 url.protocol.c_str (), context->proxy_user.c_str (), url.host.c_str (), url.port);
                    }
                }

                std::string nonce ("temp");
                std::string out;
                create_nonce (8, nonce);
                // wget --connect-timeout=3
                //      -t 1
                //      http://crl.microsoft.com/pki/crl/products/MicrosoftCodeVerifRoot.crl
                //      -O crl/crl.microsoft.com/pki/crl/products/MicrosoftCodeVerifRoot.crl
                //      -o tempfile
                std::string cmdline_wget = format ("wget %s --connect-timeout=%d -t %d %s -O %s -o %s",
                                                   cmdline_proxy.c_str (), context->crl_download_timeout, context->crl_download_retry,
                                                   crl_url.c_str (), crl_file.c_str (), nonce.c_str ());


                mkdirp (crl_path.c_str ());
                process.run (cmdline_wget.c_str (), out);
                unlink (nonce.c_str ());

                BIO* bio = BIO_new_file (crl_file.c_str (), "r");
                X509_CRL* crl = d2i_X509_CRL_bio (bio, nullptr);
                BIO_free (bio);

                if (nullptr == crl) {
                    unlink (crl_file.c_str ());
                }

                // no matter what crl is null or not
                context->crl_map.insert (std::make_pair (crl_url, crl));
                crl_map.insert (std::make_pair (crl_url, crl));
#endif
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

static return_t clear_crl(authenticode_context_t* context) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(context->crl_lock);
        for (auto& pair : context->crl_map) {
            X509_CRL* crl = pair.second;
            if (crl) {
                X509_CRL_free(crl);
            }
        }
        context->crl_map.clear();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
