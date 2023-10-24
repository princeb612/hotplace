/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <hotplace/sdk/sdk.hpp>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;
typedef struct _OPTION {
    bool dump_keys;
    bool validate_testvector;

    _OPTION() : dump_keys(false), validate_testvector(false) {
        // do nothing
    }
} OPTION;
t_shared_instance<cmdline_t<OPTION> > _cmdline;

crypto_key rfc8152_privkeys;
crypto_key rfc8152_pubkeys;
crypto_key rfc8152_privkeys_c4;

return_t dump_test_data(const char* text, basic_stream& diagnostic) {
    return_t ret = errorcode_t::success;

    if (text) {
        std::cout << text;
    } else {
        std::cout << "diagnostic";
    }
    std::cout << std::endl << diagnostic.c_str() << std::endl;

    return ret;
}

return_t dump_test_data(const char* text, binary_t const& cbor) {
    return_t ret = errorcode_t::success;
    basic_stream bs;

    dump_memory(cbor, &bs, 32);

    if (text) {
        std::cout << text;
    } else {
        std::cout << "diagnostic";
    }
    std::cout << std::endl << bs.c_str() << std::endl;

    return ret;
}

void dump_crypto_key(crypto_key_object_t* key, void*) {
    OPTION option = _cmdline->value();  // (*_cmdline).value () is ok

    if (option.dump_keys) {
        uint32 nid = 0;

        nidof_evp_pkey(key->pkey, nid);
        printf("nid %i kid %s alg %s use %08x\n", nid, key->kid.c_str(), key->alg.c_str(), key->use);

        basic_stream bs;
        dump_key(key->pkey, &bs);
        printf("%s\n", bs.c_str());
    }
}

return_t test_cose_example(cose_context_t* cose_handle, crypto_key* cose_keys, cbor_object* root, const char* expect_file, const char* text) {
    return_t ret = errorcode_t::success;
    return_t test = errorcode_t::success;

    __try2 {
        if (nullptr == cose_handle || nullptr == cose_keys || nullptr == root || nullptr == expect_file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_publisher publisher;

        // cbor_object* to diagnostic
        basic_stream diagnostic;
        publisher.publish(root, &diagnostic);

        // cbor_object* to cbor
        binary_t bin;
        publisher.publish(root, &bin);

        // load cbor from file
        binary_t expect;
        {
            test_case_notimecheck notimecheck(_test_case);

            file_stream fs;
            ret = fs.open(expect_file);
            if (errorcode_t::success != ret) {
                __leave2;
            }
            fs.begin_mmap();

            byte_t* file_contents = fs.data();
            size_t file_size = fs.size();
            expect.insert(expect.end(), file_contents, file_contents + file_size);

            dump_test_data("test vector", expect);
            dump_test_data("diagnostic #1", diagnostic);
            dump_test_data("cbor #1", bin);
        }

        _test_case.assert((bin == expect), __FUNCTION__, "check1.cborcheck %s", text ? text : "");

        // parse
        basic_stream bs_diagnostic_lv1;
        binary_t bin_cbor_lv1;

        cbor_reader reader;
        cbor_reader_context_t* handle = nullptr;
        cbor_object* newone = nullptr;

        reader.open(&handle);
        reader.parse(handle, bin);
        // cbor_reader_context_t* to diagnostic
        reader.publish(handle, &bs_diagnostic_lv1);
        // cbor_reader_context_t* to cbor
        reader.publish(handle, &bin_cbor_lv1);
        // cbor_reader_context_t* to cbor_object*
        reader.publish(handle, &newone);
        reader.close(handle);

        if (newone) {
            {
                test_case_notimecheck notimecheck(_test_case);

                dump_test_data("diagnostic #2", bs_diagnostic_lv1);
                dump_test_data("cbor #2", bin_cbor_lv1);
            }
            _test_case.assert((bin_cbor_lv1 == expect), __FUNCTION__, "check2.cborparse %s", text ? text : "");

            // parsed cbor_object* to diagnostic
            basic_stream bs_diagnostic_lv2;
            publisher.publish(newone, &bs_diagnostic_lv2);

            // parsed cbor_object* to cbor
            binary_t bin_cbor_lv2;
            publisher.publish(newone, &bin_cbor_lv2);

            {
                test_case_notimecheck notimecheck(_test_case);

                dump_test_data("diagnostic #3", bs_diagnostic_lv2);
                dump_test_data("cbor #3", bin_cbor_lv2);
            }
            _test_case.assert((bin_cbor_lv2 == expect), __FUNCTION__, "check3.cborparse %s", text ? text : "");

            newone->release();  // release parsed object
        }

        cbor_object_signing_encryption cose;
        binary_t signature;
        binary_t decrypted;
        bool result = false;

        if (root->tagged()) {
            switch (root->tag_value()) {
                case cbor_tag_t::cose_tag_sign:
                case cbor_tag_t::cose_tag_sign1:
                    ret = cose.verify(cose_handle, cose_keys, bin, result);
                    _test_case.test(ret, __FUNCTION__, "check4.verify %s", text ? text : "");
                    break;
                case cbor_tag_t::cose_tag_encrypt:
                case cbor_tag_t::cose_tag_encrypt0:
                    ret = cose.decrypt(cose_handle, cose_keys, bin, decrypted, result);
                    if (errorcode_t::success == ret) {
                        basic_stream bs;
                        dump_memory(decrypted, &bs);
                        printf("%s\n", bs.c_str());
                    }
                    _test_case.test(ret, __FUNCTION__, "check4.decrypt %s", text ? text : "");
                    break;
                case cbor_tag_t::cose_tag_mac:
                case cbor_tag_t::cose_tag_mac0:
                    ret = cose.verify(cose_handle, cose_keys, bin, result);
                    _test_case.test(ret, __FUNCTION__, "check4.verify %s", text ? text : "");
                    break;
                default:
                    break;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void test_cbor_file(const char* expect_file, const char* text) {
    _test_case.begin("parse and generate diagnostic from RFC examples");

    console_color concolor;

    std::cout << concolor.turnon().set_style(console_style_t::bold).set_fgcolor(console_color_t::cyan) << expect_file << std::endl;
    std::cout << concolor.turnoff();

    return_t ret = errorcode_t::success;

    __try2 {
        binary_t expect;
        file_stream fs;
        ret = fs.open(expect_file);
        if (errorcode_t::success == ret) {
            fs.begin_mmap();

            byte_t* file_contents = fs.data();
            size_t file_size = fs.size();
            expect.insert(expect.end(), file_contents, file_contents + file_size);
        } else {
            __leave2;
        }

        basic_stream bs_diagnostic;
        binary_t bin_cbor;

        cbor_reader reader;
        cbor_reader_context_t* handle = nullptr;
        cbor_object* root = nullptr;

        reader.open(&handle);
        reader.parse(handle, expect);
        reader.publish(handle, &bs_diagnostic);
        reader.publish(handle, &bin_cbor);
        reader.publish(handle, &root);
        reader.close(handle);

        dump_test_data("diagnostic", bs_diagnostic);
        dump_test_data("cbor", bin_cbor);

        root->release();

        _test_case.assert((bin_cbor == expect), __FUNCTION__, text ? text : "");
    }
    __finally2 {
        // do nothing
    }
}

void test_rfc8152_c_1_1() {
    _test_case.begin("RFC 8152 C.1");

    // Signature Algorithm: ECDSA w/ SHA-256, Curve P-256

    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_data* cbor_data_protected = nullptr;
    composer.build_protected(&cbor_data_protected);

    cbor_data* cbor_data_payload = nullptr;
    composer.build_data(&cbor_data_payload, "This is the content.");

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_sign);
    *root << cbor_data_protected  // protected, bstr
          << new cbor_map()       // unprotected, map
          << cbor_data_payload    // payload, bstr/nil(detached)
          << new cbor_array();    // signatures

    cbor_array* signatures = (cbor_array*)(*root)[3];

    cbor_array* signature = new cbor_array();
    {
        cbor_data* cbor_data_signature_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_es256);  // -7
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_signature_protected, protected_map);
        }

        cbor_map* cbor_data_signature_unprotected = nullptr;
        {
            cose_variantmap_t unprotected_map;
            variant_set_binary_new(value, convert("11"));
            unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            composer.build_unprotected(&cbor_data_signature_unprotected, unprotected_map);
        }

        cbor_data* cbor_data_signature_signature = nullptr;
        {
            constexpr char constexpr_sig[] =
                "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a";
            composer.build_data_b16(&cbor_data_signature_signature, constexpr_sig);
        }

        *signature << cbor_data_signature_protected << cbor_data_signature_unprotected << cbor_data_signature_signature;
    }
    *signatures << signature;

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_1.cbor", "RFC 8152 C.1.1.  Single Signature");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_1_2() {
    _test_case.begin("RFC 8152 C.1");

    // Signature Algorithm: ECDSA w/ SHA-256, Curve P-256
    // Signature Algorithm: ECDSA w/ SHA-512, Curve P-521

    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_data* cbor_data_protected = nullptr;
    composer.build_protected(&cbor_data_protected);

    cbor_data* cbor_data_payload = nullptr;
    composer.build_data(&cbor_data_payload, "This is the content.");

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_sign);
    *root << cbor_data_protected  // protected
          << new cbor_map()       // unprotected
          << cbor_data_payload    // payload
          << new cbor_array();    // signatures

    cbor_array* signatures = (cbor_array*)(*root)[3];

    {
        cbor_array* signature = new cbor_array();

        cbor_data* cbor_data_signature_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_es256);  // -7
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_signature_protected, protected_map);
        }

        cbor_map* cbor_data_signature_unprotected = nullptr;
        {
            cose_variantmap_t unprotected_map;
            variant_set_binary_new(value, convert("11"));
            unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            composer.build_unprotected(&cbor_data_signature_unprotected, unprotected_map);
        }

        cbor_data* cbor_data_signature_signature = nullptr;
        {
            constexpr char constexpr_sig[] =
                "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a";
            composer.build_data_b16(&cbor_data_signature_signature, constexpr_sig);
        }

        *signature << cbor_data_signature_protected << cbor_data_signature_unprotected << cbor_data_signature_signature;

        *signatures << signature;
    }
    {
        cbor_array* signature = new cbor_array();

        cbor_data* cbor_data_signature_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_es512);  // -36
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_signature_protected, protected_map);
        }

        cbor_map* cbor_data_signature_unprotected = nullptr;
        {
            cose_variantmap_t unprotected_map;
            variant_set_binary_new(value, convert("bilbo.baggins@hobbiton.example"));
            unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            composer.build_unprotected(&cbor_data_signature_unprotected, unprotected_map);
        }

        cbor_data* cbor_data_signature_signature = nullptr;
        {
            constexpr char constexpr_sig[] =
                "00a2d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e8705524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf4"
                "82270cc5771aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f83ab87bb4f7a0297";
            composer.build_data_b16(&cbor_data_signature_signature, constexpr_sig);
        }

        *signature << cbor_data_signature_protected << cbor_data_signature_unprotected << cbor_data_signature_signature;

        *signatures << signature;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_2.cbor", "RFC 8152 C.1.2.  Multiple Signers");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_1_3() {
    _test_case.begin("RFC 8152 C.1");

    // Signature Algorithm: ECDSA w/ SHA-256, Curve P-256
    // The same parameters are used for both the signature and the counter signature.

    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_data* cbor_data_protected = nullptr;
    composer.build_protected(&cbor_data_protected);

    cbor_data* cbor_data_payload = nullptr;
    composer.build_data(&cbor_data_payload, "This is the content.");

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_sign);
    *root << cbor_data_protected  // protected
          << new cbor_map()       // unprotected
          << cbor_data_payload    // payload
          << new cbor_array();    // signatures

    cbor_map* header_unprotected = (cbor_map*)(*root)[1];
    {
        cbor_array* countersign = new cbor_array();
        *header_unprotected << new cbor_pair(cose_key_t::cose_counter_sig, countersign);

        cbor_data* cbor_data_countersignature_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_es256);
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_countersignature_protected, protected_map);
        }

        cbor_map* cbor_data_countersignature_unprotected = nullptr;
        {
            cose_variantmap_t unprotected_map;
            variant_set_binary_new(value, convert("11"));
            unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            composer.build_unprotected(&cbor_data_countersignature_unprotected, unprotected_map);
        }

        cbor_data* cbor_data_countersignature_signature = nullptr;
        {
            constexpr char constexpr_sig[] =
                "5ac05e289d5d0e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887e8802bb6650cceb2c";
            composer.build_data_b16(&cbor_data_countersignature_signature, constexpr_sig);
        }

        *countersign << cbor_data_countersignature_protected << cbor_data_countersignature_unprotected << cbor_data_countersignature_signature;
    }

    cbor_array* signatures = (cbor_array*)(*root)[3];

    cbor_array* signature = new cbor_array();
    {
        cbor_data* cbor_data_signature_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_es256);  // -7
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_signature_protected, protected_map);
        }

        cbor_map* cbor_data_signature_unprotected = nullptr;
        {
            cose_variantmap_t unprotected_map;
            variant_set_binary_new(value, convert("11"));
            unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            composer.build_unprotected(&cbor_data_signature_unprotected, unprotected_map);
        }

        cbor_data* cbor_data_signature_signature = nullptr;
        {
            constexpr char constexpr_sig[] =
                "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a";
            composer.build_data_b16(&cbor_data_signature_signature, constexpr_sig);
        }

        *signature << cbor_data_signature_protected << cbor_data_signature_unprotected << cbor_data_signature_signature;

        *signatures << signature;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_3.cbor", "RFC 8152 C.1.3.  Counter Signature");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_1_4() {
    _test_case.begin("RFC 8152 C.1");

    // Signature Algorithm: ECDSA w/ SHA-256, Curve P-256
    // There is a criticality marker on the "reserved" header parameter

    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_sign);

    cbor_data* cbor_data_protected = nullptr;
    {
        cbor_map* cbor_map_protected = new cbor_map();

        cbor_array* crit = new cbor_array();
        *crit << new cbor_data("reserved");  // [+ label]

        *cbor_map_protected << new cbor_pair("reserved", new cbor_data(false)) << new cbor_pair(cose_key_t::cose_crit, crit);

        composer.build_protected(&cbor_data_protected, cbor_map_protected);

        cbor_map_protected->release();
    }

    cbor_data* cbor_data_payload = nullptr;
    composer.build_data(&cbor_data_payload, "This is the content.");

    *root << cbor_data_protected  // protected
          << new cbor_map()       // unprotected
          << cbor_data_payload    // payload
          << new cbor_array();    // signatures

    cbor_array* signatures = (cbor_array*)(*root)[3];

    cbor_array* signature = new cbor_array();
    {
        cbor_data* cbor_data_signature_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_es256);  // -7
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_signature_protected, protected_map);
        }

        cbor_map* cbor_data_signature_unprotected = nullptr;
        {
            cose_variantmap_t unprotected_map;
            variant_set_binary_new(value, convert("11"));
            unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            composer.build_unprotected(&cbor_data_signature_unprotected, unprotected_map);
        }

        cbor_data* cbor_data_signature_signature = nullptr;
        {
            constexpr char constexpr_sig[] =
                "3fc54702aa56e1b2cb20284294c9106a63f91bac658d69351210a031d8fc7c5ff3e4be39445b1a3e83e1510d1aca2f2e8a7c081c7645042b18aba9d1fad1bd9c";
            composer.build_data_b16(&cbor_data_signature_signature, constexpr_sig);
        }

        *signature << cbor_data_signature_protected << cbor_data_signature_unprotected << cbor_data_signature_signature;

        *signatures << signature;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_4.cbor", "RFC 8152 C.1.4.  Signature with Criticality");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_2_1() {
    _test_case.begin("RFC 8152 C.2");
    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_sign1);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_es256);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose_variantmap_t unprotected_map;
        variant_set_binary_new(value, convert("11"));
        unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
        composer.build_unprotected(&cbor_data_unprotected, unprotected_map);
    }

    cbor_data* cbor_data_payload = nullptr;
    composer.build_data(&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_signature = nullptr;
    composer.build_data_b16(&cbor_data_signature,
                            "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36");

    *root << cbor_data_protected << cbor_data_unprotected << cbor_data_payload << cbor_data_signature;

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_2_1.cbor", "RFC 8152 C.2.1.  Single ECDSA Signature");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_1() {
    _test_case.begin("RFC 8152 C.3");
    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_encrypt);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_aes128gcm);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    cbor_data* cbor_data_ciphertext = nullptr;
    composer.build_data_b16(&cbor_data_ciphertext, "7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0");

    *root << cbor_data_protected   // protected
          << new cbor_map()        // unprotected
          << cbor_data_ciphertext  // ciphertext
          << new cbor_array();     // recipients

    cbor_map* header_unprotected = (cbor_map*)(*root)[1];
    { *header_unprotected << new cbor_pair(cose_key_t::cose_iv, new cbor_data(base16_decode("c9cf4df2fe6c632bf7886413"))); }

    cbor_array* recipients = (cbor_array*)(*root)[3];

    cbor_array* recipient = new cbor_array();
    {
        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_ecdhes_hkdf_256);
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_recipient_protected, protected_map);
        }

        cbor_map* cbor_data_recipient_unprotected = new cbor_map();
        {
            constexpr char constexpr_x[] = "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280";
            constexpr char constexpr_kid[] = "meriadoc.brandybuck@buckland.example";

            cbor_map* ephemeral = new cbor_map();
            *ephemeral << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))    // kty(1)
                       << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))  // crv(-1)
                       << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode(constexpr_x)))       // x(-2)
                       << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(true));                            // y(-3)

            *cbor_data_recipient_unprotected << new cbor_pair(cose_key_t::cose_ephemeral_key, ephemeral)                     // epk(-1)
                                             << new cbor_pair(cose_key_t::cose_kid, new cbor_data(convert(constexpr_kid)));  // kid(4)
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        composer.build_data_b16(&cbor_data_recipient_ciphertext, "");

        *recipient << cbor_data_recipient_protected    // protected
                   << cbor_data_recipient_unprotected  // unprotected
                   << cbor_data_recipient_ciphertext;  // ciphertext
    }
    *recipients << recipient;

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_3_1.cbor", "RFC 8152 C.3.1.  Direct ECDH");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_2() {
    _test_case.begin("RFC 8152 C.3");
    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_encrypt);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_aesccm_16_64_128);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_binary_new(value, base16_decode("89f52f65a1c580933b5261a76c"));
        protected_map.insert(std::make_pair(cose_key_t::cose_iv, value));
        composer.build_unprotected(&cbor_data_unprotected, protected_map);
    }

    cbor_data* cbor_data_ciphertext = nullptr;
    composer.build_data_b16(&cbor_data_ciphertext, "753548a19b1307084ca7b2056924ed95f2e3b17006dfe931b687b847");

    *root << cbor_data_protected    // protected
          << cbor_data_unprotected  // unprotected
          << cbor_data_ciphertext   // ciphertext
          << new cbor_array();      // recipients

    cbor_array* recipients = (cbor_array*)(*root)[3];

    {
        cbor_array* recipient = new cbor_array();
        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_hkdf_sha256);
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_recipient_protected, protected_map);
        }
        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_variantmap_t unprotected_map;
            variant_set_binary_new(value, convert("aabbccddeeffgghh"));
            unprotected_map.insert(std::make_pair(cose_key_t::cose_salt, value));
            variant_set_binary_new(value, convert("our-secret"));
            unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            composer.build_unprotected(&cbor_data_recipient_unprotected, unprotected_map);
        }

        *recipient << cbor_data_recipient_protected      // protected
                   << cbor_data_recipient_unprotected    // unprotected
                   << new cbor_data(base16_decode(""));  // ciphertext

        *recipients << recipient;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);

    variant_t vt;
    cose_variantmap_t partyu;
    cose_variantmap_t partyv;
    cose_variantmap_t pub;

    cose.set(cose_handle, cose_param_t::cose_unsent_apu_id, convert("lighting-client"));
    cose.set(cose_handle, cose_param_t::cose_unsent_apv_id, convert("lighting-server"));

    cose.set(cose_handle, cose_param_t::cose_unsent_pub_other, convert("Encryption Example 02"));

    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_3_2.cbor", "RFC 8152 C.3.2.  Direct Plus Key Derivation");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_3() {
    _test_case.begin("RFC 8152 C.3");
    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_encrypt);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_aes128gcm);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    constexpr char constexpr_ciphertext[] = "7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0";
    cbor_data* cbor_data_ciphertext = nullptr;
    composer.build_data_b16(&cbor_data_ciphertext, constexpr_ciphertext);

    *root << cbor_data_protected   // protected
          << new cbor_map()        // unprotected
          << cbor_data_ciphertext  // ciphertext
          << new cbor_array();     // recipients

    cbor_map* cbor_data_unprotected = (cbor_map*)(*root)[1];
    {
        cbor_array* countersign = new cbor_array();
        *cbor_data_unprotected << new cbor_pair(cose_key_t::cose_iv, new cbor_data(base16_decode("c9cf4df2fe6c632bf7886413")));
        *cbor_data_unprotected << new cbor_pair(cose_key_t::cose_counter_sig, countersign);

        cbor_data* cbor_data_countersignature_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_es512);
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_countersignature_protected, protected_map);
        }

        cbor_map* cbor_data_countersignature_unprotected = nullptr;
        {
            cose_variantmap_t unprotected_map;
            variant_set_binary_new(value, convert("bilbo.baggins@hobbiton.example"));
            unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            composer.build_unprotected(&cbor_data_countersignature_unprotected, unprotected_map);
        }

        constexpr char constexpr_signature[] =
            "00929663c8789bb28177ae28467e66377da12302d7f9594d2999afa5dfa531294f8896f2b6cdf1740014f4c7f1a358e3a6cf57f4ed6fb02fcf8f7aa989f5dfd07f0700a3a7d8f3c604"
            "ba70fa9411bd10c2591b483e1d2c31de003183e434d8fba18f17a4c7e3dfa003ac1cf3d30d44d2533c4989d3ac38c38b71481cc3430c9d65e7ddff";
        cbor_data* cbor_data_countersignature_signature = nullptr;
        composer.build_data_b16(&cbor_data_countersignature_signature, constexpr_signature);

        *countersign << cbor_data_countersignature_protected    // protected
                     << cbor_data_countersignature_unprotected  // unprotected
                     << cbor_data_countersignature_signature;   // signature
    }

    cbor_array* recipients = (cbor_array*)(*root)[3];
    {
        cbor_array* recipient = new cbor_array();

        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_ecdhes_hkdf_256);
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_recipient_protected, protected_map);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        composer.build_data_b16(&cbor_data_recipient_ciphertext, "");

        *recipient << cbor_data_recipient_protected    // protected
                   << new cbor_map()                   // unprotected
                   << cbor_data_recipient_ciphertext;  // ciphertext

        cbor_map* cbor_data_recipient_unprotected = (cbor_map*)(*recipient)[1];
        {
            constexpr char constexpr_x[] = "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280";
            constexpr char constexpr_kid[] = "meriadoc.brandybuck@buckland.example";
            cbor_map* ephemeral = new cbor_map();
            *ephemeral << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))    // kty
                       << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))  // crv
                       << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode(constexpr_x)))       // x
                       << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(true));                            // y

            *cbor_data_recipient_unprotected << new cbor_pair(cose_key_t::cose_ephemeral_key, ephemeral)                     // epk
                                             << new cbor_pair(cose_key_t::cose_kid, new cbor_data(convert(constexpr_kid)));  // kid
        }

        *recipients << recipient;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_3_3.cbor", "RFC 8152 C.3.3.  Counter Signature on Encrypted Content");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_4() {
    _test_case.begin("RFC 8152 C.3");

    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_encrypt);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_aes128gcm);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_binary_new(value, base16_decode("02d1f7e6f26c43d4868d87ce"));
        protected_map.insert(std::make_pair(cose_key_t::cose_iv, value));
        composer.build_unprotected(&cbor_data_unprotected, protected_map);
    }

    constexpr char constexpr_ciphertext[] = "64f84d913ba60a76070a9a48f26e97e863e28529d8f5335e5f0165eee976b4a5f6c6f09d";
    cbor_data* cbor_data_ciphertext = nullptr;
    composer.build_data_b16(&cbor_data_ciphertext, constexpr_ciphertext);

    *root << cbor_data_protected    // protected
          << cbor_data_unprotected  // unprotected
          << cbor_data_ciphertext   // ciphertext
          << new cbor_array();      // recipients

    cbor_array* recipients = (cbor_array*)(*root)[3];
    {
        cbor_array* recipient = new cbor_array();

        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_ecdhss_a128kw);
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_recipient_protected, protected_map);
        }

        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_variantmap_t protected_map;
            cose_orderlist_t order;
            order.push_back(cose_key_t::cose_static_key_id);
            order.push_back(cose_key_t::cose_kid);
            order.push_back(cose_key_t::cose_partyu_nonce);
            variant_set_binary_new(value, convert("peregrin.took@tuckborough.example"));
            protected_map.insert(std::make_pair(cose_key_t::cose_static_key_id, value));
            variant_set_binary_new(value, convert("meriadoc.brandybuck@buckland.example"));
            protected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            variant_set_binary_new(value, base16_decode("0101"));
            protected_map.insert(std::make_pair(cose_key_t::cose_partyu_nonce, value));
            composer.build_unprotected(&cbor_data_recipient_unprotected, protected_map, order);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        composer.build_data_b16(&cbor_data_recipient_ciphertext, "41e0d76f579dbd0d936a662d54d8582037de2e366fde1c62");

        *recipient << cbor_data_recipient_protected    // protected
                   << cbor_data_recipient_unprotected  // unprotected
                   << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }

    // Externally Supplied AAD: h'0011bbcc22dd44ee55ff660077'
    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    cose.set(cose_handle, cose_param_t::cose_external, base16_decode("0011bbcc22dd44ee55ff660077"));
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_3_4.cbor", "RFC 8152 C.3.4.  Encrypted Content with External Data");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_4_1() {
    _test_case.begin("RFC 8152 C.4");

    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_encrypt0);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_aesccm_16_64_128);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_binary_new(value, base16_decode("89f52f65a1c580933b5261a78c"));
        protected_map.insert(std::make_pair(cose_key_t::cose_iv, value));
        composer.build_unprotected(&cbor_data_unprotected, protected_map);
    }

    constexpr char constexpr_ciphertext[] = "5974e1b99a3a4cc09a659aa2e9e7fff161d38ce71cb45ce460ffb569";
    cbor_data* cbor_data_ciphertext = nullptr;
    composer.build_data_b16(&cbor_data_ciphertext, constexpr_ciphertext);

    *root << cbor_data_protected    // protected
          << cbor_data_unprotected  // unprotected
          << cbor_data_ciphertext;  // ciphertext

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys_c4, root, "rfc8152_c_4_1.cbor", "RFC 8152 C.4.1.  Simple Encrypted Message");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_4_2() {
    _test_case.begin("RFC 8152 C.4");

    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_encrypt0);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_aesccm_16_64_128);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_binary_new(value, base16_decode("61a7"));
        protected_map.insert(std::make_pair(cose_key_t::cose_partial_iv, value));
        composer.build_unprotected(&cbor_data_unprotected, protected_map);
    }

    constexpr char constexpr_ciphertext[] = "252a8911d465c125b6764739700f0141ed09192de139e053bd09abca";
    cbor_data* cbor_data_ciphertext = nullptr;
    composer.build_data_b16(&cbor_data_ciphertext, constexpr_ciphertext);

    *root << cbor_data_protected    // protected
          << cbor_data_unprotected  // unprotected
          << cbor_data_ciphertext;  // ciphertext

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    cose.set(cose_handle, cose_param_t::cose_unsent_iv, base16_decode("89F52F65A1C5809300000061A7"));
    test_cose_example(cose_handle, &rfc8152_privkeys_c4, root, "rfc8152_c_4_2.cbor", "RFC 8152 C.4.2.  Encrypted Message with a Partial IV");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_5_1() {
    _test_case.begin("RFC 8152 C.5");

    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_mac);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_aescmac_256_64);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    { composer.build_unprotected(&cbor_data_unprotected); }

    cbor_data* cbor_data_payload = nullptr;
    composer.build_data(&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_tag = nullptr;
    composer.build_data_b16(&cbor_data_tag, "9e1226ba1f81b848");

    *root << cbor_data_protected    // protected
          << cbor_data_unprotected  // unprotected
          << cbor_data_payload      // payload
          << cbor_data_tag          // tag
          << new cbor_array();      // recipients

    cbor_array* recipients = (cbor_array*)(*root)[4];
    {
        cbor_array* recipient = new cbor_array();

        cbor_data* cbor_data_recipient_protected = nullptr;
        { composer.build_protected(&cbor_data_recipient_protected); }

        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_variantmap_t unprotected_map;
            variant_set_int16(value, cose_alg_t::cose_direct);
            unprotected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            variant_set_binary_new(value, convert("our-secret"));
            unprotected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            composer.build_unprotected(&cbor_data_recipient_unprotected, unprotected_map);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        composer.build_data_b16(&cbor_data_recipient_ciphertext, "");

        *recipient << cbor_data_recipient_protected    // protected
                   << cbor_data_recipient_unprotected  // unprotected
                   << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_1.cbor", "RFC 8152 C.5.1.  Shared Secret Direct MAC");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_5_2() {
    _test_case.begin("RFC 8152 C.5");

    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_mac);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_hs256);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    { composer.build_unprotected(&cbor_data_unprotected); }

    cbor_data* cbor_data_payload = nullptr;
    composer.build_data(&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_tag = nullptr;
    composer.build_data_b16(&cbor_data_tag, "81a03448acd3d305376eaa11fb3fe416a955be2cbe7ec96f012c994bc3f16a41");

    *root << cbor_data_protected    // protected
          << cbor_data_unprotected  // unprotected
          << cbor_data_payload      // payload
          << cbor_data_tag          // tag
          << new cbor_array();      // recipients

    cbor_array* recipients = (cbor_array*)(*root)[4];
    {
        cbor_array* recipient = new cbor_array();

        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_ecdhss_hkdf_256);
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_recipient_protected, protected_map);
        }

        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_variantmap_t protected_map;
            cose_orderlist_t order;
            order.push_back(cose_key_t::cose_static_key_id);
            order.push_back(cose_key_t::cose_kid);
            order.push_back(cose_key_t::cose_partyu_nonce);
            variant_set_binary_new(value, convert("peregrin.took@tuckborough.example"));
            protected_map.insert(std::make_pair(cose_key_t::cose_static_key_id, value));
            variant_set_binary_new(value, convert("meriadoc.brandybuck@buckland.example"));
            protected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            variant_set_binary_new(
                value, base16_decode(
                           "4d8553e7e74f3c6a3a9dd3ef286a8195cbf8a23d19558ccfec7d34b824f42d92bd06bd2c7f0271f0214e141fb779ae2856abf585a58368b017e7f2a9e5ce4db5"));
            protected_map.insert(std::make_pair(cose_key_t::cose_partyu_nonce, value));
            composer.build_unprotected(&cbor_data_recipient_unprotected, protected_map, order);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        composer.build_data_b16(&cbor_data_recipient_ciphertext, "");

        *recipient << cbor_data_recipient_protected    // protected
                   << cbor_data_recipient_unprotected  // unprotected
                   << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_2.cbor", "RFC 8152 C.5.2.  ECDH Direct MAC");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_5_3() {
    _test_case.begin("RFC 8152 C.5");

    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_mac);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_aescmac_128_64);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    { composer.build_unprotected(&cbor_data_unprotected); }

    cbor_data* cbor_data_payload = nullptr;
    composer.build_data(&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_tag = nullptr;
    composer.build_data_b16(&cbor_data_tag, "36f5afaf0bab5d43");

    *root << cbor_data_protected    // protected
          << cbor_data_unprotected  // unprotected
          << cbor_data_payload      // payload
          << cbor_data_tag          // tag
          << new cbor_array();      // recipients

    cbor_array* recipients = (cbor_array*)(*root)[4];
    {
        cbor_array* recipient = new cbor_array();

        cbor_data* cbor_data_recipient_protected = nullptr;
        { composer.build_protected(&cbor_data_recipient_protected); }

        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_aes256kw);
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            variant_set_binary_new(value, convert("018c0ae5-4d9b-471b-bfd6-eef314bc7037"));
            protected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            composer.build_unprotected(&cbor_data_recipient_unprotected, protected_map);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        composer.build_data_b16(&cbor_data_recipient_ciphertext, "711ab0dc2fc4585dce27effa6781c8093eba906f227b6eb0");

        *recipient << cbor_data_recipient_protected    // protected
                   << cbor_data_recipient_unprotected  // unprotected
                   << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_3.cbor", "RFC 8152 C.5.3.  Wrapped MAC");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_5_4() {
    _test_case.begin("RFC 8152 C.5");

    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_mac);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_hs256);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    { composer.build_unprotected(&cbor_data_unprotected); }

    cbor_data* cbor_data_payload = nullptr;
    composer.build_data(&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_tag = nullptr;
    composer.build_data_b16(&cbor_data_tag, "bf48235e809b5c42e995f2b7d5fa13620e7ed834e337f6aa43df161e49e9323e");

    *root << cbor_data_protected    // protected
          << cbor_data_unprotected  // unprotected
          << cbor_data_payload      // payload
          << cbor_data_tag          // tag
          << new cbor_array();      // recipients

    cbor_array* recipients = (cbor_array*)(*root)[4];
    {
        cbor_array* recipient = new cbor_array();

        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_ecdhes_a128kw);
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            composer.build_protected(&cbor_data_recipient_protected, protected_map);
        }

        cbor_map* cbor_data_recipient_unprotected = new cbor_map();
        {
            constexpr char constexpr_x[] =
                "0043b12669acac3fd27898ffba0bcd2e6c366d53bc4db71f909a759304acfb5e18cdc7ba0b13ff8c7636271a6924b1ac63c02688075b55ef2d613574e7dc242f79c3";
            constexpr char constexpr_kid[] = "bilbo.baggins@hobbiton.example";
            cbor_map* ephemeral = new cbor_map();
            *ephemeral << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))    // kty
                       << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p521))  // crv
                       << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode(constexpr_x)))       // x
                       << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(true));                            // y

            *cbor_data_recipient_unprotected << new cbor_pair(cose_key_t::cose_ephemeral_key, ephemeral)                     // epk
                                             << new cbor_pair(cose_key_t::cose_kid, new cbor_data(convert(constexpr_kid)));  // kid
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        composer.build_data_b16(&cbor_data_recipient_ciphertext, "339bc4f79984cdc6b3e6ce5f315a4c7d2b0ac466fcea69e8c07dfbca5bb1f661bc5f8e0df9e3eff5");

        *recipient << cbor_data_recipient_protected    // protected
                   << cbor_data_recipient_unprotected  // unprotected
                   << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }
    {
        cbor_array* recipient = new cbor_array();

        cbor_data* cbor_data_recipient_protected = nullptr;
        { composer.build_protected(&cbor_data_recipient_protected); }

        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_variantmap_t protected_map;
            variant_set_int16(value, cose_alg_t::cose_aes256kw);
            protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
            variant_set_binary_new(value, convert("018c0ae5-4d9b-471b-bfd6-eef314bc7037"));
            protected_map.insert(std::make_pair(cose_key_t::cose_kid, value));
            composer.build_unprotected(&cbor_data_recipient_unprotected, protected_map);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        composer.build_data_b16(&cbor_data_recipient_ciphertext, "0b2c7cfce04e98276342d6476a7723c090dfdd15f9a518e7736549e998370695e6d6a83b4ae507bb");

        *recipient << cbor_data_recipient_protected    // protected
                   << cbor_data_recipient_unprotected  // unprotected
                   << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_4.cbor", "RFC 8152 C.5.4.  Multi-Recipient MACed Message");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_6_1() {
    _test_case.begin("RFC 8152 C.6");
    // C.6.1.  Shared Secret Direct MAC
    cbor_publisher publisher;
    variant_t value;

    cbor_object_signing_encryption::composer composer;

    cbor_array* root = new cbor_array();
    root->tag(true, cbor_tag_t::cose_tag_mac0);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_variantmap_t protected_map;
        variant_set_int16(value, cose_alg_t::cose_aescmac_256_64);
        protected_map.insert(std::make_pair(cose_key_t::cose_alg, value));
        composer.build_protected(&cbor_data_protected, protected_map);
    }

    cbor_data* cbor_data_payload = nullptr;
    composer.build_data(&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_tag = nullptr;
    composer.build_data_b16(&cbor_data_tag, "726043745027214f");

    *root << cbor_data_protected  // protected
          << new cbor_map()       // unprotected
          << cbor_data_payload    // payload
          << cbor_data_tag;       // tag

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_6_1.cbor", "RFC 8152 C.6.1.  Shared Secret Direct MAC");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_7_1() {
    _test_case.begin("RFC 8152 C.7");

    cbor_array* root = new cbor_array();
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")))
             << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(convert("meriadoc.brandybuck@buckland.example")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")))
             << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(convert("11")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key
            << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p521))
            << new cbor_pair(
                   cose_key_lable_t::cose_ec_x,
                   new cbor_data(base16_decode(
                       "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad")))
            << new cbor_pair(
                   cose_key_lable_t::cose_ec_y,
                   new cbor_data(base16_decode(
                       "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475")))
            << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
            << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(convert("bilbo.baggins@hobbiton.example")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb")))
             << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(convert("peregrin.took@tuckborough.example")));

        *root << key;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_7_1.cbor", "RFC 8152 C.7.1.  Public Keys");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_7_2() {
    _test_case.begin("RFC 8152 C.7");

    cbor_array* root = new cbor_array();
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(convert("meriadoc.brandybuck@buckland.example")))
             << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")))
             << new cbor_pair(cose_key_lable_t::cose_ec_d, new cbor_data(base16_decode("aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(convert("11")))
             << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")))
             << new cbor_pair(cose_key_lable_t::cose_ec_d, new cbor_data(base16_decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key
            << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
            << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(convert("bilbo.baggins@hobbiton.example")))
            << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p521))
            << new cbor_pair(
                   cose_key_lable_t::cose_ec_x,
                   new cbor_data(base16_decode(
                       "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad")))
            << new cbor_pair(
                   cose_key_lable_t::cose_ec_y,
                   new cbor_data(base16_decode(
                       "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475")))
            << new cbor_pair(cose_key_lable_t::cose_ec_d, new cbor_data(base16_decode("00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c"
                                                                                      "72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_symm))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(convert("our-secret")))
             << new cbor_pair(cose_key_lable_t::cose_symm_k, new cbor_data(base16_decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_ec2))
             << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(cose_ec_curve_t::cose_ec_p256))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(convert("peregrin.took@tuckborough.example")))
             << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(base16_decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")))
             << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(base16_decode("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb")))
             << new cbor_pair(cose_key_lable_t::cose_ec_d, new cbor_data(base16_decode("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_symm))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(convert("our-secret2")))
             << new cbor_pair(cose_key_lable_t::cose_symm_k, new cbor_data(base16_decode("849b5786457c1491be3a76dcea6c4271")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map();

        *key << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(cose_kty_t::cose_kty_symm))
             << new cbor_pair(cose_key_lable_t::cose_lable_kid, new cbor_data(convert("018c0ae5-4d9b-471b-bfd6-eef314bc7037")))
             << new cbor_pair(cose_key_lable_t::cose_symm_k, new cbor_data(base16_decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188")));

        *root << key;
    }

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_7_2.cbor", "RFC 8152 C.7.2.  Private Keys");
    cose.close(cose_handle);

    root->release();
}

void test_cbor_key(const char* file, const char* text) {
    _test_case.begin("CBOR encoded keys - order not guaranteed");
    return_t ret = errorcode_t::success;
    crypto_key key;
    cbor_web_key cwk;

    binary_t cbor;
    file_stream fs;

    ret = fs.open(file);
    if (errorcode_t::success == ret) {
        fs.begin_mmap();

        byte_t* file_contents = fs.data();
        size_t file_size = fs.size();
        cbor.insert(cbor.end(), file_contents, file_contents + file_size);

        ret = cwk.load(&key, cbor);
        key.for_each(dump_crypto_key, nullptr);
        _test_case.test(ret, __FUNCTION__, "step.load %s", text ? text : "");

        binary_t cbor_written;
        ret = cwk.write(&key, cbor_written);
        _test_case.test(ret, __FUNCTION__, "step.write %s", text ? text : "");

        if (1) {
            test_case_notimecheck notimecheck(_test_case);

            basic_stream bs;
            dump_memory(cbor, &bs, 32);
            std::cout << "from file" << std::endl << bs.c_str() << std::endl;
            dump_memory(cbor_written, &bs, 32);
            std::cout << "from cwk" << std::endl << bs.c_str() << std::endl;

            basic_stream diagnostic;
            cbor_reader reader;
            cbor_reader_context_t* handle = nullptr;

            reader.open(&handle);
            reader.parse(handle, cbor);
            reader.publish(handle, &diagnostic);
            std::cout << "from file" << std::endl << diagnostic.c_str() << std::endl;

            reader.parse(handle, cbor_written);
            reader.publish(handle, &diagnostic);
            std::cout << "from cwk" << std::endl << diagnostic.c_str() << std::endl;

            reader.close(handle);
        }
    }
    _test_case.test(ret, __FUNCTION__, text ? text : "");
}

void test_rfc8152_read_cbor() {
    test_cbor_file("rfc8152_b.cbor", "RFC 8152 Appendix B.  Two Layers of Recipient Information");
    test_cbor_file("rfc8152_c_1_1.cbor", "RFC 8152 C.1.1.  Single Signature");
    test_cbor_file("rfc8152_c_1_2.cbor", "RFC 8152 C.1.2.  Multiple Signers");
    test_cbor_file("rfc8152_c_1_3.cbor", "RFC 8152 C.1.3.  Counter Signature");
    test_cbor_file("rfc8152_c_1_4.cbor", "RFC 8152 C.1.4.  Signature with Criticality");
    test_cbor_file("rfc8152_c_2_1.cbor", "RFC 8152 C.2.1.  Single ECDSA Signature");
    test_cbor_file("rfc8152_c_3_1.cbor", "RFC 8152 C.3.1.  Direct ECDH");
    test_cbor_file("rfc8152_c_3_2.cbor", "RFC 8152 C.3.2.  Direct Plus Key Derivation");
    test_cbor_file("rfc8152_c_3_3.cbor", "RFC 8152 C.3.3.  Counter Signature on Encrypted Content");
    test_cbor_file("rfc8152_c_3_4.cbor", "RFC 8152 C.3.4.  Encrypted Content with External Data");
    test_cbor_file("rfc8152_c_4_1.cbor", "RFC 8152 C.4.1.  Simple Encrypted Message");
    test_cbor_file("rfc8152_c_4_2.cbor", "RFC 8152 C.4.2.  Encrypted Message with a Partial IV");
    test_cbor_file("rfc8152_c_5_1.cbor", "RFC 8152 C.5.1.  Shared Secret Direct MAC");
    test_cbor_file("rfc8152_c_5_2.cbor", "RFC 8152 C.5.2.  ECDH Direct MAC");
    test_cbor_file("rfc8152_c_5_3.cbor", "RFC 8152 C.5.3.  Wrapped MAC");
    test_cbor_file("rfc8152_c_5_4.cbor", "RFC 8152 C.5.4.  Multi-Recipient MACed Message");
    test_cbor_file("rfc8152_c_6_1.cbor", "RFC 8152 C.6.1.  Shared Secret Direct MAC");
    test_cbor_file("rfc8152_c_7_1.cbor", "RFC 8152 C.7.1.  Public Keys");
    test_cbor_file("rfc8152_c_7_2.cbor", "RFC 8152 C.7.2.  Private Keys");
    test_cbor_file("rfc8778_a_1.cbor", "RFC 8778 A.1.  Example COSE Full Message Signature");
    test_cbor_file("rfc8778_a_2.cbor", "RFC 8778 A.2.  Example COSE_Sign1 Message");
    test_cbor_file("rfc9338_a_1_1.cbor", "RFC 9338 A.1.1.  Countersignature");
    test_cbor_file("rfc9338_a_2_1.cbor", "RFC 9338 A.2.1.  Countersignature");
    test_cbor_file("rfc9338_a_3_1.cbor", "RFC 9338 A.3.1.  Countersignature on Encrypted Content");
    test_cbor_file("rfc9338_a_4_1.cbor", "RFC 9338 A.4.1.  Countersignature on Encrypted Content");
    test_cbor_file("rfc9338_a_5_1.cbor", "RFC 9338 A.5.1.  Countersignature on MAC Content");
    test_cbor_file("rfc9338_a_6_1.cbor", "RFC 9338 A.6.1.  Countersignature on MAC0 Content");  // typo ? not 159 bytes, but 139 bytes
    test_cbor_key("rfc8152_c_7_1.cbor", "RFC 8152 C.7.1.  Public Keys");
    test_cbor_key("rfc8152_c_7_2.cbor", "RFC 8152 C.7.2.  Private Keys");
}

void test_jose_from_cwk() {
    _test_case.begin("crypto_key");

    // load keys from CBOR
    cbor_web_key cwk;
    crypto_key pubkey;
    cwk.load_file(&pubkey, "rfc8152_c_7_1.cbor");
    pubkey.for_each(dump_crypto_key, nullptr);
    crypto_key privkey;
    cwk.load_file(&privkey, "rfc8152_c_7_2.cbor");
    privkey.for_each(dump_crypto_key, nullptr);

    // dump keys JWK formatted
    json_web_key jwk;
    size_t size = 0;
    basic_stream json;
    jwk.write(&privkey, &json, 1);
    printf("JWK from CBOR key\n%s\n", json.c_str());
    basic_stream pem;
    jwk.write_pem(&pubkey, &pem);
    printf("PEM (public)\n%s\n", pem.c_str());
    jwk.write_pem(&privkey, &pem);
    printf("PEM (private)\n%s\n", pem.c_str());

    EVP_PKEY* pkey = nullptr;
    std::string kid;
    pkey = privkey.select(kid, crypt_sig_t::sig_es512);
    _test_case.assert(kid == "bilbo.baggins@hobbiton.example", __FUNCTION__, "select key from CWK where type is es512");
    pkey = privkey.select(kid, crypt_sig_t::sig_es256);
    _test_case.assert(kid == "11", __FUNCTION__, "select key from CWK where type is es256");  // alphabetic order...

    _test_case.reset_time();

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    cbor_object_signing_encryption cose;
    cose_context_t* handle = nullptr;
    binary_t signature;
    basic_stream bs;
    bool result = true;
    constexpr char input[] = "wild wild world";
    cose.open(&handle);
    std::list<cose_alg_t> algs;
    algs.push_back(cose_alg_t::cose_es256);
    algs.push_back(cose_alg_t::cose_es512);
    ret = cose.sign(handle, &privkey, algs, convert(input), signature);
    _test_case.test(ret, __FUNCTION__, "sign");
    {
        test_case_notimecheck notimecheck(_test_case);

        dump_memory(signature, &bs);
        printf("signature\n%s\n", bs.c_str());
        printf("cbor\n%s\n", base16_encode(signature).c_str());

        basic_stream diagnostic;
        cbor_reader reader;
        cbor_reader_context_t* reader_handle = nullptr;
        reader.open(&reader_handle);
        reader.parse(reader_handle, signature);
        reader.publish(reader_handle, &diagnostic);
        reader.close(reader_handle);
        printf("diagnostic\n%s\n", diagnostic.c_str());
    }
    ret = cose.verify(handle, &pubkey, signature, result);
    _test_case.test(ret, __FUNCTION__, "verify");
    cose.close(handle);
}

void test_github_example() {
    _test_case.begin("https://github.com/cose-wg/Examples");

    cbor_web_key cwk;
    crypto_key key;
    cwk.add_ec_b64u(&key, "11", nullptr, "P-256", "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8", "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                    "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM");
    cwk.add_ec_b64u(&key, "P384", nullptr, "P-384", "kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc",
                    "mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s", "ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo");
    cwk.add_ec_b64u(&key, "bilbo.baggins@hobbiton.example", "ES512", "P-521",
                    "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
                    "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
                    "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt");
    cwk.add_ec_b16(&key, "11", "EdDSA", "Ed25519", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                   "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    cwk.add_ec_b16(&key, "ed448", "EdDSA", "Ed448",
                   "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180", "",
                   "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
    cwk.add_ec_b16(&key, "Alice Lovelace", "ES256", "P-256", "863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c",
                   "ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca", "d42044eb2cd2691e926da4871cf3529ddec6b034f824ba5e050d2c702f97c7a5");
    cwk.add_ec_b64u(&key, "meriadoc.brandybuck@buckland.example", nullptr, "P-256", "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                    "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw", "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8");
    cwk.add_ec_b64u(&key, "peregrin.took@tuckborough.example", nullptr, "P-256", "mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA",
                    "8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs", "AtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cM");
    cwk.add_ec_b16(&key, "X25519-1", "EdDSA", "X25519", "7FFE91F5F932DAE92BE603F55FAC0F4C4C9328906EE550EDCB7F6F7626EBC07E", "",
                   "00a943daa2e38b2edbf0da0434eaaec6016fe25dcd5ecacbc07dc30300567655");
    cwk.add_ec_b16(&key, "X25519-bob", "EdDSA", "X25519", "DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F", "",
                   "58AB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E06B");
    cwk.add_ec_b16(&key, "X25519-alice", "EdDSA", "X25519", "8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A", "",
                   "70076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C6A");

    cwk.add_oct_b64u(&key, "our-secret", nullptr, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", crypto_use_t::use_enc);
    cwk.add_oct_b64u(&key, "sec-48", nullptr, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJico", crypto_use_t::use_enc);
    cwk.add_oct_b64u(&key, "sec-64", nullptr, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJicoqrvM3e7_paanqKmgsbKztA", crypto_use_t::use_enc);
    cwk.add_rsa_b16(&key, "meriadoc.brandybuck@rsa.example", nullptr,
                    "BC7E29D0DF7E20CC9DC8D509E0F68895922AF0EF452190D402C61B554334A7BF91C9A570240F994FAE1B69035BCFAD4F7E249EB26087C2665E7C958C967B1517413DC3F97A"
                    "431691A5999B257CC6CD356BAD168D929B8BAE9020750E74CF60F6FD35D6BB3FC93FC28900478694F508B33E7C00E24F90EDF37457FC3E8EFCFD2F42306301A8205AB74051"
                    "5331D5C18F0C64D4A43BE52FC440400F6BFC558A6E32884C2AF56F29E5C52780CEA7285F5C057FC0DFDA232D0ADA681B01495D9D0E32196633588E289E59035FF664F05618"
                    "9F2F10FE05827B796C326E3E748FFA7C589ED273C9C43436CDDB4A6A22523EF8BCB2221615B799966F1ABA5BC84B7A27CF",
                    "010001",
                    "0969FF04FCC1E1647C20402CF3F736D4CAE33F264C1C6EE3252CFCC77CDEF533D700570AC09A50D7646EDFB1F86A13BCABCF00BD659F27813D08843597271838BC46ED4743"
                    "FE741D9BC38E0BF36D406981C7B81FCE54861CEBFB85AD23A8B4833C1BEE18C05E4E436A869636980646EECB839E4DAF434C9C6DFBF3A55CE1DB73E4902F89384BD6F9ECD3"
                    "399FB1ED4B83F28D356C8E619F1F0DC96BBE8B75C1812CA58F360259EAEB1D17130C3C0A2715A99BE49898E871F6088A29570DC2FFA0CEFFFA27F1F055CBAABFD8894E0CC2"
                    "4F176E34EBAD32278A466F8A34A685ACC8207D9EC1FCBBD094996DC73C6305FCA31668BE57B1699D0BB456CC8871BFFBCD");

    crypto_key ecdh_wrap_p256_key;
    cwk.add_ec_b64u(&ecdh_wrap_p256_key, "meriadoc.brandybuck@buckland.example", nullptr, "P-256", "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                    "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw", "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8");
    crypto_key ecdh_wrap_p521_key;
    cwk.add_ec_b64u(&ecdh_wrap_p521_key, "meriadoc.brandybuck@buckland.example", "ES512", "P-521",
                    "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
                    "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
                    "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt");

    crypto_key aes_ccm_key;
    cwk.add_oct_b64u(&aes_ccm_key, "our-secret", nullptr, "hJtXIZ2uSN5kbQfbtTNWbg", crypto_use_t::use_enc);
    cwk.add_oct_b64u(&aes_ccm_key, "sec-256", nullptr, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA", crypto_use_t::use_enc);
    cwk.add_oct_b64u(&aes_ccm_key, "sec-192", nullptr, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmI", crypto_use_t::use_enc);
    cwk.add_oct_b64u(&aes_ccm_key, "sec-64", nullptr, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJicoqrvM3e7_paanqKmgsbKztA",
                     crypto_use_t::use_enc);
    cwk.add_oct_b64u(&aes_ccm_key, "sec-48", nullptr, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJico", crypto_use_t::use_enc);
    cwk.add_oct_b64u(&aes_ccm_key, "018c0ae5-4d9b-471b-bfd6-eef314bc7037", nullptr, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", crypto_use_t::use_enc);

    crypto_key aes_ccm_05_key;
    cwk.add_oct_b64u(&aes_ccm_05_key, "our-secret", nullptr, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA", crypto_use_t::use_enc);

    crypto_key aes_gcm_02_key;
    cwk.add_oct_b64u(&aes_gcm_02_key, "sec-48", nullptr, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmI", crypto_use_t::use_enc);
    crypto_key aes_gcm_03_key;
    cwk.add_oct_b64u(&aes_gcm_03_key, "sec-64", nullptr, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA", crypto_use_t::use_enc);
    crypto_key aes_gcm_04_key;
    cwk.add_oct_b64u(&aes_gcm_04_key, "our-secret", nullptr, "hJtXIZ2uSN5kbQfbtTNWbg", crypto_use_t::use_enc);

    crypto_key cwtkey;
    cwk.add_ec_b16(&cwtkey, nullptr, "ES256", "P-256", "143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f",
                   "60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9", "6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19");
    cwk.add_oct_b16(&cwtkey, "our-secret", nullptr, "231f4c4d4d3051fdc2ec0a3851d5b383");

    struct {
        crypto_key* key;
        const char* file;
        const char* cbor;
        struct {
            const char* external;
            const char* iv_hex;
            const char* apu_id;
            const char* apu_nonce;
            const char* apu_other;
            const char* apv_id;
            const char* apv_nonce;
            const char* apv_other;
            const char* pub_other;
            const char* priv;
        } shared;
        struct {
            const char* aad_hex;
            const char* cek_hex;
            const char* tomac_hex;
        } enc;
        int debug;
    } vector[] = {
        // aes-ccm-examples
        {
            &aes_ccm_key,
            "aes-ccm-examples/aes-ccm-01.json",
            "D8608443A1010AA1054D89F52F65A1C580933B5261A72F581C6899DA0A132BD2D2B9B10915743EE1F7B92A46802388816C040275EE818340A20125044A6F75722D73656372657440",
        },
        {
            &aes_ccm_key,
            "aes-ccm-examples/aes-ccm-02.json",
            "D8608444A101181EA1054D89F52F65A1C580933B5261A72F58246899DA0A132BD2D2B9B10915743EE1F7B92A46801D3D61B6E7C964520652F9D3C8347E8A818340A20125044A6F7572"
            "2D73656372657440",
        },
        {
            &aes_ccm_key,
            "aes-ccm-examples/aes-ccm-03.json",
            "D8608443A1010CA1054789F52F65A1C580581C191BD858DEC79FC11DA3428BDFA446AC240D591F9F0F25E3A3FA4E6C818340A20125044A6F75722D73656372657440",
        },
        {
            &aes_ccm_key,
            "aes-ccm-examples/aes-ccm-04.json",
            "D8608444A1011820A1054789F52F65A1C5805824191BD858DEC79FC11DA3428BDFA446AC240D591F59482AEA4157167842D7BF5EDD68EC92818340A20125044A6F75722D7365637265"
            "7440",
        },
        {
            &aes_ccm_05_key,
            "aes-ccm-examples/aes-ccm-05.json",
            "D8608443A1010BA1054D89F52F65A1C580933B5261A72F581C28B3BDDFF844A736C5F0EE0F8C691FD0B7ADF917A8A3EF3313D6D332818340A20125044A6F75722D73656372657440",
        },
        {
            &aes_ccm_05_key,
            "aes-ccm-examples/aes-ccm-06.json",
            "D8608444A101181FA1054D89F52F65A1C580933B5261A72F582428B3BDDFF844A736C5F0EE0F8C691FD0B7ADF917348CDDC1FD07F3653AD991F9DFB65D50818340A20125044A6F7572"
            "2D73656372657440",
        },
        {
            &aes_ccm_05_key,
            "aes-ccm-examples/aes-ccm-07.json",
            "D8608443A1010DA1054789F52F65A1C580581C721908D60812806F2660054238E931ADB575771EE26C547EC3DE06C5818340A20125044A6F75722D73656372657440",
        },
        {
            &aes_ccm_05_key,
            "aes-ccm-examples/aes-ccm-08.json",
            "D8608444A1011821A1054789F52F65A1C5805824721908D60812806F2660054238E931ADB575771EB58752E5F0FB62A828917386A770CE9C818340A20125044A6F75722D7365637265"
            "7440",
        },
        {
            &aes_ccm_key,
            "aes-ccm-examples/aes-ccm-enc-01.json",
            "D08343A1010AA1054D89F52F65A1C580933B5261A72F581C6899DA0A132BD2D2B9B10915743EE1F7B92A4680E7C51BDBC1B320EA",
        },
        {
            &aes_ccm_key,
            "aes-ccm-examples/aes-ccm-enc-02.json",
            "D08344A101181EA1054D89F52F65A1C580933B5261A72F58246899DA0A132BD2D2B9B10915743EE1F7B92A4680903F2C00D37E14D4EBDC7EF2C03CF5A9",
        },
        {
            &aes_ccm_key,
            "aes-ccm-examples/aes-ccm-enc-03.json",
            "D08343A1010CA1054789F52F65A1C580581C191BD858DEC79FC11DA3428BDFA446AC240D591FFCF91EEB8035F87A",
        },
        {
            &aes_ccm_key,
            "aes-ccm-examples/aes-ccm-enc-04.json",
            "D08344A1011820A1054789F52F65A1C5805824191BD858DEC79FC11DA3428BDFA446AC240D591F3965FA7CA156FE666BC262807DF0EE99",
        },
        {
            &aes_ccm_05_key,
            "aes-ccm-examples/aes-ccm-enc-05.json",
            "D08343A1010BA1054D89F52F65A1C580933B5261A72F581C28B3BDDFF844A736C5F0EE0F8C691FD0B7ADF9173140CB621DF47C2F",
        },
        {
            &aes_ccm_05_key,
            "aes-ccm-examples/aes-ccm-enc-06.json",
            "D08344A101181FA1054D89F52F65A1C580933B5261A72F582428B3BDDFF844A736C5F0EE0F8C691FD0B7ADF917B0CFA0D187C769A4BA100372A585BCCC",
        },
        {
            &aes_ccm_05_key,
            "aes-ccm-examples/aes-ccm-enc-07.json",
            "D08343A1010DA1054789F52F65A1C580581C721908D60812806F2660054238E931ADB575771E9BC42FF530BAEB00",
        },
        {
            &aes_ccm_05_key,
            "aes-ccm-examples/aes-ccm-enc-08.json",
            "D08344A1011821A1054789F52F65A1C5805824721908D60812806F2660054238E931ADB575771E723C6FFD415A07CDB9FA9CEECC6C81FC",
        },
        // aes-gcm-examples
        {
            &aes_ccm_key,
            "aes-gcm-examples/aes-gcm-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A20125044A6F75722D73"
            "656372657440",
        },
        {
            &aes_gcm_02_key,
            "aes-gcm-examples/aes-gcm-02.json",
            "D8608443A10102A1054C02D1F7E6F26C43D4868D87CE5824134D3B9223A00C1552C77585C157F467F295919D12124F19F521484C0725410947B4D1CA818340A2012504467365632D34"
            "3840",
        },
        {
            &aes_gcm_03_key,
            "aes-gcm-examples/aes-gcm-03.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE58249D64A5A59A3B04867DCCF6B8EF82F7D1A3B25EF862B6EDDB29DF2EF16582172E5B5FC757818340A2012504467365632D36"
            "3440",
        },
#if 0
        {
            &aes_gcm_04_key,
            "aes-gcm-examples/aes-gcm-04.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FD818340A20125044A6F75722D73"
            "656372657440",
        },
#endif
        {
            &aes_gcm_04_key,
            "aes-gcm-examples/aes-gcm-05.json",
            "D8608443A10101A1064261A75824D3D893DFF22BDCF09A58CBBE701371AEE31EE0AA3C1C8A6CE8409D5E5E81A6B5C355A644818340A20125044A6F75722D73656372657440",
            {
                nullptr,
                "89F52F65A1C58093000061A7",  // IV
            },
        },
        {
            &aes_gcm_04_key,
            "aes-gcm-examples/aes-gcm-enc-01.json",
            "D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A",
        },
        {
            &aes_gcm_02_key,
            "aes-gcm-examples/aes-gcm-enc-02.json",
            "D08343A10102A1054C02D1F7E6F26C43D4868D87CE5824134D3B9223A00C1552C77585C157F467F295919D530FBE21F7689AB3CD4D18FFE8E17CEB",
        },
        {
            &aes_ccm_05_key,
            "aes-gcm-examples/aes-gcm-enc-03.json",
            "D08343A10103A1054C02D1F7E6F26C43D4868D87CE58249D64A5A59A3B04867DCCF6B8EF82F7D1A3B25EF84ECA2BC5D7593A96E943859A9CC24AD3",
        },
#if 0
        {
            &aes_gcm_04_key,
            "aes-gcm-examples/aes-gcm-enc-04.json",
            "D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250B",
        },
#endif
        // aes-wrap-examples
        {
            &aes_gcm_04_key,
            "aes-wrap-examples/aes-wrap-128-01.json",
            "D8618543A1010EA054546869732069732074686520636F6E74656E742E4836F5AFAF0BAB5D43818340A20122044A6F75722D73656372657458182F8A3D2AA397D3D5C40AAF9F6656BA"
            "FA5DB714EF925B72BC",
        },
        {
            &aes_gcm_04_key,
            "aes-wrap-examples/aes-wrap-128-02.json",
            "D8618543A1010FA054546869732069732074686520636F6E74656E742E48BC099BCBDB51AF62818340A20122044A6F75722D7365637265745828CBF83C6935F064FAA9681ACFC3936D"
            "8A6CE1AB64777D581ACA4BBBFEC3C32206A63056C993C6E609",
        },
        {
            &aes_gcm_04_key,
            "aes-wrap-examples/aes-wrap-128-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E58400021C21B2A7FADB677DAB64389B3FDA4AAC892D5C81B786A459E4182104A1501462FFD471422AF4D48BE"
            "EB864951D5947A55E3155E670DFC4A96017B0FD0E725818340A20122044A6F75722D7365637265745848792C46CE0BC689747133FA0DB1F5E2BC4DAAE22F906E93DFCA2DF44F0DF6C2"
            "CEF16EA8FC91D52AD662C4B49DD0D689E1086EC754347957F80F95C92C887521641B8F637D91C6E258",
        },
        {
            &aes_gcm_04_key,
            "aes-wrap-examples/aes-wrap-128-04.json",
            "D8608443A10101A1054CDDDC08972DF9BE62855291A158246F5556D71834CD1BD3FDCBFFF28CFA0F7D598C138D23B40C225AF5E3F2096A46C766813D818340A20122044A6F75722D73"
            "65637265745818112872F405A5AC48A2EDE46AC20E93E3D3A38B9762D0A3E8",
        },
        {
            &aes_gcm_04_key,
            "aes-wrap-examples/aes-wrap-128-05.json",
            "D8608443A10102A1054CDDDC08972DF9BE62855291A158243CA8EE3F7927A730BC9DBD6FA3070764F6F6319CF2C31FBDA4C288F19CF6F064C8B32E28818340A20122044A6F75722D73"
            "6563726574582023A276FE917EF97D9D60E1732C02E6B7E5820C2FD2712DE9E36000F74559BC38",
        },
        {
            &aes_ccm_key,
            "aes-wrap-examples/aes-wrap-192-01.json",
            "D8618543A1010EA054546869732069732074686520636F6E74656E742E4836F5AFAF0BAB5D43818340A2012304477365632D31393258180C60CBB6DB490AF990714848D249FB599A3E"
            "2F23B18FF29E",
        },
        {
            &aes_ccm_key,
            "aes-wrap-examples/aes-wrap-192-02.json",
            "D8618543A1010FA054546869732069732074686520636F6E74656E742E486DDE04729881CDFF818340A2012304477365632D3139325828C3F9C4CB155D284187E84C34BAD08FD89E72"
            "63C093166DCC63723A94E08F97E6601F397360BBD114",
        },
        {
            &aes_ccm_key,
            "aes-wrap-examples/aes-wrap-192-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E58408FED1AF0EFC73BE97B81A2A2E0BE2889AA2C28DED89F757B25E871C55763820B789F1E433AA0D13F9C02"
            "62E7122B4BDF97625C2419B534EFBABCE51083E9AEE8818340A2012304477365632D313932584826A1A368150DE3754AF57307F76A67CE9B6AE1FFD4C8D168C4B84FB85D9A12FEED7F"
            "8E0FF0BB1470AB58DF9559BA5623D59C49C75311EF3AAD3FB332B82CABE3FCC0FCC4EF551D07",
        },
        {
            &aes_ccm_key,
            "aes-wrap-examples/aes-wrap-192-04.json",
            "D8608443A10101A1054CDDDC08972DF9BE62855291A158245E26B474F941D1223ADF75D9F970D608278AADF1EC0558EF4C5A9DF55732BA901BD631FF818340A2012304477365632D31"
            "393258184677A7C41F33EC27E8489AFBA06249A649F01F06496DC414",
        },
        {
            &aes_ccm_key,
            "aes-wrap-examples/aes-wrap-192-05.json",
            "D8608443A10102A1054CDDDC08972DF9BE62855291A1582400D06F278ECC3678D93CC906845F1E5A849AF95C0EEC22DACFA2FEA27AC14BA9031D355F818340A2012304477365632D31"
            "39325820D34FF57DBD52928650AC54D71BFA9D9530494860EF97E977A0D8F0DDD133E08C",
        },
        {
            &aes_ccm_key,
            "aes-wrap-examples/aes-wrap-256-01.json",
            "D8618543A1010EA054546869732069732074686520636F6E74656E742E4836F5AFAF0BAB5D43818340A2012404582430313863306165352D346439622D343731622D626664362D6565"
            "663331346263373033375818711AB0DC2FC4585DCE27EFFA6781C8093EBA906F227B6EB0",
        },
        {
            &aes_ccm_key,
            "aes-wrap-examples/aes-wrap-256-02.json",
            "D8618543A1010FA054546869732069732074686520636F6E74656E742E48804E3B7905594750818340A2012404582430313863306165352D346439622D343731622D626664362D6565"
            "6633313462633730333758287AEE8261238880308251A7231533135CB0C9AE8B4EC79E77C43452BFD523569BE49393145DCC8615",
        },
        {
            &aes_ccm_key,
            "aes-wrap-examples/aes-wrap-256-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E58404336C9B446AC3B1A062A719CBF5AF19F9DAC88BE743DC9102D9B0185C9EEBD0134AAE137C0E79A5F4326"
            "7FADDC6EE3FFA277157F26390DB9EE6ADA88CC952139818340A2012404582430313863306165352D346439622D343731622D626664362D65656633313462633730333758483FBB60F8"
            "82C1523A8B7768CA0C48920425A3CC47935F0D7FD4980020E378EAB85210D97B557B891EEC70785DB812C57DF719F064540ED84D5C93C8765095E422DDBCEF290D86633D",
        },
        {
            &aes_ccm_key,
            "aes-wrap-examples/aes-wrap-256-04.json",
            "D8608443A10101A1054CDDDC08972DF9BE62855291A1582470C0A7FEEA2254DD2C301963DAF77580EE31F7C4125246D436EB205B58AEFB5140DFDF51818340A2012404582430313863"
            "306165352D346439622D343731622D626664362D6565663331346263373033375818DC4725A1E6FE212C3B2C268954C97E7422D4B85E6E131D72",
        },
        {
            &aes_ccm_key,
            "aes-wrap-examples/aes-wrap-256-05.json",
            "D8608443A10102A1054CDDDC08972DF9BE62855291A1582456469FC7CA43E0F7F1970156D7D3C5EDAE33915C6DDFC0D2AC38AC13C3D00818E806D9C9818340A2012404582430313863"
            "306165352D346439622D343731622D626664362D6565663331346263373033375820E23608D3E444847B45BD6FEBFF3CC83C5C0769E65D441CCEF0B70C09121A79F6",
        },
        // cbc-mac-examples
        {
            &key,
            "cbc-mac-examples/cbc-mac-01.json",
            "D8618543A1010EA054546869732069732074686520636F6E74656E742E48C1CA820E6E247089818340A20125044A6F75722D73656372657440",
        },
        {
            &key,
            "cbc-mac-examples/cbc-mac-enc-01.json",
            "D18443A1010EA054546869732069732074686520636F6E74656E742E488584DBF007FDC69F",
        },
        // chacha-poly-examples
        {
            &aes_ccm_key,
            "chacha-poly-examples/chacha-poly-01.json",
            "D8608444A1011818A1054C26682306D4FB28CA01B43B8058245F2BD5381BBB04921A8477E55C0D850069674A05E683D416583AA0CEE0E2929CDF648094818340A2012504477365632D"
            "32353640",
        },
        {
            &aes_ccm_key,
            "chacha-poly-examples/chacha-poly-enc-01.json",
            "D08344A1011818A1054C5C3A9950BD2852F66E6C8D4F58243E536D4992A21591575C55FA22981B31AE1C045946D0E41A8A1ABD12BC9525922F4EB618",
        },
        // countersign
        {
            &key,
            "countersign/Encrypt-01.json",
            "D08343A10101A2054C02D1F7E6F26C43D4868D87CE078343A10127A1044231315840E10439154CC75C7A3A5391491F88651E0292FD0FE0E02CF740547EAF6677B4A4040B8ECA16DB59"
            "2881262F77B14C1A086C02268B17171CA16BE4B8595F8C0A08582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A",
        },
        {
            &key,
            "countersign/Encrypt-02.json",
            "D08343A10101A2054C02D1F7E6F26C43D4868D87CE07828343A10127A1044231315840E10439154CC75C7A3A5391491F88651E0292FD0FE0E02CF740547EAF6677B4A4040B8ECA16DB"
            "592881262F77B14C1A086C02268B17171CA16BE4B8595F8C0A088343A10126A1044231315840FCA98ECAC80B5FEB3AC7C108B2B79110DE88867BC0426FC83C53CCD6789694EDC5FEE3"
            "C40DE8E7B44FE8AAD367E095C8FC31B79EE666DF9CF90906EB43756C73582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A",
        },
        {
            &key,
            "countersign/Enveloped-01.json",
            "D8608443A10101A2054C02D1F7E6F26C43D4868D87CE078343A10127A10442313158409A8EEDE3B3CB837BA00DF08FA21B128B2D6D9162A4290A582D9F19BD0FB502F0F92B9BF453A4"
            "05401F8B7055EF4E958DF7F4FBD7CFB4A0C97160F9472B0AA104582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A20125044A6F"
            "75722D73656372657440",
        },
        {
            &key,
            "countersign/Enveloped-02.json",
            "D8608443A10101A2054C02D1F7E6F26C43D4868D87CE07828343A10127A10442313158409A8EEDE3B3CB837BA00DF08FA21B128B2D6D9162A4290A582D9F19BD0FB502F0F92B9BF453"
            "A405401F8B7055EF4E958DF7F4FBD7CFB4A0C97160F9472B0AA1048343A10126A10442313158402427CB3756850FBB79051807C8B23D2E6D16A3224F9901B47399CFC7E3FAC4CC621D"
            "BBEB0202A6D8BB25695C9DCC9C474920FF57606D764DEA192FC8674116F2582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A201"
            "25044A6F75722D73656372657440",
        },
        {
            &key,
            "countersign/Enveloped-03.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A30125044A6F75722D73"
            "6563726574078343A10127A1044231315840CCB1F3FEDFCEA72B9C867963E252B6658AD07F3F5F15A326A3F57254CCB8D48D60021D2F1F8A803B844B7872166C6D459025D21C8C8462"
            "A244BA19604EC4D50B40",
        },
        {
            &key,
            "countersign/mac0-01.json",
            "D18443A10105A1078343A10127A1044231315840B4924B18EB4E047313C707B0EDA4AB844345F2C44987D6F9EBCC777EFD4078CC0F4C108DEF959F78F1EDB2765425785FCD17D512BE"
            "31EEB66BEFF1E8FC27470754546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58",
        },
        {
            &key,
            "countersign/mac0-02.json",
            "D18443A10105A107828343A10127A1044231315840B4924B18EB4E047313C707B0EDA4AB844345F2C44987D6F9EBCC777EFD4078CC0F4C108DEF959F78F1EDB2765425785FCD17D512"
            "BE31EEB66BEFF1E8FC2747078343A10126A10442313158406ACD94D3CCF71D192E8528360BA7E346DAC464E9EDCA4CFEB6CEB6BDE7BAEC9FF26CA6BDF73D0BE41E36129DCFF751DD2B"
            "5AD5CE116E8A963A2738A299477A6854546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58",
        },
        {
            &key,
            "countersign/mac-01.json",
            "D8618543A10105A1078343A10127A1044231315840B4924B18EB4E047313C707B0EDA4AB844345F2C44987D6F9EBCC777EFD4078CC0F4C108DEF959F78F1EDB2765425785FCD17D512"
            "BE31EEB66BEFF1E8FC27470754546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6818340A20125"
            "044A6F75722D73656372657440",
        },
        {
            &key,
            "countersign/mac-02.json",
            "D8618543A10105A107828343A10127A1044231315840B4924B18EB4E047313C707B0EDA4AB844345F2C44987D6F9EBCC777EFD4078CC0F4C108DEF959F78F1EDB2765425785FCD17D5"
            "12BE31EEB66BEFF1E8FC2747078343A10126A10442313158406ACD94D3CCF71D192E8528360BA7E346DAC464E9EDCA4CFEB6CEB6BDE7BAEC9FF26CA6BDF73D0BE41E36129DCFF751DD"
            "2B5AD5CE116E8A963A2738A299477A6854546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F68183"
            "40A20125044A6F75722D73656372657440",
        },
        {
            &key,
            "countersign/signed-01.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10127A2078343A10127A10442313158408E1BE2F9453D264812E590499132BEF3FBF9EE9DB27C2C16"
            "8788E3B7EBE506C04FD3D19FAA9F51232AF5C959E4EF47928834647F56DFBE939112884D08EF250504423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5B7EC83B8"
            "3557652264E69690DBC1172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106",
        },
        {
            &key,
            "countersign/signed-02.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10127A207828343A10127A10442313158408E1BE2F9453D264812E590499132BEF3FBF9EE9DB27C2C"
            "168788E3B7EBE506C04FD3D19FAA9F51232AF5C959E4EF47928834647F56DFBE939112884D08EF25058343A10126A1044231315840AF049B80D52C3669B29970C133543754F9CC608C"
            "E41123AE1C827E36B38CB825987F01F22BB8AB13E9C66226EE23178FFA00A4FC220593B6E5AC38960071C9C804423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5"
            "B7EC83B83557652264E69690DBC1172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106",
        },
        {
            &key,
            "countersign/signed-03.json",
            "D8628443A10300A1078343A10127A1044231315840B7CACBA285C4CD3ED2F0146F419886144CA638D087DE123D400167308ACEABC4B5E5C6A40C0DE0B71167A39175EA56C1FE96C89E"
            "5E7D30DAF2438A456159A20A54546869732069732074686520636F6E74656E742E818343A10127A104423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5B7EC83B8"
            "3557652264E69690DBC1172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106",
        },
        {
            &key,
            "countersign/signed1-01.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10127A209584036739BEE3AA76D601E9C5F8AA391D9D67168F80DE3968A39FCA86CA00C7B9CC8C823"
            "9A6D5317C8CCFE1F6308931C739FFA151DF214604C7DA21B85BF0EE7D70F04423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5B7EC83B83557652264E69690DBC1"
            "172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106",
        },
        {
            &key,
            "countersign/signed1-02.json",
            "D8628443A10300A1095840D3AFDA37684DE8EBE5F65805D85035083AA5A5CFCF4162411308E3846B8316752E9CE4BDC0ED5AE7B574B9A87D2480CD2FA3875D945908F9F68BDE8AF810"
            "6E0A54546869732069732074686520636F6E74656E742E818343A10127A104423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5B7EC83B83557652264E69690DBC1"
            "172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106",
        },
        // countersign1
        {
            &key,
            "countersign1/Encrypt-01.json",
            "D08343A10101A2054C02D1F7E6F26C43D4868D87CE0958407C6ABF5B370044E78852036A42126DC5683AA4C6C62D28FA395849C7401AD54C5E60F98437988EDB75925889852C9D910E"
            "59B095BC2E372B52D527B3C55A3D04582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A",
        },
        {
            &key,
            "countersign1/Enveloped-01.json",
            "D8608443A10101A2054C02D1F7E6F26C43D4868D87CE0958404997FF3E4D0054A8851834A3F0493F594A6ED9CF52255BF6CEDC8C912B9C7A3FA91D62BABB2425242981752B42C4D95A"
            "F216401C8D8DCFF089DDA1B5219CCF0D582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A20125044A6F75722D7365637265744"
            "0",
        },
        {
            &key,
            "countersign1/Enveloped-02.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A30125044A6F75722D73"
            "656372657409584096EA1993B2B2018D33C176FC43F2BC4DA7AFE0147748BE52A54F3C8784A79FE8127DB32017224E0B929D5C1D60B8989262D5D8F501A058F97B3FB9871C841C0D4"
            "0",
        },
        {
            &key,
            "countersign1/mac0-01.json",
            "D18443A10105A1095840E818087173D1E6A0EB6D35F7F434239DB796DB0BFACBC9DE983DC8C80D02FBEC4B61ECC7200550A6FFAF7DD76326511EB7ABDC3C07D675566CC9B7A66D390C"
            "0B54546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58",
        },
        {
            &key,
            "countersign1/mac-01.json",
            "D8618543A10105A1095840E818087173D1E6A0EB6D35F7F434239DB796DB0BFACBC9DE983DC8C80D02FBEC4B61ECC7200550A6FFAF7DD76326511EB7ABDC3C07D675566CC9B7A66D39"
            "0C0B54546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6818340A20125044A6F75722D73656372"
            "657440",
        },
        {
            &key,
            "countersign1/signed-01.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10127A209584036739BEE3AA76D601E9C5F8AA391D9D67168F80DE3968A39FCA86CA00C7B9CC8C823"
            "9A6D5317C8CCFE1F6308931C739FFA151DF214604C7DA21B85BF0EE7D70F04423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5B7EC83B83557652264E69690DBC1"
            "172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106",
        },
        {
            &key,
            "countersign1/signed-02.json",
            "D8628443A10300A1095840D3AFDA37684DE8EBE5F65805D85035083AA5A5CFCF4162411308E3846B8316752E9CE4BDC0ED5AE7B574B9A87D2480CD2FA3875D945908F9F68BDE8AF810"
            "6E0A54546869732069732074686520636F6E74656E742E818343A10127A104423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5B7EC83B83557652264E69690DBC1"
            "172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106",
        },
        {
            &key,
            "countersign1/signed1-01.json",
            "D28445A201270300A2095840845E748A28577E94928D91C06CC3835DE31F1E6C64A24219EFEB2C2DC167B17FC8E1F79966FB09271D38DF60D2749B20B6A09948042B0BB21D7F48AA32"
            "5A65020442313154546869732069732074686520636F6E74656E742E58407142FD2FF96D56DB85BEE905A76BA1D0B7321A95C8C4D3607C5781932B7AFB8711497DFA751BF40B58B3BC"
            "C32300B1487F3DB34085EEF013BF08F4A44D6FEF0D",
        },
        // CWT
        {
            &cwtkey,
            "CWT/A_3.json",
            "D28443A10126A05850A70175636F61703A2F2F61732E6578616D706C652E636F6D02656572696B77037818636F61703A2F2F6C696768742E6578616D706C652E636F6D041A5612AEB0"
            "051A5610D9F0061A5610D9F007420B7158405427C1FF28D23FBAD1F29C4C7C6A555E601D6FA29F9179BC3D7438BACACA5ACD08C8D4D4F96131680C429A01F85951ECEE743A52B9B636"
            "32C57209120E1C9E30",
        },
        {
            &cwtkey,
            "CWT/A_4.json",
            "D18443A10104A05850A70175636F61703A2F2F61732E6578616D706C652E636F6D02656572696B77037818636F61703A2F2F6C696768742E6578616D706C652E636F6D041A5612AEB0"
            "051A5610D9F0061A5610D9F007420B7148093101EF6D789200",
        },
        {
            &cwtkey,
            "CWT/A_5.json",
            "D08343A1010AA1054D99A0D7846E762C49FFE8A63E0B5858B918A11FD81E438B7F973D9E2E119BCB22424BA0F38A80F27562F400EE1D0D6C0FDB559C02421FD384FC2EBE22D7071378"
            "B0EA7428FFF157444D45F7E6AFCDA1AAE5F6495830C58627087FC5B4974F319A8707A635DD643B",
        },
        {
            &cwtkey,
            "CWT/A_6.json",
            "D08343A1010AA1054D86BBD41CC32604396324B7F38058A372439FBFF538AA7B601EBFB29454050A3C99FD13B27216D084556496C7355C4BB462510F8E0E8479DBE08722D620E96BCB"
            "7764D75140D96220F062679B46B897E7ABE0C325DC2C96D8BB2C8334E3B92A42C0078983E753C054E647AD5387ED149F802F52B5A95EBF5F153C4FD64854AB7531E082B7F22721F939"
            "D257C94F8BC248E1D9CF04F9DD4E5DE7AB62DF37842FABEC230A657D4ABF7162BC786345EBB8EB3AF0",
        },
        {
            &cwtkey,
            "CWT/A_7.json",
            "D18443A10104A04BA106FB41D584367C20000048B8816F34C0542892",
        },
        // ecdh-direct-examples
        {
            &key,
            "ecdh-direct-examples/p256-hkdf-256-01.json",
            "D8608443A10101A1054CC9CF4DF2FE6C632BF788641358247ADBE2709CA818FB415F1E5DF66F4E1A51053BA6D65A1A0C52A357DA7A644B8070A151B0818344A1013818A220A4010220"
            "0121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280225820F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB0458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },
        {
            &key,
            "ecdh-direct-examples/p256-hkdf-256-02.json",
            "D8608443A10103A1054CC9CF4DF2FE6C632BF788641358243E63CBB945790A3AAA7EBDA78779DFB31FF2EF54DD07C2447A224B6828D3781749A76A4E818344A1013818A220A4010220"
            "0121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280225820F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB0458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },
        {
            &key,
            "ecdh-direct-examples/p256-hkdf-256-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840DB49CF4E1444B976C74D550A6134E1A69774AE0F132AD38FB5F409B25740EE564870FBAEB0EE01BA4A7E"
            "7DFD2BBBECBF21E5BB1B7CCD94210375D3461AF851EA818344A1013818A220A40102200121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D62802258"
            "20F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB0458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C654"
            "0",
        },
        {
            &key,
            "ecdh-direct-examples/p256-hkdf-512-01.json",
            "D8608443A10101A1054CC9CF4DF2FE6C632BF788641358242ACAF2D3BABAFC8B5EE715168DF349AC10E9B82CE51B9E4834F64FF240BE4D49A022A99F818344A1013819A220A4010220"
            "0121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280225820F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB0458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },
        {
            &key,
            "ecdh-direct-examples/p256-hkdf-512-02.json",
            "D8608443A10103A1054CC9CF4DF2FE6C632BF788641358242EC2BE4CDDA5838267A7E9529F9FF2CABA6449D03E7A148CA57582D76C8CE77F9D606A77818344A1013819A220A4010220"
            "0121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280225820F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB0458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },
        {
            &key,
            "ecdh-direct-examples/p256-ss-hkdf-256-01.json",
            "D8608443A10101A1054CD7923E677B71A3F40A179643582455DE918D6CA1E33BEDE48DB6E48678A8159214E76B2099E74AA52F250B940D13C4E7AB78818344A101381AA321A4200121"
            "5820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9"
            "CF4DF2FE6C632BF7886413F76E88523A8260B857D70B350027FD842B5E594740",
        },
        {
            &key,
            "ecdh-direct-examples/p256-ss-hkdf-256-02.json",
            "D8608443A10103A1054C2DE17507BE74667DA9B7B8AC5824DA8955ED1647756DE4C6846FC3581A8EB2176C583363AFCE78D3868F282F221D20ED6063818344A101381AA321A4200121"
            "5820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9"
            "CF4DF2FE6C632BF7886413F76E885299E58C2F0F717D59C6123210A16AD92040",
        },
        {
            &key,
            "ecdh-direct-examples/p256-ss-hkdf-256-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840CED9C9DBD280362DAEBB48CDD67239A25CD2DD96FE60C3001DBF353A7A36F1EA34C7ED84FC18757E1244"
            "4A6AD5C3B3F7416651C6A3CDD2A9D9E9844C5F46CF84818344A101381BA321A42001215820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F"
            "38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535"
            "584002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9CF4DF2FE6C632BF7886413F76E8852D8D30979D9C0217A424941B5CA02A3AA40",
        },
        {
            &key,
            "ecdh-direct-examples/p256-ss-hkdf-512-01.json",
            "D8608443A10101A1054C77745450192BD611F420713E582445CD1DEF3EF7FF69F779805844AAAB20A1A9B672BBC16C601D5AC3AB2560ABA7A795D5C5818344A101381BA321A4200121"
            "5820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9"
            "CF4DF2FE6C632BF7886413F76E8852423BED8B225D042ABE4480A2DD13883240",
        },
        {
            &key,
            "ecdh-direct-examples/p256-ss-hkdf-512-02.json",
            "D8608443A10103A1054C02EC966BD19F50A11CA2021258246773B51092493E6174CB91B33F649947E2376328FB410E297895709E9E4C62092BD32F91818344A101381AA321A4200121"
            "5820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9"
            "CF4DF2FE6C632BF7886413F76E8852A6423991E18819CCCB2EE6FD6517BC0640",
        },
        {
            &key,
            "ecdh-direct-examples/p256-ss-hkdf-512-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840CA8E6BC30FA2433A04311CBE75AC2994C5BCCE073B00116E2545A7278F194782F12B5E7B7A449735762B"
            "2882498F2F633FF31F37C8961A23B4B119103AAA3A36818344A1013818A220A401022003215842000E2CE3AA90FB69E4C648BABA21A8B616ACF6D9F2AF7699888DD8FF9A6DF164B059"
            "F6842AD27DD24F1893FAC8D5C03283CF60211F9D17138662DC8F1547C289C2A52258420084D56A168242745AA99EFDA9D58D4439EEC0A6AA434918BC549F57F31F38B2C0A80FF0B875"
            "4367F315D1BE1D805BB95DA3880E01035E760E92CA8517D313F591EE0458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-hkdf-256-01.json",
            "D8608443A10101A1054C3082660901A9B9CD87AACB715824E4BB61A1BF4DB80CD9345BB7AA9D46844763AC0B242F09D43744B83D8C48C4E87BC90775818344A1013818A220A4010220"
            "03215842007490FF6DC6C8FAA34D07627DDD725EF11B8D901C931DBF3BC2EB4A9445CEDC752A62A4DC63CD80BDDDF5A0C7CB164479C4ADAABAAC7A78D03E0EC8496D4740FCF4225842"
            "019D3F45929FC96E122FCEBB8FC426DA84A36EF177AFDC894DC111ACD7AF9F7120EFC0D0BE7F48716DB7EB30B65ADEDF5294651E3BDD2ED921EA0A7A88FC77D3394D0458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-hkdf-256-02.json",
            "D8608443A10103A1054C512C9CC879517ADCF0FA768E5824E4DAB91AE49A086F731CB0C9A4741A519033156C3CFA6B80FA8D5CB705A0676E5561C7B6818344A1013818A220A4010220"
            "032158420186A55E1A9E1937CED31F184623A7BBAE115CFADB9A05A2913F67BB4D66B591EFC30D7C5857111837673D2050FC3AB3FE58697CED8A6FEC883107F1842ACDE6F9AA225842"
            "002034BC5484085C4DB6E98B381193B13C1C94A58BB14EDC72A7E9EDFED30F05F9A10EA7B61391B06A6D7711339B843F71238B4A3C3146334188C0B8E4804CD65D780458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-hkdf-256-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840CA8E6BC30FA2433A04311CBE75AC2994C5BCCE073B00116E2545A7278F194782F12B5E7B7A449735762B"
            "2882498F2F633FF31F37C8961A23B4B119103AAA3A36818344A1013818A220A401022003215842000E2CE3AA90FB69E4C648BABA21A8B616ACF6D9F2AF7699888DD8FF9A6DF164B059"
            "F6842AD27DD24F1893FAC8D5C03283CF60211F9D17138662DC8F1547C289C2A52258420084D56A168242745AA99EFDA9D58D4439EEC0A6AA434918BC549F57F31F38B2C0A80FF0B875"
            "4367F315D1BE1D805BB95DA3880E01035E760E92CA8517D313F591EE0458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-hkdf-512-01.json",
            "D8608443A10101A1054CCFDC1CA6D690CF1964458D425824B994CCC29C6490FEE1AD6EA997248CDFCF7BE6F7283224006B5E7BBE9958435CFA553D0F818344A1013819A220A4010220"
            "0321584200F11B8FBCB163447DE1FBB059CB56B46654CAAB99D13BA0FB5858783E89990754729682F04F6AC4AC3DD36451940AFA933D373BF1D7015D4FD7530DD48DED8CAA8C225842"
            "00A806098B016CDBB9E66042C2C30C7C18F8AA7F5851517FA1B154E42EB2C69EAD1A063457F37A996B2E139193F1AB3B5B5CD345288D7375F35F6E1DC515F1B058760458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-hkdf-512-02.json",
            "D8608443A10103A1054CE89FD3534E1ABAF69C65CFE058241187EFE3B75F733299723024E3A1335962AB622D69587A716851ABEBD303977509DD491C818344A1013819A220A4010220"
            "0321584201E3A6C126F1C3C27C38FC723A696C5E233F504D911516AE2899595EB6376A71AEE95911EDE9F372205A5BAFDA006B6F0EDCC6288705C6BCE357B537E54863B93C4A225842"
            "0066E0423D3BEFC80194FC9A0EB7D9AE63F7F7CDE74030A79D9F3E9CEDF221E1999605CF908ED44515B8F6B8BC816325380960383EF3EE8D08635FF0305BE6F5164B0458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-hkdf-512-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840F443D77D89327661A654A52E6C055BDD9CB163E2520EBC152E4A0BC7424950EA795F6FB2B5677CEFD92C"
            "DFC6EED22BA6EDCEDA8D2D55A495238A2D29C4C41173818344A1013819A220A4010220032158420003ABE163C86CFC288CB6E6E2FB0199A36D460016D1B5AAFB46C9895C646398FD5C"
            "194CA82BE9A4317F4E3EEF318A406F0D7BBA653B3B564B1B262C13B02EB96FEB225842005D76FBD13FCA10C40CF206D8757BFFDDCE98417D3E221A8104F61B21B9F219D6069801AE8B"
            "8DE19CC704E9859E7EA991C0FDDA9AA974411AE44DC5FD41BBDC38090458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },

        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-ss-hkdf-256-01.json",
            "D8608443A10101A1054CB9B63082660901A9B9CD87AA58244275EEA3F025755DC242556BD66FC87DA27B70C99228F16CA9661A37C813019F562DA26C818344A101381AA321A4200321"
            "584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF9809866547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E012258420103"
            "1EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9CF4DF2FE6C"
            "632BF7886413F76E885252908DF901D1581A045444DD996E170440",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-ss-hkdf-256-02.json",
            "D8608443A10103A1054CED7A512C9CC879517ADCF0FA5824FF69D38AEC771937C07062F6BF3D9DCFF98ACED55D16DB40BC33C1A90AA456D82AC874D0818344A101381AA321A4200321"
            "584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF9809866547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E012258420103"
            "1EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9CF4DF2FE6C"
            "632BF7886413F76E88527FAC271A4C7EA34B7E28D7BBB54C682B40",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-ss-hkdf-256-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840AAC325E699B439C23393F5C233300408FBFB13984AF9086680B0D7A1BDA06098925AE520899034F25949"
            "89741850A780EB05C1D3839B36EB9FE0A258BCB04454818344A101381AA321A4200321584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF98098"
            "66547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E0122584201031EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4"
            "390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7"
            "E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9CF4DF2FE6C632BF7886413F76E88522CD81CA6C3B47139724AD1D4309098EC40",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-ss-hkdf-512-01.json",
            "D8608443A10101A1054C8358CFDC1CA6D690CF1964455824F4AC868505C818DB73A2F657299B1D72D5E6D511B1FEDA6FDA5B91BB899A48F85BE2C229818344A101381BA321A4200321"
            "584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF9809866547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E012258420103"
            "1EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9CF4DF2FE6C"
            "632BF7886413F76E88526B37FD0B58734CA925A389AD361ECEF240",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-ss-hkdf-512-02.json",
            "D8608443A10103A1054CE3B4E89FD3534E1ABAF69C65582415BB9CAE6D06303AF8A3711DB08822C06113E87AB5B77304DBB6D7674E23344EA1C17E59818344A101381BA321A4200321"
            "584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF9809866547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E012258420103"
            "1EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9CF4DF2FE6C"
            "632BF7886413F76E885238FB137F6C20764D89E26452937675B540",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-direct-examples/p521-ss-hkdf-512-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E58406BAC31E9B3D4F0D90CA64D9B217425E1453F8E353A5A1D7CB83B0DA18418AF701CF66F1605F7DD6125B7"
            "0107D22B0125444F55E1F6FCD760DFF1851F06837C24818344A101381BA321A4200321584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF98098"
            "66547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E0122584201031EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4"
            "390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6535584002D1F7"
            "E6F26C43D4868D87CEB2353161740AACF1F7163647984B522A848DF1C3C9CF4DF2FE6C632BF7886413F76E8852C2772BFB570B2D11D2CD3C5B6888AFEF40",
        },
        // ecdh-wrap-examples
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-ss-wrap-128-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A101381FA221A4200121"
            "5820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65581833CB2D33A9C2A9178284E03D6DCCFFEA4E32D7363BDA50D3",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-ss-wrap-128-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A101381FA221A4200121"
            "5820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655828FCE1BCC94823E72A5483565A7BDF21F4B374259E2C3A6E0B239D0E7E51B0AB05885D"
            "62EBB087C15D",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-ss-wrap-128-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E584029AE099F8876172256B7823347E3BC0DDB133835297292691884E3BFAD629586AC00D0A24DD44C508B5A"
            "92DF6FE711345CD7CBE87257C5D7D0DA03ADA33B2FA7818344A101381FA221A42001215820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F"
            "38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558"
            "481F0AE1AEC2E0E68D37FAAD6E9A5F46B22386D223611B20A4DA0BCA4E0AA033DDE80CC003B263CD150A0D70B7F9BFF668F153D2D23EA4421FED40974A206145E2AC6DABA29AFB619"
            "0",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-ss-wrap-192-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A1013820A221A4200121"
            "5820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818FB271774C7AD02BCE547EE7170CE02A2E2BD493EEAEB5641",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-ss-wrap-192-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A1013820A221A4200121"
            "5820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65582893EC49A23215ABE7703F4EDCE6423AC9E850268107BE5E4C6D65D26087C44A37CCAC"
            "4CABEDD92446",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-ss-wrap-192-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E584029AE099F8876172256B7823347E3BC0DDB133835297292691884E3BFAD629586AC00D0A24DD44C508B5A"
            "92DF6FE711345CD7CBE87257C5D7D0DA03ADA33B2FA7818344A1013820A221A42001215820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F"
            "38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558"
            "48494F559386FC0EBBE744163D4C796015AE7BC4BC3758F59318843DFDF77675D1B0B69534F9201B38FCFBCD6F87C1D581043F417BA17EE13CA88BCED26F94870CDB06693FD234727"
            "F",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-ss-wrap-256-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A1013821A221A4200121"
            "5820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818008C801E1FC95BE6DD8B3AF3C5B7226470AF28549060B598",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-ss-wrap-256-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A1013821A221A4200121"
            "5820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655828352126297E8D63A0E8FCD16B891ED3CAF970C18F3F7028C31C4A16BB6494FFBF8B0E"
            "7DBD7C787734",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-ss-wrap-256-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E58407A70B85528A44069F6523B52A05E655557D6E2A403580C6A63A5585183454F3105473981DF08A309D6C5"
            "CCAD79578669B00999E25AD463F16D2DC06ADA13C17D818344A1013821A221A42001215820EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F52258200F"
            "38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A01020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558"
            "4829F5E6ADA6636959721550B3F509BFE4AC32AE4B694A95E0BAAE77EDC7981FBF4D2189C5B99F1E3962E56E07EEB63905D80B346306B2B42881DAF4CE7BC9A3A8D012E21B2600F38"
            "A",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-wrap-128-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A101381CA220A4010220"
            "01215820ECDBCEC636CC1408A503BBF6B7311B900C9AED9C5B71503848C89A07D0EF6F5B225820D6D1586710C02203E4E53B20DC7B233CA4C8B6853467B9FB8244A3840ACCD6020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818D23BCA11C3F8E35BF6F81412794E159772E946FF4FB31BD1",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-wrap-128-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A101381CA220A4010220"
            "01215820E12C938B182258C9D447D41821715261AE99AD77D241943F4A12FF20DD3CE40022582048B0588903365733B98D388C6136C04B7FFD1A770CD2611189EE84E9941A7E260458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655828508FAD30A1A95D1380B5167D032799C72477AB60258ABFB71C7AB603A4890EF44F13"
            "63ED9F569E85",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-wrap-128-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E584029AE099F8876172256B7823347E3BC0DDB133835297292691884E3BFAD629586AC00D0A24DD44C508B5A"
            "92DF6FE711345CD7CBE87257C5D7D0DA03ADA33B2FA7818344A101381CA220A401022001215820E4CFD3201DE9D3A56315FA0AF77105331EF03666C85A5F4BB67C309CB33860672258"
            "20A5EE5A8670A96163092B992BD17CAD47866AD8579C4B2676C3B5BB7E01ADD7560458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558"
            "48836026593749A7C92049501148814F87FC396856E74739D6B39C99154E690E7FA1BEB86B5669722467EF083E8EF68D09DC674B0D94294597C27DD5016C937DD4056F7B85BE14492"
            "6",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-wrap-192-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A101381DA220A4010220"
            "01215820ECDBCEC636CC1408A503BBF6B7311B900C9AED9C5B71503848C89A07D0EF6F5B225820D6D1586710C02203E4E53B20DC7B233CA4C8B6853467B9FB8244A3840ACCD6020458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558189A425F9CEE4175EE2966C1FE2462CF0C8E802D3E0FCA3006",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-wrap-192-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A101381DA220A4010220"
            "01215820E12C938B182258C9D447D41821715261AE99AD77D241943F4A12FF20DD3CE40022582048B0588903365733B98D388C6136C04B7FFD1A770CD2611189EE84E9941A7E260458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655828A82C516F35C1858EEC49DC339568E674F51921DD5F254E12404B4CFBE7D33AA96C5A"
            "4AF0906026FF",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-wrap-192-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E584029AE099F8876172256B7823347E3BC0DDB133835297292691884E3BFAD629586AC00D0A24DD44C508B5A"
            "92DF6FE711345CD7CBE87257C5D7D0DA03ADA33B2FA7818344A101381DA220A401022001215820E4CFD3201DE9D3A56315FA0AF77105331EF03666C85A5F4BB67C309CB33860672258"
            "20A5EE5A8670A96163092B992BD17CAD47866AD8579C4B2676C3B5BB7E01ADD7560458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558"
            "4895FF88D324E49ABAAB4DAA873EDD13DD5AA2225E0C0739A7813753E87C216D9610AACE2BB8A49DD3C3279B38334F4435E7C529BB53B44E5D88ADDD0D515B0369B8FFD9C70088D39"
            "4",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-wrap-256-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A101381EA220A4010220"
            "012158203FC1141F492FDB3B33122BE61B31BAFD860798DB190E07831FB7A2E42713F4CA225820FC09D3DEF88EA52953B51F48955BFAC1AC79B4286F0673519A4A71FC18B628690458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818E00E25B58AEADDE5A475F1D69D2A2C199E5C1F231C5B164A",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-wrap-256-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A101381EA220A4010220"
            "01215820687312AA4E2112CB2A06721F984788D3D1E235F64F48CEBBC81CB19E11D3F8E1225820C31C514CCB8AF91800DD519ADA41CF6B03ECDFB212FDB34D371D536C7419ACC40458"
            "246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558289F7FF60D7189124425A470E48FF66A00B6E3D013B07C2428F2C29ECB6E605DBBADC3"
            "EA91AB671E59",
        },
        {
            &ecdh_wrap_p256_key,
            "ecdh-wrap-examples/p256-wrap-256-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E58407A70B85528A44069F6523B52A05E655557D6E2A403580C6A63A5585183454F3105473981DF08A309D6C5"
            "CCAD79578669B00999E25AD463F16D2DC06ADA13C17D818344A101381EA220A40102200121582030687714315D2F77217589A529DC9704D736636EE541064C896FDA61E42377192258"
            "202707A4E0B91EED9A57A2B0E5FCD18FACBA0BF879E8415D1762A1B8E75624C4610458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558"
            "4892113A046864D7BABBD98A157E73B5E873198BD1BE51CE2E6FDFAD285F6C8AD95BDA73AEFD7D1EED01A767F76CFC809B623B0E6F0C373F6274360241E85B3139AF1112827E936F3"
            "5",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-ss-wrap-128-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A101381FA221A4200321"
            "584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF9809866547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E012258420103"
            "1EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558184C72A80A4657F722C39983AB695555C65F3050E786EB5CB2",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-ss-wrap-128-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A101381FA221A4200321"
            "584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF9809866547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E012258420103"
            "1EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65582830828DEAF978B83AFEB4F4AA4A1D4624F9395FB80253E95E4F9E11CA1D820E1AE0DF9DB0A7B48A"
            "6D",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-ss-wrap-128-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840D666AE264277E9B4345AFBCD83317AED530C46C7E43D52671C13EEB92415249035A9A01A397A11A60EBD"
            "212402468EE4403F388D1E5D878B35BD2B0292B90883818344A101381FA221A4200321584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF98098"
            "66547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E0122584201031EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4"
            "390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655848CB164F65"
            "F37023E6C940230160762002593D6F42CF4A4D61CDE14AC2A5F41A7A88D77B257A1887518C1BF9ED3038B7C049D874DDABE1CB287204D59B14C88D54B9A00BF078505934",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-ss-wrap-192-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A1013820A221A4200321"
            "584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF9809866547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E012258420103"
            "1EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818E196B00055198859B29FEDCBA6A81E5DAFB6A36AC2E3CB6E",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-ss-wrap-192-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A1013820A221A4200321"
            "584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF9809866547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E012258420103"
            "1EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655828CFDA89F747BD0380D81AEA6892573AE1F447D07149CCDD4B775B582DBBF76904F6EFDC288BA87F"
            "62",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-ss-wrap-192-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840D666AE264277E9B4345AFBCD83317AED530C46C7E43D52671C13EEB92415249035A9A01A397A11A60EBD"
            "212402468EE4403F388D1E5D878B35BD2B0292B90883818344A1013820A221A4200321584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF98098"
            "66547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E0122584201031EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4"
            "390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655848DA8425C0"
            "454C9F5BFED9477CB5E4A1D3CE7B00FF2AAC666A05E6053E34278B75C841095C6C178BD8243C1778C2301A98CE7087B3815DDDB905AB26F258B00BADA4CDE35911282AA7",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-ss-wrap-256-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A1013821A221A4200321"
            "584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF9809866547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E012258420103"
            "1EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818E322636D8AB5B809B718F4569CD849C38FFE9DA482EADA7F",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-ss-wrap-256-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A1013821A221A4200321"
            "584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF9809866547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E012258420103"
            "1EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655828F1CDA91C895A807F3E1EA764E69629EDC322A2BB2BE33DBA4C5168ADDE62005795D848CC28018C"
            "10",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-ss-wrap-256-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840C0D81EE9617FC80C75E33057CFA3A45794DC56793580B2564ABE4BD820C6CC58440AD86F18454429D5F3"
            "D2B01259645C65BF90ED96A04D5CD98F58D083DDD20E818344A1013821A221A4200321584200F3F5B480B5132DBFFF869E920D3A9E27292B7BAF4042D7EC73DA6545D87F6A9DF98098"
            "66547B2FA46A5B40A21A336FF6EC89E6CAF17516FF4ADF3BA706DF671E0122584201031EEFEC44BB9B38F6C2E2157206B18E0556003115EE875B59D3DECA8E72A82416CD3F63B7D6A4"
            "390018B7353A0DD0AA6B7BFBCFBB7747D35B59CDB5FE5126A74C01020458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655848FE219F4B"
            "E502C74FF314230732AB77EDC5B3EAE7D068A0B2889EAA929CE23F6A04A0161757591D49FFA0D2678EA0FA68914F3086522E7D4553DC9E2F49A7C12FCE8A622EA5719070",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-wrap-128-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A101381CA220A4010220"
            "0321584200790FF988875233F821CC919CCD19137A4985C4FD1A41546E5C8EB4172E9FD153B47F1C0B30DE54D75F4DAAED9B4A29D756577959D1AF4C2126CEBF3FF2703E2BF9225842"
            "01098DEC92309CECC4E1AD02DC7CF43EBE63BA606B34944119C9AA565A6A0C9198BF900CF2CEA7A90C1067C60D4ED5EC22BC134F422A3147CB88A4FB279EAA5911F80458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818AD60C775300EFF4994D954D7BC02B322375B91CFAF2B60DC",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-wrap-128-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A101381CA220A4010220"
            "0321584201118B1EB02274976993694D310DB8B2935488DEC231AD6D1EB78F124E080173D7C9454B30E017FDBF9ADF7D5EA69DCBCAD64AF48D06AF090E76F4CBD4A236507DF6225842"
            "00FC0F961FA1C470060C7B650CD6761B741E3C78209DC258FE22B04DA3D08F34E28D3831435DC4DB85F52CE3D0BD855DB1B51B363C8B965B0B0E4AFA862328076F5C0458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655828EB90AEC77B834C3FAFDF834374F5D6CC4251CA779BA2BB8039602294655CF6B9747673E551BFD6"
            "93",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-wrap-128-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840D666AE264277E9B4345AFBCD83317AED530C46C7E43D52671C13EEB92415249035A9A01A397A11A60EBD"
            "212402468EE4403F388D1E5D878B35BD2B0292B90883818344A101381CA220A40102200321584200BEBB1995854D8C2928453B585315C451183DF1DFB70DB73B63044F0B726EECF535"
            "1075C6DD6DE19C53D9070A68D671D9AA50F94B7BC7D08DD53E17CD1399D9EA16225842006DC444781BDE859B6D4A7ED510B335446D5D800D7C212E76CFA0157A2D9C6ECB0F6A6DD0D9"
            "F34AB2430B6128586F497B0EE4C5ED97770376340207FC3E3D7492410458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655848D258E106"
            "8ABE0CAD46D69E91FD00DBEFD4981CD682533C892C302483C9294F4005B835816D5E431A05F64897FD3C0A52F24A4E9703AE3CF718C18D7C88B866BF06C01A6760EABF1C",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-wrap-192-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A101381DA220A4010220"
            "0321584200790FF988875233F821CC919CCD19137A4985C4FD1A41546E5C8EB4172E9FD153B47F1C0B30DE54D75F4DAAED9B4A29D756577959D1AF4C2126CEBF3FF2703E2BF9225842"
            "01098DEC92309CECC4E1AD02DC7CF43EBE63BA606B34944119C9AA565A6A0C9198BF900CF2CEA7A90C1067C60D4ED5EC22BC134F422A3147CB88A4FB279EAA5911F80458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818AF1599C80DEB5DD020D4B9392708B6D99C7EA0302A224724",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-wrap-192-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A101381DA220A4010220"
            "0321584201118B1EB02274976993694D310DB8B2935488DEC231AD6D1EB78F124E080173D7C9454B30E017FDBF9ADF7D5EA69DCBCAD64AF48D06AF090E76F4CBD4A236507DF6225842"
            "00FC0F961FA1C470060C7B650CD6761B741E3C78209DC258FE22B04DA3D08F34E28D3831435DC4DB85F52CE3D0BD855DB1B51B363C8B965B0B0E4AFA862328076F5C0458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558280A7AAC87FAE5ED32F49C4910A3CB9EE26D572EA5AB92BFD48DCC332957703D181C9335693917ED"
            "BA",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-wrap-192-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840D666AE264277E9B4345AFBCD83317AED530C46C7E43D52671C13EEB92415249035A9A01A397A11A60EBD"
            "212402468EE4403F388D1E5D878B35BD2B0292B90883818344A101381DA220A40102200321584200BEBB1995854D8C2928453B585315C451183DF1DFB70DB73B63044F0B726EECF535"
            "1075C6DD6DE19C53D9070A68D671D9AA50F94B7BC7D08DD53E17CD1399D9EA16225842006DC444781BDE859B6D4A7ED510B335446D5D800D7C212E76CFA0157A2D9C6ECB0F6A6DD0D9"
            "F34AB2430B6128586F497B0EE4C5ED97770376340207FC3E3D7492410458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558485D1C6D82"
            "3D5ED035903B6284905E3D13737870C0931B0CCB10475AA14F6ACF0EE4216FBADAC6198E629340B3C59E3749E2A0C66230CB4C68681CB9037047BF767C093300B5F267D2",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-wrap-256-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818344A101381EA220A4010220"
            "0321584200660166E1526532A24030C773182F1410639E4972C649CF17698935BEA24FAE0E20505CFD30C335DA4ABBB21A1EF6A7E5BFDD04D8539CBE505D24821702BF399221225842"
            "00204FAFA97FDCF8373AB0E2EF5524CFFAC3FDCD02BE36008371031C440C9D978BE67DC99CE07A641BF443DA053BB0839E2D319725FF1F20C46C965EBFDFEF8B02B40458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655818998F2525381347FF57E67C43ACB867A05567CE3D9FC01336",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-wrap-256-02.json",
            "D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A101381EA220A4010220"
            "0321584201C97A1A9F1EED9F3D168F12AFC2FE1A1F86F1559C5F21DBBE5F5C36006B0E8BDE096400BACA2CB1E178A3F1E88DF3E5333F30B0B8A4261E8C35B1E62E603B25D8CB225842"
            "0128AACFA5E390E978FF4C9CFDBCE9610FC2B6D89CFEE27C73880C256C6A1B1A89BF771B8806DA1DF36817B405EC124A32D0BEC3BD337687ACC79825794C099BD3100458246D657269"
            "61646F632E6272616E64796275636B406275636B6C616E642E6578616D706C655828355E1B6E810A43189F4356AC607A07E2374B38FE5823CAC496F913B20EA710A2BACFC5535D0FD8"
            "D8",
        },
        {
            &ecdh_wrap_p521_key,
            "ecdh-wrap-examples/p521-wrap-256-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840C0D81EE9617FC80C75E33057CFA3A45794DC56793580B2564ABE4BD820C6CC58440AD86F18454429D5F3"
            "D2B01259645C65BF90ED96A04D5CD98F58D083DDD20E818344A101381EA220A4010220032158420152CE61790CCF5588A7A08F017E461871A3F76B25B28BC1FB4D6B8FD9F7A1EC81A8"
            "E2246BC3FA3B7D4A4AA0C96B1EB6165881D0B0034036F273A69C1CACFF50CD5A2258420046845542279B7833ED8E79E567BE74B7A3CA638CD79E019D4E83666C6CA4C1FC52E903FDFD"
            "01A15D8041C7747E9C0D25F879D59CA37CF7A4893D8B2EE514A382600458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65584886C4162F"
            "0D7F7A57E97CDF31583C28C6C542DE20589F94A6B63489269C03473C02D0CE06459B97F6A0DF3F5985076031F9A9A3B15EA8622570D739DEF806D2221CAD2BF7C5826B50",
        },
        // ecdsa-examples
        {
            &key,
            "ecdsa-examples/ecdsa-01.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840D71C05DB52C9CE7F1BF5AAC01334BBEACAC1D86A2303E6EEAA89266F45C01E"
            "D602CA649EAF790D8BC99D2458457CA6A872061940E7AFBE48E289DFAC146AE258",
        },
        {
            &key,
            "ecdsa-examples/ecdsa-02.json",
            "D8628440A054546869732069732074686520636F6E74656E742E818344A1013822A10444503338345860230DF24B9F31DD2D7D1B9C33CE59073FC21E02BB63DC55847626B5B7F43905"
            "D59ACC186890BC1FE8B6D12E61B0373FFBA131ECC6C21958CDFF28AD77E0C32F9A0C6CA247135F538496228B2BE5557E7DBD7280DB24B46B68C0772D1BAEF09DE5",
        },
        {
            &key,
            "ecdsa-examples/ecdsa-03.json",
            "D8628440A054546869732069732074686520636F6E74656E742E818344A1013823A104581E62696C626F2E62616767696E7340686F626269746F6E2E6578616D706C65588400A2D28A"
            "7C2BDB1587877420F65ADF7D0B9A06635DD1DE64BB62974C863F0B160DD2163734034E6AC003B01E8705524C5C4CA479A952F0247EE8CB0B4FB7397BA08D009E0C8BF482270CC5771A"
            "A143966E5A469A09F613488030C5B07EC6D722E3835ADB5B2D8C44E95FFB13877DD2582866883535DE3BB03D01753F83AB87BB4F7A0297",
        },
        {
            &key,
            "ecdsa-examples/ecdsa-04.json",
            "D8628440A054546869732069732074686520636F6E74656E742E818344A1013823A10442313158400CA5877D333B8E68B917551F947E0977BD3C70D416FDE3F9BB6A30CCBB96E875D0"
            "941FF22C5DB4087124FB1981A88B2B34C7EE2827679B1318272C3D62622CC8",
        },
        {
            &key,
            "ecdsa-examples/ecdsa-sig-01.json",
            "D28445A201260300A10442313154546869732069732074686520636F6E74656E742E58406520BBAF2081D7E0ED0F95F76EB0733D667005F7467CEC4B87B9381A6BA1EDE8E00DF29F32"
            "A37230F39A842A54821FDD223092819D7728EFB9D3A0080B75380B",
        },
        {
            &key,
            "ecdsa-examples/ecdsa-sig-02.json",
            "D28444A1013822A104445033383454546869732069732074686520636F6E74656E742E58605F150ABD1C7D25B32065A14E05D6CB1F665D10769FF455EA9A2E0ADAB5DE63838DB257F0"
            "949C41E13330E110EBA7B912F34E1546FB1366A2568FAA91EC3E6C8D42F4A67A0EDF731D88C9AEAD52258B2E2C4740EF614F02E9D91E9B7B59622A3C",
        },
        {
            &key,
            "ecdsa-examples/ecdsa-sig-03.json",
            "D28444A1013823A104581E62696C626F2E62616767696E7340686F626269746F6E2E6578616D706C6554546869732069732074686520636F6E74656E742E588401664DD6962091B510"
            "0D6E1833D503539330EC2BC8FD3E8996950CE9F70259D9A30F73794F603B0D3E7C5E9C4C2A57E10211F76E79DF8FFD1B79D7EF5B9FA7DA109001965FA2D37E093BB13C040399C467B3"
            "B9908C09DB2B0F1F4996FE07BB02AAA121A8E1C671F3F997ADE7D651081017057BD3A8A5FBF394972EA71CFDC15E6F8FE2E1",
        },
        {
            &key,
            "ecdsa-examples/ecdsa-sig-04.json",
            "D28444A1013823A10442313154546869732069732074686520636F6E74656E742E5840EB18B84ED674284E5ED861C3943E101BED5DB9F560C0F0292B34362990D1C59B10DF7946CBC6"
            "CA3DCBD6C17A6DD1D711F50337BAA6B4FCFAE0EFC70E52C1DE0F",
        },
        // eddsa-examples
        {
            &key,
            "eddsa-examples/eddsa-01.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10127A104423131584077F3EACD11852C4BF9CB1D72FABE6B26FBA1D76092B2B5B7EC83B835576522"
            "64E69690DBC1172DDC0BF88411C0D25A507FDB247A20C40D5E245FABD3FC9EC106",
        },
        {
            &key,
            "eddsa-examples/eddsa-02.json",
            "D8628440A054546869732069732074686520636F6E74656E742E818343A10127A1044565643434385872ABF04F4BC7DFACF70C20C34A3CFBD27719911DC8518B2D67BF6AF62895D0FA"
            "1E6A1CB8B47AD1297C0E9C34BEB34E50DFFEF14350EBD57842807D54914111150F698543B0A5E1DA1DB79632C6415CE18EF74EDAEA680B0C8881439D869171481D78E2F7D26340C293"
            "C2ECDED8DE1425851900",
        },
        {
            &key,
            "eddsa-examples/eddsa-sig-01.json",
            "D28445A201270300A10442313154546869732069732074686520636F6E74656E742E58407142FD2FF96D56DB85BEE905A76BA1D0B7321A95C8C4D3607C5781932B7AFB8711497DFA75"
            "1BF40B58B3BCC32300B1487F3DB34085EEF013BF08F4A44D6FEF0D",
        },
        {
            &key,
            "eddsa-examples/eddsa-sig-02.json",
            "D28443A10127A10445656434343854546869732069732074686520636F6E74656E742E5872988240A3A2F189BD486DE14AA77F54686C576A09F2E7ED9BAE910DF9139C2AC3BE7C27B7"
            "E10A20FA17C9D57D3510A2CF1F634BC0345AB9BE00849842171D1E9E98B2674C0E38BFCF6C557A1692B01B71015A47AC9F7748840CAD1DA80CBB5B349309FEBB912672B377C8B2072A"
            "F1598B3700",
        },
        // encrypted-tests
        {
            &key,
            "encrypted-tests/aes-gcm-01.json",
            "D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A",
        },
        {
            &key,
            "encrypted-tests/enc-pass-02.json",
            "D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B1DC3A143880CA2883A5630DA08AE1E6E",
            {
                "0011bbcc22dd4455dd220099",
            },
        },
        // enveloped-tests
        {
            &key,
            "enveloped-tests/aes-gcm-01.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A20125044A6F75722D73"
            "656372657440",
        },
        {
            &key,
            "enveloped-tests/enc-pass-02.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B7CDE42D4F7E6DD896E231C71FDD6FC99818340A20125044A6F75722D73"
            "656372657440",
            {
                "0011bbcc22dd4455dd220099",
            },
        },
    // hashsig
#if 0
      // HSS LMS
      // https://www.openssl.org/roadmap.html
      // PQC - OpenSSL will not be including any of the candidate algorithms until the selection process is complete.
      {
          &key,
          "hashsig/hashsig-01.json",
          "D8628443A10300A054546869732069732074686520636F6E74656E742E818344A101382DA104464974734269675909D000000000000000010000000391291DE76CE6E24D1E2A9B602665"
          "19BC8CE889F814DEB0FC00EDD3129DE3AB9B6BFA3BF47D007D844AF7DB749EA97215E82F456CBDD473812C6A042AE39539898752C89B60A276EC8A9FEAB900E25BDFE0AB8E773AA1C36A"
          "E214D67C65BB68630450A5DB2C7C6403B77F6A9BF4D30A0219DB5CCED884D7514F3CBD19220020BF3045B0E5C6955B32864F16F97DA02F0CBFEA70458B07032E30B0342D75B8F3DC6871"
          "442E6384B10F559F5DC594A214924C48CCC337078665653FC740340428138B0FB5154F2F2CB291AD05ACE7ACAE60031B2D09B2F417712D1C01E34B165AF2E070F5A521A85A5FB3DD2A62"
          "88947BCBD5E2265D3670BD6192EB2BF643964E2783D84AEC343F8E3571E4FCF09CBEEA94E80470AA7252D1C733A5535907E66C7B9F0B88B159DC2A7370EE47F13E7E134D3D05E5F53FAC"
          "640B784A9B0F183FE14217325626F487CC8D8CB9EAF0ABB174EE0B7076CF39C45037CEFDF3F1E61B5174581214C09870B72C39737EC4C46A96199B66CAD2990BCBE5BB1ABFDE99107C7F"
          "7289395BF2A433598EDE0B1969F23DB949AFB5B4D33831DAE6C641A6355F8F9BF16CDFFC4BF86891B93A557C2152AC8A1DE51C995344CC10CC4BC9ECFBB4E418BED0F334AF165339E672"
          "5DC4FC1E995521E1BE8A566D59B57CD130903B42D07087D63646EF8FC1E9E9071BB67A123FDEC3F37638CDAF0F4BF3084074069171C17885B9431AD908D36A6F8A826256D2AA34F8AA07"
          "31A357C060DB8E80FEFD61B1C323890E640633B98D175D4D6EBFF800A71CFC864EC02837DE9D0E079F0F400ACAFD56805CB273E631BA395D23E86ACF6EAE63181A5AFE1F0A361CBBD5FE"
          "FEB7DB0C95591EC3128E80DFBEA9CA0F89FC035D761C05D41E7A010892C42E8E2AF62AA604F4E214C0BB08075481F9CC307A555ADF333B9424F209B89F161032E413B047AE5AB0AA1564"
          "3BB4C643446D2C9829EB256E7375CE9639047A24A44F4DA446B7359556F3AB3484C56511C68A140DC0531F653105800D9F20990D4EBDC5CEEA918D7AE95C0D7EC69A00D6A936B25FC19B"
          "9DFC5561400F046191136C367038D6A9D0E0AE30DCDC4733712CBD5A2AEE35315EFF5C1A7E085B68C5CF0C64C495DF2CA6F030DB04480A2E11D4A0A0DBF29D9463D5B9E41E346E49C894"
          "D5E43993C834C4746309C886D6131F2F92155CA1160BAC9660802A947B5ABA94B35357D13FDF02D2AEABEF568912F68AE5D3A60214F6D00C4DD9F0AF09EB0BF961CD9F27251D46899C28"
          "D87080BA2EAD3E8193F51A789706EC32AACEE9F4B14EECA91A252FE894B30DC3938ABBBE7D217948CAE79CE3ADB4D7D7DF6756F3099F2543ED3B522BACAB257503C9E07FCD32CC32FA9A"
          "A17977EC05BC5FE0F5954D51F160F52D33F93166AF68AA90261B3F5AD273ADACF2D0CB5B0C5402BFA62DA67A52DCDDFA463E72D2C005F1AC0EA3CB62364EE3419333612E07BF68500613"
          "7A592E2FCD58398265C4FF9E11E70C2B79152E4604B4F94676E955BCFF4DFC429A8A88728B95BFC2826E25BA6EAB9CFB066C9911693EFFF242F7B51C3CB88546143B8AB2142DD3C9BDA5"
          "5D16FE3084A86B743F294DD9D0AA84F3CE3B083A5879A4762A756E9B41F4BDF8B71418073B0A0D4A9C131882455ECE23E50324C5FEEA217920B0F3109DCBDC81762E41B7CA271EFAC8E3"
          "9CC26EBE085ABDBF6B314A38929799FB7FEEBEE2E20B97056ED17EF3881E6E89330314DD7E9C629C46DFDB925C7C5F5D243F159D964691745CD46579FD0696479E1C49CBD2AF879A2BCE"
          "8576619CCA7B6E516E6C94C1087441A81F11B9A83535B24DDC725A81A9D1FF62DA2804C8D84C6E382065574282EA1F23EAF648CFA9767AFB098FD81654D76133F5F39BCC762C9BC31F7F"
          "4665CC0EFA929B5C05DEDD76143C63DC7018AB130C108EA901BE32B9D911B66DA13A1528C32A9694C899A772F8E1FE00C17ECEB343E737D72CBA06CF5DDAC9A4D3DF7EF391CF6595A6D8"
          "C14B0D80F93023B1B3D4371239DA98B67A1B6A379422616282A16E8D1F97A130BAF21E572BCCA91ABB760EAC6957F9B1B05E49E2D181874AC6DD160D1C717B73BD28EF55F08D47466D5A"
          "EF754814C7E206FA9E2EC53385D14D52F7769D95EA50524FFB20DC7275B04D71D1967E3BBC6ED481F1FC5A15E78A1FD967D96045625645DBD173CCCDD97661E995CE47D6B3EAD96EE6D0"
          "06A5CE6F4C9777FE2E3F91BEBE877CAC8C6486DFCE0315DC71BBB93879759B8981C5FF2E11DEB809ABF4280EE93D1711E73645B410ACB518538CE3D4BDA1E355C988F068165668E99D6A"
          "8DE356B4B13298036AD05D526C4A5E2591612A477B7E86550ADDE128CD71EE651D4499699000A02979E42BBCCF32C83B1EB0FF99AA4D352E20E0B3382422DF2C2ED4CE90C94CF1A359E9"
          "2EF971DC6DB06047A333C2EBE827EB6D5F2811FDBE0BF0F12BF2094E0DCD8E418F3F691A60CEB0CEFB6F45F47883D6B9F320950E91266740C6DBFAD6B3CFE56DE0AA6658B0DC893BB6E4"
          "9E6294537A7878E86CFC8E6C150675DB1A89D188EA6EFE7D88FF57B39B8610E392811EE097CA61C4841E0FBD346ED3FF6A5E412ACB0D9F13022DF2E7FDAA8E0FACE7366C8FFE6F446995"
          "B564FC3D59C70FECDB60A25E28650417157F43F3E72C3AFC601509641CFD099A78130E1F7BA8333502AD4F036F46411A43D035E2CA0ED0C346D9AAC5DF05196C95C38E6E52763ED896B6"
          "D02464A910DDA6CCA34024E3B9C3723D26E2886AD724DD56EA285E8E4B60BEEC924D55DD700C38877B74552FEA1F8741579B02061416131DB390F628522885236B51F7AEF23167D3A5FE"
          "5EADCD88B0E99B2B6BC56B0DEA4FB22146294766C28E5E7C834DBDCB6BFDD7BD8455252522FF2E974F6FD3FDA176749B7CDCED5B9ABA092B2982C89CB7D2B36348928C8F01170618ECFF"
          "14D9E0EED9D88D97E38BCF7A837F674BE5243FC624C8AFD3D105F462BFA939B8143A3A98F78FBB8C915E00BDBBF707B12C45784F4D1CB1426B583A0D5FBEC1F5EA6D0067C090168CB788"
          "E532ACA770C7BE366EC07E7808F1892B00000006ED1CE8C6E437918D43FBA7BD9385694C41182703F6B7F704DEEDD9384BA6F8BC362C948646B3C9848803E6D9BA1F7D3967F709CDDD35"
          "DC77D60356F0C36808900B491CB4ECBBABEC128E7C81A46E62A67B57640A0A78BE1CBF7DD9D419A10CD8686D16621A80816BFDB5BDC56211D72CA70B81F1117D129529A7570CF79CF52A"
          "7028A48538ECDD3B38D3D5D62D26246595C4FB73A525A5ED2C30524EBB1D8CC82E0C19BC4977C6898FF95FD3D310B0BAE71696CEF93C6A552456BF96E9D075E383BB7543C675842BAFBF"
          "C7CDB88483B3276C29D4F0A341C2D406E40D4653B7E4D045851ACF6A0A0EA9C710B805CCED4635EE8C107362F0FC8D80C14D0AC49C516703D26D14752F34C1C0D2C4247581C18C2CF4DE"
          "48E9CE949BE7C888E9CAEBE4A415E291FD107D21DC1F084B1158208249F28F4F7C7E931BA7B3BD0D824A4570",
      },
      {
          &key,
          "hashsig/hashsig-sig-01.json",
          "D28444A101382DA1044649747342696754546869732069732074686520636F6E74656E742E5909D000000000000000000000000391291DE76CE6E24D1E2A9B60266519BC8CE889F814DE"
          "B0FC00EDD3129DE3AB9B9AA5B5AC783BDF0FE689F57FB204F1992DBC1CE2484F316C74BCE3F2094CFA8E96A4A9548CEAD0F78EE5D549510D1910F647320448AE27ECCE77249802A0C39C"
          "645BF8DB08573AF52C93D91FD0E217F245C752C176B81514EB6E3067E0FBB329225EAA88C7D21635E32AE84213F89018CB06F1B84E61EAC348B690D7C6265C19F9D868952D99826AECD4"
          "17B5279DD674CD951C306016CFEE4FEE3BFCF5EE5A5AD08B5B4F53BC93995F26CFE7C0C1C5BA2574C1F2D8470993E8BD47EF9B9CF309EF895226E92BE60683459009611DEFBB9A432179"
          "56A0AB2959BBDA0FECA39DE37E7C4A6CD8A5314D6B02B377406D5A5E589E91FEAA9F2E4EC1682BA1F633C7784499323E40DA651F71D3C19E38C634D898B0C508324C0BFCF7C5F0A8C014"
          "B4AF200A739F96CDDBA94DAF86CE80C76158D4F5CF3CD2BA9F1393DF47E556887F9168540485242A05EC6BCC76659EC3D0D2FEDAE3FD1608A701C226F5FD83C9B1ED3152DDAC7426C30E"
          "3390BEC8F1DA6174ABE8D3568C9B76B149EB077D61AC15B8FB11B8CE5F9D14E448E216F375E1F96A52D39619459B131026143E8809BAD408F5EF66CD3DA227431E68670C0B4B2C3801E1"
          "E9025B1EBED218E0956967158CCC274C704ADCD8CC23C149A89EDA25478742DADC15F233844535E4021000B5D557313D4F271875680E6D5E7F6681FDD19F8B9A748CABB2377AAC1387FD"
          "B80E618EB7D69A368729CA9A092AF91EBE1C584C35FE62734D1D53D10B35DD02093A201C889AD37A558B610F1AB00179A11F881600E944CEDC47A7AE6D828009D7C61FFEA9DD5AA54064"
          "08E2E85DC056E47B57589EABA18E792F4631AF62D4588A1818167274273C69E7A0735BE5DADA7E224E3B178B3B093212EB74E762F564A26D577AA22EBD8C7B4A999419908E2F2D9C8689"
          "DC923905C198B9EE335D1E0DE6D689655F446DFFEA997B6E58F5F648415233EDE3B9D8A2DB29E8C3DDE5D8DBD55E6348CD9F421783DB090E087DE46425D62D513597B00D7DE32FAD8775"
          "2A79CEE8B2A38B1E0F2562836721CBBFBA20F131130C009A436B93A0BB44FCBB86228B1BF1A35F4FC626817924EAEBD5B78D64A7970D18DADE90CF0AD759B1C45D953C08CD1189685077"
          "C5A56069DA0944669D797496F8F886FEA6F792598DB2AC66B657AF838ED3C3A914DFFBB164170A1F63250B125EDA53ECAEAF6EE0D2B8A3C804104D7ED575B66469BC59F37EEC6C6F6FB1"
          "9E0F7EA02D7C85306230063ADB58950589F6FFAFF1407233828AE0DFBE5889E5DE00BB640A4BC24C3F704488FA669676A9EBBBED399B8A9AC0EE4CC944F864B21F642E04F610319AC927"
          "1F8BD820E77E41DAC6553D234D9480E26142C0FA37416651D6450E1F2082BD0213D6783E1AE3CC5C5AF677C3316E173BA4716D6BC8A9D89383F8B025A0859B99A43DAEAF8DDAED46D223"
          "B9B503651A67560BFEB2F35BA544722620EC4086DCC77E6E87BB53F1F18C38368662BE460EDE31325CAEAEBF018A6FA9D32E3C3A6898E15FE114DCCE51241C61AFABC36DE3608B4D3427"
          "12A833615C6131E89E1D46B713D9638A08B5A768D53AF0298B9C874DED7084358223840C2E78CD6FBFCA695279A4C1883BB7DE81B04A069DE8277F7F5109C16938347A643713C9AC36FF"
          "FC8BF141E899F48BC25C7B636D43BEBCFA7742D4E1462263E56732AD2021EEF8CE84023C4959CFD250343D62074724907DE9D49EA2F6C968FD9E9BF28FEAFCDC81702108805DEC60F278"
          "1272D2425A6EE29C66122D2C557867C1A5AED82131E06FC384ECF49017E1C9D6CF63B9F2285CCF890CBB9BBF796E0FD02101948B7EF6638493677B33FD787D9D3FC2C7CC7BABC21AF8C7"
          "48AFB80CF86B45DC89F0B9C7959621E85B98B542DC263DB9255273BB9054A7F194748F28373BA123D73FC71FEF43E7E2AC9A80008E85CF2F04AA433075DFC54C4DE24A341EBF7CF1E6B3"
          "83DBBA85898FDC368017FD67C153E7A991A3A3CEE6DAE4FBE2FE6F25A8DF314140A8176C8E6FD0C6F042CA66EB6ABBA9A2502BB6DFA52960AE86A942A673E4E45439594FEFCD2974E205"
          "54D1DC70B8E034FD1787801343D5F6EDC95CE0348C25727C771526E3FD4EFFB5F16E25A1EA3DCD8282E778E91AE9B339A5013C77FD6EA2432704E293F5E82A24121C73900BEA4B4EF14A"
          "2ADC1AB3C68224BAE1DE9C61A48B84E84C1B0E83701BE3D988012A24FA40268C8D6EF1FD2818AE8E4B6F52F89BEAB6BFDD1FF1B7ECD573EDFF3703B800B5B2A206F451F1BF2713B4AE90"
          "85BD7FE34AD4306A290E4CDB7817EE9AB7CCFB816D002B619F77D46D7DD0F8EEFE10F5C0F9723FFDB14CA75A185543770F41508B9983D5EED78225BC6E21F876BFDD08FE8BC63E0CB253"
          "C7DFC67C330897C515244F3F631682F2141EBA48CA86DFFF9206F78EDCB9DEC4B2371AEDDBE141EF96A10957E29A94747C4438FB30B14D37E7428EB7FBE4F9D870E72F35F55847F23037"
          "4BDF56DCAE6C129B4468EBAEDC340FF4CC160C6B410E2D8989488AC8EF9A9FEBBF65AD4FDFBA532A8122EF82DC1A4FFC361CBF9F752B36AA9821683D5F3F5842F90134EB423D5CBC7685"
          "8B4C0A7BA798EC94A089FDB24B5B25F42D7B6BB8192F07B98EB2DE1FE7BC8B6C740FA5CDE6FB4890D2F1791664A96C25A0A71A541025B5EC825EED91F393505473E21D0620177993982E"
          "6C1B6BF91B777B5AB5739B84946C518C7E6AA0E689E9AD1D34E6EF6CA0E709C4AEFECD6F2594B017940742ACEB72C5A52D7D47A3A74F9D09EB84CF82B349DE32278A771CEBC31EBC580C"
          "09B11799B1F0E6D11D75B17E389D259C531F957A1E699250711DF2E36F64F21C92EFF698A392D92DF0B2F91991408A076B83149E025A9FFBA1FF1CAED916A2FC1AC5D3081C30B5C64B7D"
          "677C314B6E76AC20ED8BB4A4C0EB465AE5C0C265969264B27E6D54C266F79E58E2FA6A381069090BEC00189562ABCF831ADC86A05A2FC7FFAA70DBD3FA60E09D447CD76B2FF2B851C38E"
          "72650ADE093BA8BD000000067B95DE445ABF89161DFF4B91A4A9E3BF156A39A4660F98F06BF3F017686D9DFC362C948646B3C9848803E6D9BA1F7D3967F709CDDD35DC77D60356F0C368"
          "08900B491CB4ECBBABEC128E7C81A46E62A67B57640A0A78BE1CBF7DD9D419A10CD8686D16621A80816BFDB5BDC56211D72CA70B81F1117D129529A7570CF79CF52A7028A48538ECDD3B"
          "38D3D5D62D26246595C4FB73A525A5ED2C30524EBB1D8CC82E0C19BC4977C6898FF95FD3D310B0BAE71696CEF93C6A552456BF96E9D075E383BB7543C675842BAFBFC7CDB88483B3276C"
          "29D4F0A341C2D406E40D4653B7E4D045851ACF6A0A0EA9C710B805CCED4635EE8C107362F0FC8D80C14D0AC49C516703D26D14752F34C1C0D2C4247581C18C2CF4DE48E9CE949BE7C888"
          "E9CAEBE4A415E291FD107D21DC1F084B1158208249F28F4F7C7E931BA7B3BD0D824A4570",
      },
#endif
        // hkdf-aes-examples
        {
            &aes_ccm_key,
            "hkdf-aes-examples/hmac-aes-128-01.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581CEFCF947DDDD19D2E894C9388B6032A987A06FF7E64A88D3C11075E9A818343A1012BA233506161626263636464656566"
            "6667676868044A6F75722D73656372657440",
        },
        {
            &key,
            "hkdf-aes-examples/hmac-aes-128-02.json",
            "D8608443A1010BA1054DBFE89563EE070CE187BDF1C472581C77B02BF7C3C9DAC2AFF027F79C8B6E50AFDBA25F5F48ED4E04C33D76818343A1012BA233506161626263636464656566"
            "6667676868044A6F75722D73656372657440",
            {},
            {},
            1,
        },
        // hkdf-hmac-sha-examples
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-01.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C5192B2794858242DE0BC141017137EDE1F597AB41F58D809452F3A2B818343A10129A233506161626263636464656566"
            "6667676868044A6F75722D73656372657440",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-02.json",
            "D8608443A1010BA1054DBFE89563EE070CE187BDF1C472581C73C739B6EC556323FDB6B123CF271E77D1465F615A2922743B006ED9818343A10129A233506161626263636464656566"
            "6667676868044A6F75722D73656372657440",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-03.json",
            "D8618543A10105A054546869732069732074686520636F6E74656E742E582092356FD58B43BB978B1A627A7353F2094E1CFCEAFBC3D0FCF15BCE74D260FD98818343A10129A2335061"
            "616262636364646565666667676868044A6F75722D73656372657440",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-04.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E584071B8F7CBD4590A7C58E9E773B309DABD5BAD23939E5EA9DF603227635B19C2CC4EA085D8A2D4D4346AA8"
            "229D9395184FEEE2F5B73F3FEFCD32E4A037B149F2A0818343A10129A2335061616262636364646565666667676868044A6F75722D73656372657440",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-05.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581CC4CEC13466EEAA20D92E94FBD1FE9B97793AF44A21408EDE75A96F47818343A10129A433506161626263636464656566"
            "6667676868044A6F75722D736563726574344653656E6465723749526563697069656E7440",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-06.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C08F7BF5AE142A79ED4BDEDC978559D762C394444527F2F797AECC298818343A10129A433506161626263636464656566"
            "6667676868044A6F75722D7365637265743544533130313818445231303240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-07.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C08F7BF5AE142A79ED4BDEDC978559D762C394444527F2F797AECC298818343A10129A433506161626263636464656566"
            "6667676868044A6F75722D7365637265743544533130313818445231303240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-08.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C29A84BB9DC7F2E130DE1BB5E5A9240DE247D263A02735B336DA27ECD818343A10129A33647532D6F74686572044A6F75"
            "722D736563726574381947522D6F7468657240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-09.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581CE1FC8942C576DE776EEC2DCBE302743C82404AB8642A4D9193A90EC2818343A10129A5344653656E646572044A6F7572"
            "2D7365637265743749526563697069656E743544533130313818445231303240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-10.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C693A42189916B38DDCB5B6F5CF65E4E39D1AFC74B7E9B5E7B0B997EF818343A10129A5344653656E646572044A6F7572"
            "2D7365637265743749526563697069656E743647532D6F74686572381947522D6F7468657240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-11.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581CCF27AF6F9206CC99B34DAE74162E7F2117E2B30CF587169F3B073F5C818343A10129A5354453313031044A6F75722D73"
            "6563726574381844523130323647532D6F74686572381947522D6F7468657240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-12.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C8D9129CCD0EEFA0526A2F71AD91E19ADF013C0454C0DAC56CDE8F31E818343A10129A7344653656E646572044A6F7572"
            "2D7365637265743749526563697069656E74354453313031381844523130323647532D6F74686572381947522D6F7468657240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-13.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C21331CC990421BAE71871E7B1A9C760E62C8B09C66DB6F3298D94B21818343A10129A2344653656E646572044A6F7572"
            "2D73656372657440",
            {
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                "5075626c6963204f74686572",  // "Public Other"
            },
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-256-14.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581CF5CB7489E7F933D1444438D671633D2A4DB756BB5930385B53508700818343A10129A1044A6F75722D7365637265744"
            "0",
            {
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                "50726976617465204f746865722044617461",  // "Private Other Data"
            },
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-01.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C97B849AA156A3C7FE2BEDB813E03CC769EAD876A45B05778B3ACF2C1818343A1012AA233506161626263636464656566"
            "6667676868044A6F75722D73656372657440",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-02.json",
            "D8608443A1010BA1054DBFE89563EE070CE187BDF1C472581C0EECA76865429484BA6D6916E900BABCC47982549D706B67F1EE71D1818343A1012AA233506161626263636464656566"
            "6667676868044A6F75722D73656372657440",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-03.json",
            "D8618543A10105A054546869732069732074686520636F6E74656E742E5820E248C0CC50FAAF759CDA500035245D160B74A96A20234B764706D8E7911C96FD818343A1012AA2335061"
            "616262636364646565666667676868044A6F75722D73656372657440",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-04.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840391518189364FE41270F2C05931103AF448901E21B1BFA5816E54E57A828C192C226AF60617AC9D51B97"
            "56F2231CC3CBB9D72A2BD6BECFCDB0B90E4C05CC3F2A818343A1012AA2335061616262636364646565666667676868044A6F75722D73656372657440",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-05.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C0D70785FF421D68EB3A6D9B22D4C24B0A5617A3AD01D4F31DE108329818343A1012AA433506161626263636464656566"
            "6667676868044A6F75722D736563726574344653656E6465723749526563697069656E7440",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-06.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C052ABDCC369C4EA59418DB1B35FB739A971FE6D17EC517404B0932C4818343A1012AA433506161626263636464656566"
            "6667676868044A6F75722D7365637265743544533130313818445231303240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-07.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C052ABDCC369C4EA59418DB1B35FB739A971FE6D17EC517404B0932C4818343A1012AA433506161626263636464656566"
            "6667676868044A6F75722D7365637265743544533130313818445231303240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-08.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C5B6C491745F0F78C02706828195BAFE5124C3FF2E748FC7E04B98B87818343A1012AA33647532D6F74686572044A6F75"
            "722D736563726574381947522D6F7468657240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-09.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581CDF9D8A2E30420AEABB1FFF3A2CFFCB6350921B810F1AA0134EEE27FE818343A1012AA5344653656E646572044A6F7572"
            "2D7365637265743749526563697069656E743544533130313818445231303240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-10.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581CD0050523271621FB792EF7DEA199BF7D62EBD484C96155CE992ADDC0818343A1012AA5344653656E646572044A6F7572"
            "2D7365637265743749526563697069656E743647532D6F74686572381947522D6F7468657240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-11.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C79FFAE108F68449FCA0CF291D6C1770A3C8CC312855D19642304EBCD818343A1012AA5354453313031044A6F75722D73"
            "6563726574381844523130323647532D6F74686572381947522D6F7468657240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-12.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581CD7751DCCE7FF4E13EDE04486975481978F3E3145D762A250640159B0818343A1012AA7344653656E646572044A6F7572"
            "2D7365637265743749526563697069656E74354453313031381844523130323647532D6F74686572381947522D6F7468657240",
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-13.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581C90F652D7E399AE8E8734541E081203EDB8D24ED161787AE85C14D443818343A1012AA2344653656E646572044A6F7572"
            "2D73656372657440",
            {
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                "5075626c6963204f74686572",  // "Public Other"
            },
        },
        {
            &key,
            "hkdf-hmac-sha-examples/hmac-sha-512-14.json",
            "D8608443A1010AA1054DBFE89563EE070CE187BDF1C472581CA6A8C745350E75285AC4AF50B5742D56D930E1ADC5406233BD11FE27818343A1012AA1044A6F75722D7365637265744"
            "0",
            {
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                "50726976617465204f746865722044617461",  // "Private Other Data"
            },
        },
        // hmac-examples
        {
            &key,
            "hmac-examples/HMac-01.json",
            "D8618543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6818340A20125044A6F75"
            "722D73656372657440",
        },
        {
            &key,
            "hmac-examples/HMac-02.json",
            "D8618543A10106A054546869732069732074686520636F6E74656E742E5830B3097F70009A11507409598A83E15BBBBF1982DCE28E5AB6D5A6AFF6897BD24BB8B7479622C9401B2409"
            "0D458206D587818340A2012504467365632D343840",
        },
        {
            &key,
            "hmac-examples/HMac-03.json",
            "D8618543A10107A054546869732069732074686520636F6E74656E742E5840CD28A6B3CFBBBF214851B906E050056CB438A8B88905B8B7461977022711A9D8AC5DBC54E29A56D92604"
            "6B40FC2607C25B344454AA5F68DE09A3E525D3865A05818340A2012504467365632D363440",
        },
        {
            &key,
            "hmac-examples/HMac-04.json",
            "D8618543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F7818340A20125044A6F75"
            "722D73656372657440",
        },
        {
            &key,
            "hmac-examples/HMac-05.json",
            "D8618543A10104A054546869732069732074686520636F6E74656E742E486F35CAB779F77833818340A20125044A6F75722D73656372657440",
        },
        {
            &key,
            "hmac-examples/HMac-enc-01.json",
            "D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58",
        },
        {
            &key,
            "hmac-examples/HMac-enc-02.json",
            "D18443A10106A054546869732069732074686520636F6E74656E742E5830998D26C6459AAEECF44ED20CE00C8CCEDF0A1F3D22A92FC05DB08C5AEB1CB594CAAF5A5C5E2E9D01CCE7E7"
            "7A93AA8C62",
        },
        {
            &key,
            "hmac-examples/HMac-enc-03.json",
            "D18443A10107A054546869732069732074686520636F6E74656E742E58404A555BF971F7C1891D9DDF304A1A132E2D6F817449474D813E6D04D65962BED8BBA70C17E1F5308FA39962"
            "959A4B9B8D7DA8E6D849B209DCD3E98CC0F11EDDF2",
        },
        {
            &key,
            "hmac-examples/HMac-enc-04.json",
            "D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C59",
        },
        {
            &key,
            "hmac-examples/HMac-enc-05.json",
            "D18443A10104A054546869732069732074686520636F6E74656E742E4811F9E357975FB849",
        },
        // mac0-tests
        // mac-tests
        {
            &key,
            "mac-tests/HMac-01.json",
            "D8608443A10103A1054C769C56F939ADAEFCFA9AAD2F5824800DC70E6406E03E7FCCA3A5F40FDAB565093D89FD41B5FBD401BE9E7D45732AA2719E17818340A201382904581F6D6572"
            "6961646F632E6272616E64796275636B407273612E6578616D706C6559010072D8DA91014D055908703CADF1D9813714B365E899788A774AABE8233FB21F44DF183BEF48DE5B4C731F"
            "CD981D124E3640B042A4F6248FEA04BDD1BBE63DE2CB4351D333A528E6ACC831FC08AF93DB15069B9D9C6E9E63282DC0E74D0A4D662C762BE0EF29A597394D23032BF2F0D49A9DC15A"
            "13DB0E672BEBA1E1D92966CBFD964F1FE813EE42166545339F8FB61B992271E46433F7DF991DC11800710268671A571D6497BF48D147FE114A1572E261AF7866A05C762901052DB353"
            "153AEB07C0BBA307DE7890082A980AED9D28A363512E605D58EEB8B05A80848FB1CF7B8C8447C958084D758AB82D79B4E7F81077A51AA6E3B94747FCEB4ADC44EF559699",
        },
        {
            &key,
            "mac-tests/mac-pass-01.json",
            "D8618541A0A1010554546869732069732074686520636F6E74656E742E5820C2EBE664C1D996AA3026824BBBB7CAA454E2CC4212181AD9F34C7879CBA1972E818340A20125044A6F75"
            "722D73656372657440",
        },
        {
            &key,
            "mac-tests/mac-pass-02.json",
            "D18440A1010554546869732069732074686520636F6E74656E742E58200FECAEC59BB46CC8A488AACA4B205E322DD52696B75A45768D3C302DD4BAE2F7",
            {
                "ff00ee11dd22cc33bb44aa559966",
            },
        },
    // RFC8152
#if 0
        {
            &rfc8152_pubkeys,
            "RFC8152/Appendix_B.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E2852948658F0811139868826E89218A75715B818440A101225818DBD43C4E9D"
            "719C27C6275C67D628D493F090593DB8218F11818344A1013818A220A401022001215820B2ADD44368EA6D641F9CA9AF308B4079AEB519F11E9B8A55A600B21233E86E6822F4045824"
            "6D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
            {},
            {},
            1,
        },
#endif
        {
            &rfc8152_pubkeys,
            "RFC8152/Appendix_C_1_1.json",
            "D8628440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45"
            "AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A",
        },
        {
            &rfc8152_pubkeys,
            "RFC8152/Appendix_C_1_2.json",
            "D8628440A054546869732069732074686520636F6E74656E742E828343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45"
            "AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A8344A1013823A104581E62696C626F2E62616767696E7340686F626269746F6E2E6578616D706C65588400"
            "A2D28A7C2BDB1587877420F65ADF7D0B9A06635DD1DE64BB62974C863F0B160DD2163734034E6AC003B01E8705524C5C4CA479A952F0247EE8CB0B4FB7397BA08D009E0C8BF482270C"
            "C5771AA143966E5A469A09F613488030C5B07EC6D722E3835ADB5B2D8C44E95FFB13877DD2582866883535DE3BB03D01753F83AB87BB4F7A0297",
        },
        {
            &rfc8152_pubkeys,
            "RFC8152/Appendix_C_1_3.json",
            "D8628440A1078343A10126A10442313158405AC05E289D5D0E1B0A7F048A5D2B643813DED50BC9E49220F4F7278F85F19D4A77D655C9D3B51E805A74B099E1E085AACD97FC29D72F88"
            "7E8802BB6650CCEB2C54546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19"
            "D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A",
        },
        {
            &rfc8152_pubkeys,
            "RFC8152/Appendix_C_1_4.json",
            "D8628456A2687265736572766564F40281687265736572766564A054546869732069732074686520636F6E74656E742E818343A10126A10442313158403FC54702AA56E1B2CB202842"
            "94C9106A63F91BAC658D69351210A031D8FC7C5FF3E4BE39445B1A3E83E1510D1ACA2F2E8A7C081C7645042B18ABA9D1FAD1BD9C",
        },
        {
            &rfc8152_pubkeys,
            "RFC8152/Appendix_C_2_1.json",
            "D28443A10126A10442313154546869732069732074686520636F6E74656E742E58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E2AF9A291AA32E1"
            "4AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36",
        },
        {
            &rfc8152_privkeys,
            "RFC8152/Appendix_C_3_1.json",
            "D8608443A10101A1054CC9CF4DF2FE6C632BF788641358247ADBE2709CA818FB415F1E5DF66F4E1A51053BA6D65A1A0C52A357DA7A644B8070A151B0818344A1013818A220A4010220"
            "0121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D628022F50458246D65726961646F632E6272616E64796275636B406275636B6C616E642E657861"
            "6D706C6540",
        },
        {
            &rfc8152_privkeys,
            "RFC8152/Appendix_C_3_2.json",
            "D8608443A1010AA1054D89F52F65A1C580933B5261A76C581C753548A19B1307084CA7B2056924ED95F2E3B17006DFE931B687B847818343A10129A233506161626263636464656566"
            "6667676868044A6F75722D73656372657440",
            {
                nullptr, nullptr,
                "6c69676874696e672d636c69656e74",  // "lighting-client",
                nullptr, nullptr,
                "6c69676874696e672d736572766572",  // "lighting-server",
                nullptr, nullptr,
                "456e6372797074696f6e204578616d706c65203032",  // "Encryption Example 02",
            },
        },
        {
            &rfc8152_privkeys,
            "RFC8152/Appendix_C_3_3.json",
            "D8608443A10101A2054CC9CF4DF2FE6C632BF7886413078344A1013823A104581E62696C626F2E62616767696E7340686F626269746F6E2E6578616D706C65588400929663C8789BB2"
            "8177AE28467E66377DA12302D7F9594D2999AFA5DFA531294F8896F2B6CDF1740014F4C7F1A358E3A6CF57F4ED6FB02FCF8F7AA989F5DFD07F0700A3A7D8F3C604BA70FA9411BD10C2"
            "591B483E1D2C31DE003183E434D8FBA18F17A4C7E3DFA003AC1CF3D30D44D2533C4989D3AC38C38B71481CC3430C9D65E7DDFF58247ADBE2709CA818FB415F1E5DF66F4E1A51053BA6"
            "D65A1A0C52A357DA7A644B8070A151B0818344A1013818A220A40102200121582098F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D628022F50458246D6572"
            "6961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6540",
        },
        {
            &rfc8152_privkeys,
            "RFC8152/Appendix_C_3_4.json",
            "D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582464F84D913BA60A76070A9A48F26E97E863E28529D8F5335E5F0165EEE976B4A5F6C6F09D818344A101381FA32258217065"
            "72656772696E2E746F6F6B407475636B626F726F7567682E6578616D706C650458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65354201"
            "01581841E0D76F579DBD0D936A662D54D8582037DE2E366FDE1C62",
            {
                "0011bbcc22dd44ee55ff660077",  // external
            },
        },
        {
            &rfc8152_privkeys_c4,
            "RFC8152/Appendix_C_4_1.json",
            "D08343A1010AA1054D89F52F65A1C580933B5261A78C581C5974E1B99A3A4CC09A659AA2E9E7FFF161D38CE71CB45CE460FFB569",
        },
        {
            &rfc8152_privkeys_c4,
            "RFC8152/Appendix_C_4_2.json",
            "D08343A1010AA1064261A7581C252A8911D465C125B6764739700F0141ED09192DE139E053BD09ABCA",
            {
                nullptr,
                "89F52F65A1C5809300000061A7",
            },
        },
        {
            &rfc8152_privkeys,
            "RFC8152/Appendix_C_5_1.json",
            "D8618543A1010FA054546869732069732074686520636F6E74656E742E489E1226BA1F81B848818340A20125044A6F75722D73656372657440",
        },
        {
            &rfc8152_privkeys,
            "RFC8152/Appendix_C_5_2.json",
            "D8618543A10105A054546869732069732074686520636F6E74656E742E582081A03448ACD3D305376EAA11FB3FE416A955BE2CBE7EC96F012C994BC3F16A41818344A101381AA32258"
            "21706572656772696E2E746F6F6B407475636B626F726F7567682E6578616D706C650458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C65"
            "3558404D8553E7E74F3C6A3A9DD3EF286A8195CBF8A23D19558CCFEC7D34B824F42D92BD06BD2C7F0271F0214E141FB779AE2856ABF585A58368B017E7F2A9E5CE4DB540",
        },
        {
            &rfc8152_privkeys,
            "RFC8152/Appendix_C_5_3.json",
            "D8618543A1010EA054546869732069732074686520636F6E74656E742E4836F5AFAF0BAB5D43818340A2012404582430313863306165352D346439622D343731622D626664362D6565"
            "663331346263373033375818711AB0DC2FC4585DCE27EFFA6781C8093EBA906F227B6EB0",
        },
        {
            &rfc8152_privkeys,
            "RFC8152/Appendix_C_5_4.json",
            "D8618543A10105A054546869732069732074686520636F6E74656E742E5820BF48235E809B5C42E995F2B7D5FA13620E7ED834E337F6AA43DF161E49E9323E828344A101381CA220A4"
            "010220032158420043B12669ACAC3FD27898FFBA0BCD2E6C366D53BC4DB71F909A759304ACFB5E18CDC7BA0B13FF8C7636271A6924B1AC63C02688075B55EF2D613574E7DC242F79C3"
            "22F504581E62696C626F2E62616767696E7340686F626269746F6E2E6578616D706C655828339BC4F79984CDC6B3E6CE5F315A4C7D2B0AC466FCEA69E8C07DFBCA5BB1F661BC5F8E0D"
            "F9E3EFF58340A2012404582430313863306165352D346439622D343731622D626664362D65656633313462633730333758280B2C7CFCE04E98276342D6476A7723C090DFDD15F9A518"
            "E7736549E998370695E6D6A83B4AE507BB",
        },
        // rsa-oaep-examples
        {
            &key,
            "rsa-oaep-examples/ps-128gcm-01.json",
            "D8608443A10101A1054CD97AB3A5C72D2F0D7E5F8D5E5824613C8B53A5BBCD3A79F1314C668CB9EEFD362C1A78FE58AC2F7650B9F42284DEDDF6201C818340A201382704581F6D6572"
            "6961646F632E6272616E64796275636B407273612E6578616D706C655901007994141368C5FE18D3C75C296D84B31ED1BD0B9DCDB2E9C3BBDF4A199124D03E5171E09BF90099396C34"
            "6FA62D2C2E54741169FB2FCA00ABE726CE0C4F55221E7A63001D39C2026EEE8AF9D3B2E8E97084C633470E32974D65C1E046A81319F8D04316710DA060F5F1A2AD304A220B7E9B11F8"
            "6B09C1689935039519F368AD6CD6E0154487E923C0DE431AEA6425774736FDEDE666F248A136B3A08F63208CEAFACDE9F61E4CFF8AC30A61A0E024B28B7B4B0F77C2547C5652F07EF7"
            "61A75A4193B989FA5C35E6A9297CD6895228C8E5B2559A9B7DD997753CBAEA6848337E200FF0F8042AA58B75839F79FFEF3C3A7F4AB9DE545A7B0646DF99908F2C8A80F4",
        },
        {
            &key,
            "rsa-oaep-examples/ps256-128gcm-01.json",
            "D8608443A10101A1054C3345EEF78452AAA67EAF7BEF582458B7F6B31FF4C2AC20AB5B2EE5B62D5BDC9A97BDF294E3F804AAD55F71D0986DFC375748818340A201382804581F6D6572"
            "6961646F632E6272616E64796275636B407273612E6578616D706C6559010071D19F9646F451B7C8F7560303DC62B64F17B50215682AFFEBC79423F2A4350DBB66AAEEF21218E4778F"
            "0CF22684A0144758DA5FB662E3B5468D84FFF7519C2A894ACF9C310A3A0F62B311767C935D9D93971F854DE3FF5AE307CE8D004BA1394E14380C6FED081056DB861AF5885659354354"
            "889A6006319B33E3055A8B550829662C83D58E5A563C3A4C43FB484672C20EDC16F0A94046B38E4D943C4B4C2A73F6D2EB7C682B2E94FF5AAAFF3007EBDBFB4B6A7204203CC91C1549"
            "CE64A7D3792F2FB78B9E6BB2B966EEE060A37DCC03BC4FDAFAE590EF8DC8198C8CCAF9289624F62C79483DD629C38C74FB092F3B383B0CAD3E58C91B21EB3EBE36407808",
        },
        {
            &key,
            "rsa-oaep-examples/ps512-128gcm-01.json",
            "D8608443A10103A1054C769C56F939ADAEFCFA9AAD2F5824800DC70E6406E03E7FCCA3A5F40FDAB565093D89FD41B5FBD401BE9E7D45732AA2719E17818340A201382904581F6D6572"
            "6961646F632E6272616E64796275636B407273612E6578616D706C6559010072D8DA91014D055908703CADF1D9813714B365E899788A774AABE8233FB21F44DF183BEF48DE5B4C731F"
            "CD981D124E3640B042A4F6248FEA04BDD1BBE63DE2CB4351D333A528E6ACC831FC08AF93DB15069B9D9C6E9E63282DC0E74D0A4D662C762BE0EF29A597394D23032BF2F0D49A9DC15A"
            "13DB0E672BEBA1E1D92966CBFD964F1FE813EE42166545339F8FB61B992271E46433F7DF991DC11800710268671A571D6497BF48D147FE114A1572E261AF7866A05C762901052DB353"
            "153AEB07C0BBA307DE7890082A980AED9D28A363512E605D58EEB8B05A80848FB1CF7B8C8447C958084D758AB82D79B4E7F81077A51AA6E3B94747FCEB4ADC44EF559699",
        },
        // rsa-pss-examples
        {
            &key,
            "rsa-pss-examples/rsa-pss-01.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818344A1013824A104581F6D65726961646F632E6272616E64796275636B407273612E6578616D706C655901"
            "003AD4027074989995F25E167F99C9B4096FDC5C242D438D30382AE7B30F83C88D5B5EBECB64D2256D58D3CCE5C47D343BFA532B117C2D04DF3FB20679A99CF3555A7DAE6098BD123B"
            "0F3441A1E50E897CBAA1B17CE171EBAB20AE2E10F16D6EE918D37AF102175979BE65EBCEDEB47519346EA3ED6D13B5741BC63742AE31342B10B46FE93F39B55FDD6E32128FD8B476FE"
            "D88F671F304D0943D2C7A33BCE48DF08E1F890CF5ACDA3EF46DA21981C3A687CFFF85EEB276A98612F38D6EE63644859D66A9AD49939EA290F7A9FDFED9AF1246930F522CB8C690956"
            "7DCBE2729716CB18A31E6F231DB3D69A7A432AA3D6FA1DEF9C9659616BEB626F158378E0FBDD",
        },
        {
            &key,
            "rsa-pss-examples/rsa-pss-02.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818344A1013825A104581F6D65726961646F632E6272616E64796275636B407273612E6578616D706C655901"
            "00556DA92BD3AC5C4908A94EAAEB1C5FB81B6C52C16D82C42D79375F61C3388DA5E87ABEB95530CE3BDC8979DB260C326DF13D9093D5F894C9E6D345C79AB7E64A3CF2A9A8F96CEA20"
            "FD55A3204AD5C62A4BD4128B09A34154E8E401E45A83180A82A8850ADC01BF5589F811DB189C88117157D81A145DFFB6BB0564B05CF9774FB1EE55787D2AD042EA48831090369EA32A"
            "7A4987C81D7BC70805505E41ACF62F9CB6CE585159FA146B30B2E2FC6E437841402BAEFC9B189C429C130B8F107F9DDB9FF9378CCF11E36B5179BDEFFF2DB3EE1990F8E1AD7F6631D3"
            "66C8A09BE078A23124CBFC59759AAEA0FEFF48AFA5420B508DA454E9AE4516AAB64C5B346812",
        },
        {
            &key,
            "rsa-pss-examples/rsa-pss-03.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818344A1013826A104581F6D65726961646F632E6272616E64796275636B407273612E6578616D706C655901"
            "00AE12E63095413B1B30C2CD31A7A9F9E541980D66A153C7A458A688DF3D531C3F68668EDE311AF8B2443990C9C8360F7458494AE8707241EC7EEB87B6679D73C160E33622FA966C5D"
            "7D645C1321F428BB10B09EAE89E17A503D707CB4ED5506D82A1F8059E9D6ED09265FE8E3C49405B2AE98EEFF0A52E268AEC9E342EEFC1D47A3B744343821B3D34D0F976B040F9BE80D"
            "672B876AD843987DFA66F8AB117EADA8B2BCD73725B409B84F729651CEC75092E7FD7562504F49E221B80A71693BC9C5AD438A183E0ED2A3494DDD7AFAD5EAD3B87F51AE1020375323"
            "79869A9D9E169B6C7ADF2D82EA22C656FFE4BF6A2A156F9DF05C53373A3B0AA815E9E5CED03D",
        },
    // sign1-tests
#if 0
        {
            &key,
            "sign1-tests/sign-pass-01.json",
            "D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04"
            "370097CE347087B233BF722B64072BEB4486BDA4031D27244F",
        },
#endif
        {
            &key,
            "sign1-tests/sign-pass-02.json",
            "D28443A10126A10442313154546869732069732074686520636F6E74656E742E584010729CD711CB3813D8D8E944A8DA7111E7B258C9BDCA6135F7AE1ADBEE9509891267837E1E33BD"
            "36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B",
            "11aa22bb33cc44dd55006699",
        },
    // sign-tests
#if 0
        {
            &key,
            "sign-tests/sign-pass-01.json",
            "D8628441A0A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC"
            "45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A",
        },
#endif
        {
            &key, "sign-tests/sign-pass-02.json",
            "D8628440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840CBB8DAD9BEAFB890E1A414124D8BFBC26BEDF2A94FCB5A882432BFF6D63E15F574EE"
            "B2AB51D83FA2CBF62672EBF4C7D993B0F4C2447647D831BA57CCA86B930A",
            "11aa22bb33cc44dd55006699",  // external
        },
#if 0
        {
            &key,
            "sign-tests/sign-pass-03.json",
            "8440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98"
            "B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A",
        },
#endif
        // X25519-tests
        {
            &key,
            "X25519-tests/x25519-hkdf-256-direct.json",
            "D8608443A10101A1054C9862E02EC874A0DF9FB123385824D2B07042F7BA47C61646CCA83AB97FD23AF21F0D2AC75DCB47A9FC293015D8F098AE9C1B818344A1013818A220A3010120"
            "0421582072FC171C21BF5C682C64D2EF3A71AC877B40013D3754F63D4C3C3A965F1BA77604485832353531392D3140",
        },
        {
            &key,
            "X25519-tests/x25519-ss-hkdf-256-direct.json",
            "D8608443A10101A1054CCDA8E5632E1501A698960E2B582460F0E32B4E511A964DFA671D95F00463D094EDC3FCB3DF782C0EDEDDD9436FB8CC79F482818344A101381AA3224C583235"
            "3531392D616C696365044A5832353531392D626F62355840607A92A41974DF0CB967E1C395B21F557469379E011781B6BE9189F40ADFECE4715AB87A79B36FB20913240FBB833FAB14"
            "B6A72A232A3CB18D1996A16256E44540",
        },
        // x509-examples (TODO - CRT, DER, x5bag, x5chain, x5t)
        {
            &key,
            "x509-examples/signed-01.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A2046E416C696365204C6F76656C61636518205901AD308201A930820150A00302010202144E"
            "3019548429A2893D04B8EDBA143B8F7D17B276300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F"
            "726974793020170D3230313230323137323732355A180F32303533313031303137323732355A3019311730150603550403130E416C696365204C6F76656C6163653059301306072A86"
            "48CE3D020106082A8648CE3D03010703420004863AA7BC0326716AA59DB5BF66CC660D0591D51E4891BC2E6A9BAFF5077D927CAD4EED482A7985BE019E9B1936C16E00190E8BCC48EE"
            "12D35FF89F0FC7A099CAA361305F300C0603551D130101FF04023000300F0603551D0F0101FF04050303078000301D0603551D0E041604141151555B01FF3F6DDDF9E5712AD3FF72A2"
            "D94D62301F0603551D230418301680141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022038FF9207872BA4D685700774783D35BE5B45"
            "AF59265A8567AE952D7182D5CBA00220163A18388EFE6310517385458AB4D3BBF7A0C23D9C87DA1CF378884FBBCDC86C5840757C633177D2A6E6420961D239518CBAFF96F2B1E739AB"
            "9145C2E9846E601B7FAC4208E68EF0C9F754753D6DD3A98D39C8ED95A8F01B3E241A2902AF7230A31A",
        },
        {
            &key,
            "x509-examples/signed-02.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A2046E416C696365204C6F76656C6163651820825901AD308201A930820150A0030201020214"
            "4E3019548429A2893D04B8EDBA143B8F7D17B276300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F53452043657274696669636174652041757468"
            "6F726974793020170D3230313230323137323732355A180F32303533313031303137323732355A3019311730150603550403130E416C696365204C6F76656C6163653059301306072A"
            "8648CE3D020106082A8648CE3D03010703420004863AA7BC0326716AA59DB5BF66CC660D0591D51E4891BC2E6A9BAFF5077D927CAD4EED482A7985BE019E9B1936C16E00190E8BCC48"
            "EE12D35FF89F0FC7A099CAA361305F300C0603551D130101FF04023000300F0603551D0F0101FF04050303078000301D0603551D0E041604141151555B01FF3F6DDDF9E5712AD3FF72"
            "A2D94D62301F0603551D230418301680141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022038FF9207872BA4D685700774783D35BE5B"
            "45AF59265A8567AE952D7182D5CBA00220163A18388EFE6310517385458AB4D3BBF7A0C23D9C87DA1CF378884FBBCDC86C5901A23082019E30820145A003020102021414A4957FD506"
            "AA2AAFC669A880032E8C95B87624300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F7269747930"
            "20170D3230313230323137323333325A180F32303533313031303137323333325A302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574"
            "686F726974793059301306072A8648CE3D020106082A8648CE3D030107034200047B447C98F731337AFBE3BAC96E793AF12865F3BD56B647A1729764191AE111F3161B4D56FA42F26E"
            "1B18DD87F9DB42F4C9168E420E2CE5E2D149648EE0EE5FB4A3433041300F0603551D130101FF040530030101FF300F0603551D0F0101FF04050303070600301D0603551D0E04160414"
            "1E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022006F99B3ACE00007BFB717784DDD230013D8CDCA0BABE20EE00039BEA0898A6D40220"
            "0FFAF9DE61C1B6BD28BF5DDB1A191E63B22EAD4A69468D5222C487D53C33C2045840D27029503ED8CF40C7B73BBCB88C062467C0A50F0897D1559855F4FCF1788874BA8E3843D23B59"
            "566BC825102D573817437D91D0D765FA2165EFA390B50A03FF",
        },
#if 0
        {
            &key,
            "x509-examples/signed-03.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A118215901AD308201A930820150A00302010202144E3019548429A2893D04B8EDBA143B8F7D"
            "17B276300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137"
            "323732355A180F32303533313031303137323732355A3019311730150603550403130E416C696365204C6F76656C6163653059301306072A8648CE3D020106082A8648CE3D03010703"
            "420004863AA7BC0326716AA59DB5BF66CC660D0591D51E4891BC2E6A9BAFF5077D927CAD4EED482A7985BE019E9B1936C16E00190E8BCC48EE12D35FF89F0FC7A099CAA361305F300C"
            "0603551D130101FF04023000300F0603551D0F0101FF04050303078000301D0603551D0E041604141151555B01FF3F6DDDF9E5712AD3FF72A2D94D62301F0603551D23041830168014"
            "1E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022038FF9207872BA4D685700774783D35BE5B45AF59265A8567AE952D7182D5CBA00220"
            "163A18388EFE6310517385458AB4D3BBF7A0C23D9C87DA1CF378884FBBCDC86C5840CC4EF1B70DD7F33B2489597B5556507FD5D896C477C1F7FFCCDE82EF3E50718260EE6345E2993B"
            "1757C7D521D02E923DA25F02DDE0F24B40009FB4FD6B31D2FD",
        },
        {
            &key,
            "x509-examples/signed-04.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A11821825901AD308201A930820150A00302010202144E3019548429A2893D04B8EDBA143B8F"
            "7D17B276300A06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D32303132303231"
            "37323732355A180F32303533313031303137323732355A3019311730150603550403130E416C696365204C6F76656C6163653059301306072A8648CE3D020106082A8648CE3D030107"
            "03420004863AA7BC0326716AA59DB5BF66CC660D0591D51E4891BC2E6A9BAFF5077D927CAD4EED482A7985BE019E9B1936C16E00190E8BCC48EE12D35FF89F0FC7A099CAA361305F30"
            "0C0603551D130101FF04023000300F0603551D0F0101FF04050303078000301D0603551D0E041604141151555B01FF3F6DDDF9E5712AD3FF72A2D94D62301F0603551D230418301680"
            "141E6FC4D0C0DA004A8427CBBD3FE05A99EA2D2D11300A06082A8648CE3D0403020347003044022038FF9207872BA4D685700774783D35BE5B45AF59265A8567AE952D7182D5CBA002"
            "20163A18388EFE6310517385458AB4D3BBF7A0C23D9C87DA1CF378884FBBCDC86C5901A23082019E30820145A003020102021414A4957FD506AA2AAFC669A880032E8C95B87624300A"
            "06082A8648CE3D040302302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793020170D3230313230323137323333325A"
            "180F32303533313031303137323333325A302C312A30280603550403132153616D706C6520434F534520436572746966696361746520417574686F726974793059301306072A8648CE"
            "3D020106082A8648CE3D030107034200047B447C98F731337AFBE3BAC96E793AF12865F3BD56B647A1729764191AE111F3161B4D56FA42F26E1B18DD87F9DB42F4C9168E420E2CE5E2"
            "D149648EE0EE5FB4A3433041300F0603551D130101FF040530030101FF300F0603551D0F0101FF04050303070600301D0603551D0E041604141E6FC4D0C0DA004A8427CBBD3FE05A99"
            "EA2D2D11300A06082A8648CE3D0403020347003044022006F99B3ACE00007BFB717784DDD230013D8CDCA0BABE20EE00039BEA0898A6D402200FFAF9DE61C1B6BD28BF5DDB1A191E63"
            "B22EAD4A69468D5222C487D53C33C2045840CFFD4CDA8DD573279CD6878F30DC44E1295D045BCB13D93D0C42A2F6F3B58C0757F39116ACD90B84EB0DA8818D2BBEB6B919905AF14BAF"
            "804599B772FD4A4ECD",
        },
        {
            &key,
            "x509-examples/signed-05.json",
            "D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A11822822F582011FA0500D6763AE15A3238296E04C048A8FDD220A0DDA0234824B18FB66666"
            "005840E2868433DB5EB82E91F8BE52E8A67903A93332634470DE3DD90D52422B62DFE062248248AC388FAF77B277F91C4FB6EE776EDC52069C67F17D9E7FA57AC9BBA9",
        },
#endif
    };

    OPTION& option = _cmdline->value();

    int i = 0;
    cbor_encode e;

    std::map<std::string, int> dictionary;
    std::map<std::string, int>::iterator iter;
    uint16 table[] = {
        cbor_tag_t::cose_tag_encrypt0,  // 16
        cbor_tag_t::cose_tag_mac0,      // 17
        cbor_tag_t::cose_tag_sign1,     // 18
        cbor_tag_t::cose_tag_encrypt,   // 96
        cbor_tag_t::cose_tag_mac,       // 97
        cbor_tag_t::cose_tag_sign,      // 98
    };
    for (i = 0; i < RTL_NUMBER_OF(table); i++) {
        binary_t bin;
        e.encode(bin, cbor_major_t::cbor_major_tag, table[i]);
        std::string keyword = uppername(base16_encode(bin));
        dictionary.insert(std::make_pair(keyword, table[i]));
        printf("%s => %i\n", keyword.c_str(), table[i]);
    }

    basic_stream bs;
    bool result = false;
    cbor_object_signing_encryption cose;
    for (i = 0; i < RTL_NUMBER_OF(vector); i++) {
        printf("\e[33m%s\e[0m\n", vector[i].file);
        binary_t cbor = base16_decode(vector[i].cbor);

        binary_t bin_cbor;
        basic_stream bs;
        basic_stream diagnostic;
        cbor_reader reader;
        cbor_reader_context_t* reader_handle = nullptr;
        reader.open(&reader_handle);
        reader.parse(reader_handle, cbor);
        reader.publish(reader_handle, &diagnostic);
        reader.publish(reader_handle, &bin_cbor);
        reader.close(reader_handle);
        dump_memory(bin_cbor, &bs);
        printf("cbor\n%s\n", bs.c_str());
        printf("diagnostic\n%s\n", diagnostic.c_str());

        basic_stream properties;
        basic_stream reason;
        return_t ret = errorcode_t::success;
        std::string tagkey(vector[i].cbor, 4);
        iter = dictionary.find(uppername(tagkey));
        if (dictionary.end() == iter) {
            std::string tagkey2(vector[i].cbor, 2);
            iter = dictionary.find(uppername(tagkey2));
        }
        if (iter == dictionary.end()) {
            ret = errorcode_t::not_found;
        } else {
            cose_context_t* handle = nullptr;
            cose.open(&handle);
#if defined DEBUG
            if (vector[i].enc.aad_hex) {
                dump_memory(base16_decode(vector[i].enc.aad_hex), &bs);
                printf("\e[35mAAD\n%s\n%s\n\e[0m", bs.c_str(), vector[i].enc.aad_hex);
            }
            if (vector[i].enc.cek_hex) {
                dump_memory(base16_decode(vector[i].enc.cek_hex), &bs);
                printf("\e[35mCEK\n%s\n%s\n\e[0m", bs.c_str(), vector[i].enc.cek_hex);
            }
#endif
            if (vector[i].shared.external) {
                cose.set(handle, cose_param_t::cose_external, base16_decode(vector[i].shared.external));
                printf("\e[35m>external %s\n\e[0m", vector[i].shared.external);
                properties << "external ";
            }
            if (vector[i].shared.iv_hex) {
                cose.set(handle, cose_param_t::cose_unsent_iv, base16_decode(vector[i].shared.iv_hex));
                printf("\e[35m>unsent iv %s\n\e[0m", vector[i].shared.iv_hex);
                properties << "iv ";
            }
            if (vector[i].shared.apu_id) {
                cose.set(handle, cose_param_t::cose_unsent_apu_id, base16_decode(vector[i].shared.apu_id));
                printf("\e[35m>unsent partyu id %s\n\e[0m", vector[i].shared.apu_id);
                properties << "apu_id ";
            }
            if (vector[i].shared.apu_nonce) {
                cose.set(handle, cose_param_t::cose_unsent_apu_nonce, base16_decode(vector[i].shared.apu_nonce));
                printf("\e[35m>unsent partyu nonce %s\n\e[0m", vector[i].shared.apu_nonce);
                properties << "apu_nonce ";
            }
            if (vector[i].shared.apu_other) {
                cose.set(handle, cose_param_t::cose_unsent_apu_other, base16_decode(vector[i].shared.apu_other));
                printf("\e[35m>unsent partyu other %s\n\e[0m", vector[i].shared.apu_other);
                properties << "external apu_other";
            }
            if (vector[i].shared.apv_id) {
                cose.set(handle, cose_param_t::cose_unsent_apv_id, base16_decode(vector[i].shared.apv_id));
                printf("\e[35m>unsent partyv id %s\n\e[0m", vector[i].shared.apv_id);
                properties << "apv_id ";
            }
            if (vector[i].shared.apv_nonce) {
                cose.set(handle, cose_param_t::cose_unsent_apv_nonce, base16_decode(vector[i].shared.apv_nonce));
                printf("\e[35m>unsent partyv nonce %s\n\e[0m", vector[i].shared.apv_nonce);
                properties << "apv_nonce ";
            }
            if (vector[i].shared.apv_other) {
                cose.set(handle, cose_param_t::cose_unsent_apv_other, base16_decode(vector[i].shared.apv_other));
                printf("\e[35m>unsent partyv other %s\n\e[0m", vector[i].shared.apv_other);
                properties << "apv_other ";
            }
            if (vector[i].shared.pub_other) {
                cose.set(handle, cose_param_t::cose_unsent_pub_other, base16_decode(vector[i].shared.pub_other));
                printf("\e[35m>unsent pub other %s\n\e[0m", vector[i].shared.pub_other);
                properties << "pub_other ";
            }
            if (vector[i].shared.priv) {
                cose.set(handle, cose_param_t::cose_unsent_priv_other, base16_decode(vector[i].shared.priv));
                printf("\e[35m>unsent private %s\n\e[0m", vector[i].shared.priv);
                properties << "priv ";
            }
            if (vector[i].debug) {
                int break_point_here = 1;
            }

            int tagvalue = iter->second;
            binary_t decrypted;
            switch (tagvalue) {
                case cbor_tag_t::cose_tag_encrypt0:  // 16 (D0)
                case cbor_tag_t::cose_tag_encrypt:   // 96 (D860)
                    ret = cose.decrypt(handle, vector[i].key, cbor, decrypted, result);
                    if (errorcode_t::success == ret) {
                        dump_memory(decrypted, &bs);
                        printf("decrypted\n%s\n", bs.c_str());
                    }
                    break;
                case cbor_tag_t::cose_tag_mac0:  // 17 (D1)
                case cbor_tag_t::cose_tag_mac:   // 97 (D861)
                    ret = errorcode_t::not_supported;
                    break;
                case cbor_tag_t::cose_tag_sign1:  // 18 (D2)
                case cbor_tag_t::cose_tag_sign:   // 98 (D862)
                    ret = cose.verify(handle, vector[i].key, cbor, result);
                    break;
                default:
                    ret = errorcode_t::bad_data;  // todo, studying, not-tagged
                    break;
            }

#if defined DEBUG
            if (handle->debug_flag & cose_debug_notfound_key) {
                reason << "!key ";
            }
            if (handle->debug_flag & cose_debug_partial_iv) {
                reason << "partial_iv ";
            }
            if (handle->debug_flag & cose_debug_hkdf_aescmac) {
                reason << "hkdf_aescmac ";
            }
            if (handle->debug_flag & cose_debug_chacha20_poly1305) {
                reason << "chacha20_poly1305 ";
            }
#endif
            cose.close(handle);
        }

        _test_case.test(ret, __FUNCTION__, "%s %s %s%s%s", vector[i].file, properties.c_str(), reason.size() ? "[ debug : " : "", reason.c_str(),
                        reason.size() ? "]" : "");
    }
}

int main(int argc, char** argv) {
    set_trace_option(trace_option_t::trace_bt | trace_option_t::trace_except);

    _cmdline.make_share(new cmdline_t<OPTION>);
    *_cmdline << cmdarg_t<OPTION>("-dump", "dump keys", [&](OPTION& o, char* param) -> void { o.dump_keys = true; }).optional();
    *_cmdline << cmdarg_t<OPTION>("-v", "validate", [&](OPTION& o, char* param) -> void { o.validate_testvector = true; }).optional();
    (*_cmdline).parse(argc, argv);

    OPTION& option = _cmdline->value();
    std::cout << "option.dump_keys " << (option.dump_keys ? 1 : 0) << std::endl;
    std::cout << "option.validate_testvector " << (option.validate_testvector ? 1 : 0) << std::endl;

    openssl_startup();
    openssl_thread_setup();

    // check format
    // install
    //      pacman -S rubygems (MINGW)
    //      yum install rubygems (RHEL)
    //      gem install cbor-diag
    // diag2cbor.rb < inputfile > outputfile
    // compare
    //      cat outputfile | xxd
    //      xxd -ps outputfile

    // part 0 .. try to decode
    { test_rfc8152_read_cbor(); }

    // part 1 .. following cases
    // encode and decode
    // Test Vector comparison
    {
        cbor_web_key cwk;
        cwk.load_file(&rfc8152_privkeys, "rfc8152_c_7_2.cbor");
        cwk.load_file(&rfc8152_pubkeys, "rfc8152_c_7_1.cbor");

        // RFC8152/Appendix_C_4_1.json
        cwk.add_oct_b64u(&rfc8152_privkeys_c4, "our-secret2", nullptr, "hJtXhkV8FJG-Onbc6mxCcY", crypto_use_t::use_enc);

        // rfc8152_privkeys.for_each (dump_crypto_key, nullptr);
        // rfc8152_pubkeys.for_each (dump_crypto_key, nullptr);

        // cbor_tag_t::cose_tag_sign
        test_rfc8152_c_1_1();
        test_rfc8152_c_1_2();
        test_rfc8152_c_1_3();
        test_rfc8152_c_1_4();
        // cbor_tag_t::cose_tag_sign1
        test_rfc8152_c_2_1();
        // cbor_tag_t::cose_tag_encrypt
        test_rfc8152_c_3_1();
        test_rfc8152_c_3_2();
        test_rfc8152_c_3_3();
        test_rfc8152_c_3_4();
        // cbor_tag_t::cose_tag_encrypt0
        test_rfc8152_c_4_1();
        test_rfc8152_c_4_2();
        // cbor_tag_t::cose_tag_mac
        test_rfc8152_c_5_1();
        test_rfc8152_c_5_2();
        test_rfc8152_c_5_3();
        test_rfc8152_c_5_4();
        // cbor_tag_t::cose_tag_mac0
        test_rfc8152_c_6_1();
        // key
        test_rfc8152_c_7_1();
        test_rfc8152_c_7_2();
    }

    // part 2 .. test JWK, CWK compatibility
    {
        // test crypto_key, crypto_keychain
        test_jose_from_cwk();
    }

    // part 3 https://github.com/cose-wg/Examples
    // A GitHub project has been created at <https://github.com/cose-wg/
    // Examples> that contains not only the examples presented in this
    // document, but a more complete set of testing examples as well.  Each
    // example is found in a JSON file that contains the inputs used to
    // create the example, some of the intermediate values that can be used
    // in debugging the example and the output of the example presented in
    // both a hex and a CBOR diagnostic notation format.  Some of the
    // examples at the site are designed failure testing cases; these are
    // clearly marked as such in the JSON file.  If errors in the examples
    // in this document are found, the examples on GitHub will be updated,
    // and a note to that effect will be placed in the JSON file.
    {
        // implementation status
        test_github_example();
    }

    openssl_thread_cleanup();
    openssl_cleanup();

    _test_case.report(5);
    return _test_case.result();
}
