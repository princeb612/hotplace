/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    bool verbose;
    bool dump_keys;
    bool skip_cbor_basic;
    bool skip_validate;
    bool skip_gen;

    _OPTION() : verbose(false), dump_keys(false), skip_cbor_basic(false), skip_validate(false), skip_gen(false) {
        // do nothing
    }
} OPTION;
t_shared_instance<cmdline_t<OPTION> > _cmdline;

crypto_key rfc8152_privkeys;
crypto_key rfc8152_pubkeys;
crypto_key rfc8152_privkeys_c4;

return_t dump_test_data(const char* text, basic_stream& diagnostic) {
    return_t ret = errorcode_t::success;
    _logger->writeln("%s %s", text ? text : "diagnostic", diagnostic.c_str());
    return ret;
}

return_t dump_test_data(const char* text, const binary_t& cbor) {
    return_t ret = errorcode_t::success;
    basic_stream bs;
    _logger->hdump(text ? text : "diagnostic", cbor, 32, 4);
    return ret;
}

void dump_crypto_key(crypto_key_object* key, void*) {
    OPTION option = _cmdline->value();  // (*_cmdline).value () is ok
    if (option.dump_keys) {
        uint32 nid = 0;

        nidof_evp_pkey(key->get_pkey(), nid);
        _logger->writeln("nid %i kid %s alg %s use %08x", nid, key->get_kid(), key->get_alg(), key->get_use());

        basic_stream bs;
        dump_key(key->get_pkey(), &bs);
        _logger->writeln("%s", bs.c_str());
    }
}

return_t test_cose_example(cose_context_t* cose_handle, crypto_key* cose_keys, cbor_object* root, const char* expect_file, const char* text) {
    return_t ret = errorcode_t::success;
    return_t test = errorcode_t::success;
    OPTION& option = _cmdline->value();

    __try2 {
        if (nullptr == cose_handle || nullptr == cose_keys || nullptr == root || nullptr == expect_file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_publisher publisher;
        // cbor_object* to cbor
        binary_t bin;
        publisher.publish(root, &bin);

        if (option.verbose) {
            // cbor_object* to diagnostic
            basic_stream diagnostic;
            // publisher.publish(root, &diagnostic);

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

                cbor_reader reader;
                cbor_reader_context_t* handle = nullptr;
                cbor_object* newone = nullptr;

                reader.open(&handle);
                reader.parse(handle, expect);
                reader.publish(handle, &diagnostic);
                reader.close(handle);

                dump_test_data("test vector #1", expect);
                dump_test_data("diagnostic #1", diagnostic);
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

                {
                    test_case_notimecheck notimecheck(_test_case);
                    cose_composer composer;
                    binary_t bin_untagged;
                    basic_stream bs_diagnostic_composed;
                    cbor_array* cbor_newone = nullptr;

                    cbor_tag_t tag = newone->tag_value();  // backup
                    if (cbor_tag_t::cbor_tag_unknown != tag) {
                        newone->tag(cbor_tag_t::cbor_tag_unknown);

                        publisher.publish(newone, &bin_untagged);
                        composer.parse(bin_untagged);
                        composer.compose(&cbor_newone);

                        publisher.publish(cbor_newone, &bs_diagnostic_composed);
                        dump_test_data("\e[1;36mcompose\e[0m", bs_diagnostic_composed);

                        _test_case.assert(true, __FUNCTION__, "check.compose %s", text ? text : "");

                        cbor_newone->release();
                    }
                }
                newone->release();  // release parsed object
            }
        }

        cbor_object_signing_encryption cose;
        binary_t signature;
        binary_t decrypted;
        bool result = false;

        if (option.verbose) {
            cose.set(cose_handle, cose_flag_t::cose_flag_allow_debug);
        }

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
                        if (option.verbose) {
                            _logger->dump(decrypted, 16, 4);
                        }
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
    OPTION& option = _cmdline->value();

    console_color concolor;

    basic_stream bs;
    bs << concolor.turnon().set_style(console_style_t::bold).set_fgcolor(console_color_t::cyan) << expect_file << concolor.turnoff();
    _logger->writeln(bs);

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

        if (option.verbose) {
            dump_test_data("diagnostic", bs_diagnostic);
            dump_test_data("cbor", bin_cbor);
        }

        root->release();

        _test_case.assert((bin_cbor == expect), __FUNCTION__, text ? text : "");
    }
    __finally2 {
        // do nothing
    }
}

void test_rfc8152_b() {
    _test_case.begin("RFC 8152 B");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes128gcm);
    composer.get_unprotected().add(cose_key_t::cose_iv, base16_decode("02d1f7e6f26c43d4868d87ce"));
    composer.get_payload().set(base16_decode("64f84d913ba60a76070a9a48f26e97e863e2852948658f0811139868826e89218a75715b"));

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_unprotected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes128kw);
    recipient.get_payload().set(base16_decode("dbd43c4e9d719c27c6275c67d628d493f090593db8218f11"));

    cose_recipient& layered_recipient = recipient.add(new cose_recipient);
    layered_recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhes_hkdf_256);
    layered_recipient.get_unprotected()
        .add(cose_key_t::cose_ephemeral_key, cose_ec_curve_t::cose_ec_p256, base16_decode("b2add44368ea6d641f9ca9af308b4079aeb519f11e9b8a55a600b21233e86e68"),
             false)
        .add(cose_key_t::cose_kid, "meriadoc.brandybuck@buckland.example");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_b.cbor", "RFC 8152 B.  Two Layers of Recipient Information");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_1_1() {
    _test_case.begin("RFC 8152 C.1");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_payload().set("This is the content.");

    cose_recipient& signature = composer.get_recipients().add(new cose_recipient);
    signature.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
    signature.get_unprotected().add(cose_key_t::cose_kid, "11");
    signature.get_payload().set_b16(
        "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a");
    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_1.cbor", "RFC 8152 C.1.1.  Single Signature");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_1_2() {
    _test_case.begin("RFC 8152 C.1");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_payload().set("This is the content.");

    cose_recipient& signature = composer.get_recipients().add(new cose_recipient);
    signature.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
    signature.get_unprotected().add(cose_key_t::cose_kid, "11");
    signature.get_payload().set_b16(
        "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a");

    cose_recipient& signature2 = composer.get_recipients().add(new cose_recipient);
    signature2.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es512);
    signature2.get_unprotected().add(cose_key_t::cose_kid, "bilbo.baggins@hobbiton.example");
    signature2.get_payload().set_b16(
        "00a2d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e8705524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf4"
        "82270cc5771aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f83ab87bb4f7a0297");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_2.cbor", "RFC 8152 C.1.2.  Multiple Signers");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_1_3() {
    _test_case.begin("RFC 8152 C.1");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_unprotected().add(
        cose_alg_t::cose_es256, "11",
        base16_decode("5ac05e289d5d0e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887e8802bb6650cceb2c"));
    composer.get_payload().set("This is the content.");

    cose_recipient& signature = composer.get_recipients().add(new cose_recipient);
    signature.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
    signature.get_unprotected().add(cose_key_t::cose_kid, "11");
    signature.get_payload().set_b16(
        "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_3.cbor", "RFC 8152 C.1.3.  Counter Signature");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_1_4() {
    _test_case.begin("RFC 8152 C.1");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().set(base16_decode("a2687265736572766564f40281687265736572766564"));
    composer.get_payload().set("This is the content.");

    cose_recipient& signature = composer.get_recipients().add(new cose_recipient);
    signature.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
    signature.get_unprotected().add(cose_key_t::cose_kid, "11");
    signature.get_payload().set_b16(
        "3fc54702aa56e1b2cb20284294c9106a63f91bac658d69351210a031d8fc7c5ff3e4be39445b1a3e83e1510d1aca2f2e8a7c081c7645042b18aba9d1fad1bd9c");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_1_4.cbor", "RFC 8152 C.1.4.  Signature with Criticality");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_2_1() {
    _test_case.begin("RFC 8152 C.2");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_es256);
    composer.get_unprotected().add(cose_key_t::cose_kid, "11");
    composer.get_payload().set("This is the content.");
    composer.get_singleitem().set_b16(
        "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_pubkeys, root, "rfc8152_c_2_1.cbor", "RFC 8152 C.2.1.  Single ECDSA Signature");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_1() {
    _test_case.begin("RFC 8152 C.3");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes128gcm);
    composer.get_unprotected().add(cose_key_t::cose_iv, base16_decode("c9cf4df2fe6c632bf7886413"));
    composer.get_payload().set_b16("7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhes_hkdf_256);
    recipient.get_unprotected()
        .add(cose_key_t::cose_ephemeral_key, cose_ec_curve_t::cose_ec_p256, base16_decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280"),
             true)
        .add(cose_key_t::cose_kid, "meriadoc.brandybuck@buckland.example");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_3_1.cbor", "RFC 8152 C.3.1.  Direct ECDH");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_2() {
    _test_case.begin("RFC 8152 C.3");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesccm_16_64_128);
    composer.get_unprotected().add(cose_key_t::cose_iv, base16_decode("89f52f65a1c580933b5261a76c"));
    composer.get_payload().set_b16("753548a19b1307084ca7b2056924ed95f2e3b17006dfe931b687b847");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_hkdf_sha256);
    recipient.get_unprotected().add(cose_key_t::cose_salt, "aabbccddeeffgghh").add(cose_key_t::cose_kid, "our-secret");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);

    cose.set(cose_handle, cose_param_t::cose_unsent_apu_id, convert("lighting-client"));
    cose.set(cose_handle, cose_param_t::cose_unsent_apv_id, convert("lighting-server"));
    cose.set(cose_handle, cose_param_t::cose_unsent_pub_other, convert("Encryption Example 02"));

    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_3_2.cbor", "RFC 8152 C.3.2.  Direct Plus Key Derivation");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_3() {
    _test_case.begin("RFC 8152 C.3");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes128gcm);
    composer.get_unprotected()
        .add(cose_key_t::cose_iv, base16_decode("c9cf4df2fe6c632bf7886413"))
        .add(cose_alg_t::cose_es512, "bilbo.baggins@hobbiton.example",
             base16_decode("00929663c8789bb28177ae28467e66377da12302d7f9594d2999afa5dfa531294f8896f2b6cdf1740014f4c7f1a358e3a6cf57f4ed6fb02fcf8f7aa989f5dfd07f0"
                           "700a3a7d8f3c604"
                           "ba70fa9411bd10c2591b483e1d2c31de003183e434d8fba18f17a4c7e3dfa003ac1cf3d30d44d2533c4989d3ac38c38b71481cc3430c9d65e7ddff"));
    composer.get_payload().set_b16("7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhes_hkdf_256);
    recipient.get_unprotected()
        .add(cose_key_t::cose_ephemeral_key, cose_ec_curve_t::cose_ec_p256, base16_decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280"),
             true)
        .add(cose_key_t::cose_kid, "meriadoc.brandybuck@buckland.example");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_3_3.cbor", "RFC 8152 C.3.3.  Counter Signature on Encrypted Content");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_3_4() {
    _test_case.begin("RFC 8152 C.3");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes128gcm);
    composer.get_unprotected().add(cose_key_t::cose_iv, base16_decode("02d1f7e6f26c43d4868d87ce"));
    composer.get_payload().set_b16("64f84d913ba60a76070a9a48f26e97e863e28529d8f5335e5f0165eee976b4a5f6c6f09d");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhss_a128kw);
    recipient.get_unprotected()
        .add(cose_key_t::cose_static_key_id, "peregrin.took@tuckborough.example")
        .add(cose_key_t::cose_kid, "meriadoc.brandybuck@buckland.example")
        .add(cose_key_t::cose_partyu_nonce, base16_decode("0101"));
    recipient.get_payload().set_b16("41e0d76f579dbd0d936a662d54d8582037de2e366fde1c62");

    composer.compose(&root);

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

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesccm_16_64_128);
    composer.get_unprotected().add(cose_key_t::cose_iv, base16_decode("89f52f65a1c580933b5261a78c"));
    composer.get_payload().set_b16("5974e1b99a3a4cc09a659aa2e9e7fff161d38ce71cb45ce460ffb569");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys_c4, root, "rfc8152_c_4_1.cbor", "RFC 8152 C.4.1.  Simple Encrypted Message");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_4_2() {
    _test_case.begin("RFC 8152 C.4");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesccm_16_64_128);
    composer.get_unprotected().add(cose_key_t::cose_partial_iv, base16_decode("61a7"));
    composer.get_payload().set_b16("252a8911d465c125b6764739700f0141ed09192de139e053bd09abca");

    composer.compose(&root);

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

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesmac_256_64);
    composer.get_payload().set("This is the content.");
    composer.get_tag().set_b16("9e1226ba1f81b848");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_unprotected().add(cose_key_t::cose_alg, cose_alg_t::cose_direct).add(cose_key_t::cose_kid, "our-secret");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_1.cbor", "RFC 8152 C.5.1.  Shared Secret Direct MAC");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_5_2() {
    _test_case.begin("RFC 8152 C.5");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_hs256);
    composer.get_payload().set("This is the content.");
    composer.get_tag().set_b16("81a03448acd3d305376eaa11fb3fe416a955be2cbe7ec96f012c994bc3f16a41");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhss_hkdf_256);
    recipient.get_unprotected()
        .add(cose_key_t::cose_static_key_id, "peregrin.took@tuckborough.example")
        .add(cose_key_t::cose_kid, "meriadoc.brandybuck@buckland.example")
        .add(cose_key_t::cose_partyu_nonce,
             base16_decode("4d8553e7e74f3c6a3a9dd3ef286a8195cbf8a23d19558ccfec7d34b824f42d92bd06bd2c7f0271f0214e141fb779ae2856abf585a58368b017e7f2a9e5ce4db5"));

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_2.cbor", "RFC 8152 C.5.2.  ECDH Direct MAC");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_5_3() {
    _test_case.begin("RFC 8152 C.5");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesmac_128_64);
    composer.get_payload().set("This is the content.");
    composer.get_tag().set_b16("36f5afaf0bab5d43");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_unprotected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes256kw).add(cose_key_t::cose_kid, "018c0ae5-4d9b-471b-bfd6-eef314bc7037");
    recipient.get_payload().set_b16("711ab0dc2fc4585dce27effa6781c8093eba906f227b6eb0");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_3.cbor", "RFC 8152 C.5.3.  Wrapped MAC");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_5_4() {
    _test_case.begin("RFC 8152 C.5");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_hs256);
    composer.get_payload().set("This is the content.");
    composer.get_tag().set_b16("bf48235e809b5c42e995f2b7d5fa13620e7ed834e337f6aa43df161e49e9323e");

    cose_recipient& recipient = composer.get_recipients().add(new cose_recipient);
    recipient.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_ecdhes_a128kw);
    recipient.get_unprotected()
        .add(cose_key_t::cose_ephemeral_key, cose_ec_curve_t::cose_ec_p521,
             base16_decode(
                 "0043b12669acac3fd27898ffba0bcd2e6c366d53bc4db71f909a759304acfb5e18cdc7ba0b13ff8c7636271a6924b1ac63c02688075b55ef2d613574e7dc242f79c3"),
             true)
        .add(cose_key_t::cose_kid, "bilbo.baggins@hobbiton.example");
    recipient.get_payload().set_b16("339bc4f79984cdc6b3e6ce5f315a4c7d2b0ac466fcea69e8c07dfbca5bb1f661bc5f8e0df9e3eff5");

    cose_recipient& recipient2 = composer.get_recipients().add(new cose_recipient);
    recipient2.get_unprotected().add(cose_key_t::cose_alg, cose_alg_t::cose_aes256kw).add(cose_key_t::cose_kid, "018c0ae5-4d9b-471b-bfd6-eef314bc7037");
    recipient2.get_payload().set_b16("0b2c7cfce04e98276342d6476a7723c090dfdd15f9a518e7736549e998370695e6d6a83b4ae507bb");

    composer.compose(&root);

    cbor_object_signing_encryption cose;
    cose_context_t* cose_handle = nullptr;
    cose.open(&cose_handle);
    test_cose_example(cose_handle, &rfc8152_privkeys, root, "rfc8152_c_5_4.cbor", "RFC 8152 C.5.4.  Multi-Recipient MACed Message");
    cose.close(cose_handle);

    root->release();
}

void test_rfc8152_c_6_1() {
    _test_case.begin("RFC 8152 C.6");

    // interface sketch...
    cbor_array* root = nullptr;
    cose_composer composer;
    composer.get_protected().add(cose_key_t::cose_alg, cose_alg_t::cose_aesmac_256_64);
    composer.get_payload().set("This is the content.");
    composer.get_tag().set_b16("726043745027214f");

    composer.compose(&root);

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
    OPTION& option = _cmdline->value();
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

        if (option.verbose) {
            test_case_notimecheck notimecheck(_test_case);

            _logger->hdump("from file", cbor, 32);
            _logger->hdump("from cwk", cbor_written, 32);

            basic_stream diagnostic;
            cbor_reader reader;
            cbor_reader_context_t* handle = nullptr;

            reader.open(&handle);
            reader.parse(handle, cbor);
            reader.publish(handle, &diagnostic);

            _logger->writeln("from file\n%s", diagnostic.c_str());

            reader.parse(handle, cbor_written);
            reader.publish(handle, &diagnostic);

            _logger->writeln("from cwk\n%s", diagnostic.c_str());

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
    OPTION& option = _cmdline->value();

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
    if (option.verbose) {
        _logger->writeln("JWK from CBOR key\n%s", json.c_str());
    }
    basic_stream pem;
    jwk.write_pem(&pubkey, &pem);
    if (option.verbose) {
        _logger->writeln("PEM (public)\n%s", pem.c_str());
    }
    jwk.write_pem(&privkey, &pem);
    if (option.verbose) {
        _logger->writeln("PEM (private)\n%s", pem.c_str());
    }

    const EVP_PKEY* pkey = nullptr;
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
    if (option.verbose) {
        test_case_notimecheck notimecheck(_test_case);

        dump_memory(signature, &bs);
        _logger->writeln("signature\n%s", bs.c_str());
        _logger->writeln("cbor\n%s", base16_encode(signature).c_str());

        basic_stream diagnostic;
        cbor_reader reader;
        cbor_reader_context_t* reader_handle = nullptr;
        reader.open(&reader_handle);
        reader.parse(reader_handle, signature);
        reader.publish(reader_handle, &diagnostic);
        reader.close(reader_handle);
        _logger->writeln("diagnostic\n%s", diagnostic.c_str());
    }
    ret = cose.verify(handle, &pubkey, signature, result);
    _test_case.test(ret, __FUNCTION__, "verify");
    cose.close(handle);
}

void test_github_example() {
    _test_case.begin("https://github.com/cose-wg/Examples");

    OPTION& option = _cmdline->value();

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

    crypto_key hmac_aes_256_key;
    cwk.add_oct_b64u(&hmac_aes_256_key, "our-secret", nullptr, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA", crypto_use_t::use_enc);

    crypto_key aes_gcm_02_key;
    cwk.add_oct_b64u(&aes_gcm_02_key, "sec-48", nullptr, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmI", crypto_use_t::use_enc);
    crypto_key aes_gcm_03_key;
    cwk.add_oct_b64u(&aes_gcm_03_key, "sec-64", nullptr, "Dx4tPEtaaXiHlqW0w9Lh8B8uPUxbanmIl6a1xNPi8QA", crypto_use_t::use_enc);
    crypto_key hmac_aes_128_key;
    cwk.add_oct_b64u(&hmac_aes_128_key, "our-secret", nullptr, "hJtXIZ2uSN5kbQfbtTNWbg", crypto_use_t::use_enc);

    crypto_key key_hmac_enc_02;
    cwk.add_oct_b64u(&key_hmac_enc_02, "sec-48", nullptr, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJico", crypto_use_t::use_enc);

    crypto_key cwtkey;
    cwk.add_ec_b16(&cwtkey, nullptr, "ES256", "P-256", "143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f",
                   "60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9", "6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19");
    cwk.add_oct_b16(&cwtkey, "our-secret", nullptr, "231f4c4d4d3051fdc2ec0a3851d5b383");

    crypto_key key_cwt_a4;
    cwk.add_oct_b16(&key_cwt_a4, "our-secret", nullptr, "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388");

    crypto_key key_hmac_enc_03;
    cwk.add_oct_b64u(&key_hmac_enc_03, "sec-64", nullptr, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJicoqrvM3e7_paanqKmgsbKztA");

    std::map<std::string, crypto_key*> keymapper;

    keymapper["rfc8152_privkeys"] = &rfc8152_privkeys;
    keymapper["rfc8152_pubkeys"] = &rfc8152_pubkeys;
    keymapper["rfc8152_privkeys_c4"] = &rfc8152_privkeys_c4;
    keymapper["key"] = &key;
    keymapper["ecdh_wrap_p256_key"] = &ecdh_wrap_p256_key;
    keymapper["ecdh_wrap_p521_key"] = &ecdh_wrap_p521_key;
    keymapper["aes_ccm_key"] = &aes_ccm_key;
    keymapper["hmac_aes_256_key"] = &hmac_aes_256_key;
    keymapper["aes_gcm_02_key"] = &aes_gcm_02_key;
    keymapper["aes_gcm_03_key"] = &aes_gcm_03_key;
    keymapper["hmac_aes_128_key"] = &hmac_aes_128_key;
    keymapper["key_hmac_enc_02"] = &key_hmac_enc_02;
    keymapper["cwtkey"] = &cwtkey;
    keymapper["key_cwt_a4"] = &key_cwt_a4;
    keymapper["key_hmac_enc_03"] = &key_hmac_enc_03;

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
        _logger->writeln("%s => %i", keyword.c_str(), table[i]);
    }

    _test_case.reset_time();

    basic_stream bs;
    bool result = false;
    cbor_object_signing_encryption cose;
    for (i = 0; i < sizeof_test_vector_github_cose_wg; i++) {
        const test_vector_github_cose_wg_t* vector = test_vector_github_cose_wg + i;
        if (vector->skip) {
            continue;
        }
        if (vector->debug) {
            int break_point_here = 1;
        }

        _logger->writeln("\e[33m%s\e[0m", vector->file);
        binary_t cbor = base16_decode(vector->cbor);
        crypto_key* mapped_key = keymapper[vector->keysetname];

        mapped_key->for_each(dump_crypto_key, nullptr);

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
        if (option.verbose) {
            dump_memory(bin_cbor, &bs, 16, 2);
            _logger->writeln("cbor\n%s", bs.c_str());
            _logger->writeln("diagnostic\n  %s", diagnostic.c_str());

            cbor_publisher publisher;
            cose_composer composer;
            basic_stream bs_diagnostic_composed;
            binary_t bin_composed;
            cbor_array* cbor_newone = nullptr;

            composer.parse(cbor);
            composer.compose(&cbor_newone, bin_composed, vector->untagged ? false : true);

            publisher.publish(cbor_newone, &bs_diagnostic_composed);
            dump_test_data("\e[1;36mcompose\e[0m", bs_diagnostic_composed);
            _test_case.assert(bin_composed == bin_cbor, __FUNCTION__, "compose.parse %s", vector->file);
        }

        basic_stream properties;
        basic_stream reason;
        basic_stream debug_stream;
        return_t ret = errorcode_t::success;

        cose_context_t* handle = nullptr;
        cose.open(&handle);

#define dumps(b, f)                                                  \
    if (f) {                                                         \
        dump_memory(base16_decode(f), &bs, 16, 2);                   \
        _logger->writeln("\e[35m>%s %s\n%s\e[0m", b, f, bs.c_str()); \
    }

        if (option.verbose) {
            cose.set(handle, cose_flag_t::cose_flag_allow_debug);

            dumps("AAD", vector->enc.aad_hex);
            dumps("CEK", vector->enc.cek_hex);
            dumps("external", vector->shared.external);
            dumps("unsent iv", vector->shared.iv_hex);
            dumps("unsent partyu id", vector->shared.apu_id);
            dumps("unsent partyu nonce", vector->shared.apu_nonce);
            dumps("unsent partyu other", vector->shared.apu_other);
            dumps("unsent partyv id", vector->shared.apv_id);
            dumps("unsent partyv nonce", vector->shared.apv_nonce);
            dumps("unsent partyv other", vector->shared.apv_other);
            dumps("unsent pub other", vector->shared.pub_other);
            dumps("unsent private", vector->shared.priv);
        }

        if (vector->shared.external) {
            cose.set(handle, cose_param_t::cose_external, base16_decode(vector->shared.external));
            properties << "external ";
        }
        if (vector->shared.iv_hex) {
            cose.set(handle, cose_param_t::cose_unsent_iv, base16_decode(vector->shared.iv_hex));
            properties << "iv ";
        }
        if (vector->shared.apu_id) {
            cose.set(handle, cose_param_t::cose_unsent_apu_id, base16_decode(vector->shared.apu_id));
            properties << "apu_id ";
        }
        if (vector->shared.apu_nonce) {
            cose.set(handle, cose_param_t::cose_unsent_apu_nonce, base16_decode(vector->shared.apu_nonce));
            properties << "apu_nonce ";
        }
        if (vector->shared.apu_other) {
            cose.set(handle, cose_param_t::cose_unsent_apu_other, base16_decode(vector->shared.apu_other));
            properties << "external apu_other";
        }
        if (vector->shared.apv_id) {
            cose.set(handle, cose_param_t::cose_unsent_apv_id, base16_decode(vector->shared.apv_id));
            properties << "apv_id ";
        }
        if (vector->shared.apv_nonce) {
            cose.set(handle, cose_param_t::cose_unsent_apv_nonce, base16_decode(vector->shared.apv_nonce));
            properties << "apv_nonce ";
        }
        if (vector->shared.apv_other) {
            cose.set(handle, cose_param_t::cose_unsent_apv_other, base16_decode(vector->shared.apv_other));
            properties << "apv_other ";
        }
        if (vector->shared.pub_other) {
            cose.set(handle, cose_param_t::cose_unsent_pub_other, base16_decode(vector->shared.pub_other));
            properties << "pub_other ";
        }
        if (vector->shared.priv) {
            cose.set(handle, cose_param_t::cose_unsent_priv_other, base16_decode(vector->shared.priv));
            properties << "priv ";
        }

        binary_t output;
        ret = cose.process(handle, mapped_key, cbor, output);

        if (option.verbose) {
            uint32 flags = 0;
            uint32 debug_flags = 0;
            cose.get(handle, flags, debug_flags);
            if (debug_flags & cose_debug_notfound_key) {
                reason << "!key ";
            }
            if (debug_flags & cose_debug_partial_iv) {
                reason << "partial_iv ";
            }
            if (debug_flags & cose_debug_counter_sig) {
                reason << "counter_sig ";
            }
            debug_stream = handle->debug_stream;
            if (output.size()) {
                dump_memory(output, &bs, 16, 4);
                _logger->writeln("decrypted\n%s\n%s", bs.c_str(), base16_encode(output).c_str());
            }
        }

        cose.close(handle);

        _test_case.test(ret, __FUNCTION__, "%s %s %s%s%s%s", vector->file, properties.c_str(), reason.size() ? "\e[1;33m[ debug : " : "", reason.c_str(),
                        reason.size() ? "]\e[0m " : " ", debug_stream.c_str());
    }
}

void test_eckey_compressed() {
    _test_case.begin("EC compressed");
    basic_stream bs;
    crypto_keychain keychain;
    crypto_key key;
    binary_t bin_x;
    binary_t bin_y;
    binary_t bin_d;

    keychain.add_ec_b16(&key, "test", nullptr, 415, "98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280", true, nullptr);
    key.for_each(dump_crypto_key, nullptr);

    const EVP_PKEY* pkey = key.any();
    key.get_key(pkey, bin_x, bin_y, bin_d, true);
    // Appendix_C_3_1
    // x mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA
    // y 8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs
    std::string y_compressed("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs");
    bool test = (bin_y == base64_decode(y_compressed, base64_encoding_t::base64url_encoding));
    _test_case.assert(test, __FUNCTION__, "EC compressed");
}

void test_sign(crypto_key* key, std::list<cose_alg_t>& algs, const binary_t& input, const char* text) {
    _test_case.begin("sign");

    return_t ret = errorcode_t::success;
    OPTION& option = _cmdline->value();
    cose_context_t* handle = nullptr;
    cbor_object_signing_encryption cose;
    binary_t cbor;
    binary_t dummy;
    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.sign(handle, key, algs, input, cbor);
    if (option.verbose) {
        _logger->writeln("%s", base16_encode(cbor).c_str());
    }
    cose.close(handle);
    _test_case.test(ret, __FUNCTION__, "sign %s", text);

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.process(handle, key, cbor, dummy);
    cose.close(handle);
    _test_case.test(ret, __FUNCTION__, "verifysign %s", text);
}

void test_encrypt(crypto_key* key, std::list<cose_alg_t>& algs, const binary_t& input, const char* text) {
    _test_case.begin("encrypt");

    return_t ret = errorcode_t::success;
    OPTION& option = _cmdline->value();
    cose_context_t* handle = nullptr;
    cbor_object_signing_encryption cose;
    binary_t cbor;
    binary_t dummy;
    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.encrypt(handle, key, algs, input, cbor);
    if (option.verbose) {
        _logger->writeln("%s", base16_encode(cbor).c_str());
    }
    cose.close(handle);
    _test_case.test(ret, __FUNCTION__, "encrypt %s", text);

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.process(handle, key, cbor, dummy);
    cose.close(handle);
    _test_case.test(ret, __FUNCTION__, "decrypt %s", text);
}

void test_mac(crypto_key* key, std::list<cose_alg_t>& algs, const binary_t& input, const char* text) {
    _test_case.begin("mac");

    return_t ret = errorcode_t::success;
    OPTION& option = _cmdline->value();
    cose_context_t* handle = nullptr;
    cbor_object_signing_encryption cose;
    binary_t cbor;
    binary_t dummy;
    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.mac(handle, key, algs, input, cbor);
    if (option.verbose) {
        _logger->writeln("%s", base16_encode(cbor).c_str());
    }
    cose.close(handle);
    _test_case.test(ret, __FUNCTION__, "mac %s", text);

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.process(handle, key, cbor, dummy);
    cose.close(handle);
    _test_case.test(ret, __FUNCTION__, "verifymac %s", text);
}

void test_keygen(crypto_key* key) {
    key->generate_nid(crypto_kty_t::kty_oct, 32, "kid_symm", crypto_use_t::use_any);
    key->generate_nid(crypto_kty_t::kty_rsa, 2048, "kid_rsa", crypto_use_t::use_any);
    key->generate_nid(crypto_kty_t::kty_ec, ec_curve_t::ec_p256, "kid_ec256", crypto_use_t::use_any);
    key->generate_nid(crypto_kty_t::kty_ec, ec_curve_t::ec_p256k, "kid_ec256k", crypto_use_t::use_any);
    key->generate_nid(crypto_kty_t::kty_ec, ec_curve_t::ec_p384, "kid_ec384", crypto_use_t::use_any);
    key->generate_nid(crypto_kty_t::kty_ec, ec_curve_t::ec_p521, "kid_ec521", crypto_use_t::use_any);
    key->generate_nid(crypto_kty_t::kty_okp, ec_curve_t::ec_x25519, "kid_x25519", crypto_use_t::use_enc);
    key->generate_nid(crypto_kty_t::kty_okp, ec_curve_t::ec_ed25519, "kid_ed25519", crypto_use_t::use_sig);
    key->for_each(dump_crypto_key, nullptr);
    _test_case.assert(true, __FUNCTION__, "key generation");
}

const cose_alg_t enc_algs[] = {
    cose_aes128gcm,        cose_aes192gcm,         cose_aes256gcm,         cose_aesccm_16_64_128,  cose_aesccm_16_64_256,  cose_aesccm_64_64_128,
    cose_aesccm_64_64_256, cose_aesccm_16_128_128, cose_aesccm_16_128_256, cose_aesccm_64_128_128, cose_aesccm_64_128_256,
};
const cose_alg_t sign_algs[] = {
    cose_es256, cose_es384, cose_es512, cose_eddsa, cose_ps256, cose_ps384, cose_ps512, cose_es256k, cose_rs256, cose_rs384, cose_rs512, cose_rs1,
};
const cose_alg_t mac_algs[] = {
    cose_hs256_64, cose_hs256, cose_hs384, cose_hs512, cose_aesmac_128_64, cose_aesmac_256_64, cose_aesmac_128_128, cose_aesmac_256_128,
};
const cose_alg_t key_algs[] = {
    cose_aes128kw,      cose_aes192kw,        cose_aes256kw,        cose_direct,          cose_hkdf_sha256,     cose_hkdf_sha512,   cose_hkdf_aes128,
    cose_hkdf_aes256,   cose_ecdhes_hkdf_256, cose_ecdhes_hkdf_512, cose_ecdhss_hkdf_256, cose_ecdhss_hkdf_512, cose_ecdhes_a128kw, cose_ecdhes_a192kw,
    cose_ecdhes_a256kw, cose_ecdhss_a128kw,   cose_ecdhss_a192kw,   cose_ecdhss_a256kw,   cose_rsaoaep1,        cose_rsaoaep256,    cose_rsaoaep512,
};

void test_selfgen(crypto_key* key) {
    _test_case.begin("key generation");

    crypto_advisor* advisor = crypto_advisor::get_instance();
    binary_t input = convert("hello world");
    std::list<cose_alg_t> algs;
    size_t i = 0;
    size_t j = 0;
    for (i = 0; i < RTL_NUMBER_OF(sign_algs); i++) {
        algs.clear();
        cose_alg_t alg = sign_algs[i];
        algs.push_back(alg);
        std::string text = format("%i(%s)", alg, advisor->nameof_cose_algorithm(alg));
        test_sign(key, algs, input, text.c_str());
    }

    for (i = 0; i < RTL_NUMBER_OF(enc_algs); i++) {
        cose_alg_t alg = enc_algs[i];

        for (j = 0; j < RTL_NUMBER_OF(key_algs); j++) {
            algs.clear();
            cose_alg_t keyalg = key_algs[j];
            algs.push_back(alg);
            algs.push_back(keyalg);

            std::string text = format("%i(%s) %i(%s)", alg, advisor->nameof_cose_algorithm(alg), keyalg, advisor->nameof_cose_algorithm(keyalg));
            test_encrypt(key, algs, input, text.c_str());
        }
    }

    for (i = 0; i < RTL_NUMBER_OF(mac_algs); i++) {
        cose_alg_t alg = mac_algs[i];

        for (j = 0; j < RTL_NUMBER_OF(key_algs); j++) {
            algs.clear();
            cose_alg_t keyalg = key_algs[j];
            algs.push_back(alg);
            algs.push_back(keyalg);

            std::string text = format("%i(%s) %i(%s)", alg, advisor->nameof_cose_algorithm(alg), keyalg, advisor->nameof_cose_algorithm(keyalg));
            test_mac(key, algs, input, text.c_str());
        }
    }
}

void test_cose_encrypt(crypto_key* key, cose_alg_t alg, cose_alg_t keyalg, const binary_t& input, const char* text) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    binary_t cbor;

    cose_context_t* handle = nullptr;
    OPTION& option = _cmdline->value();

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }

    // sketch
    cose_layer& body = handle->composer->get_layer();
    body.get_protected().add(cose_key_t::cose_alg, alg);
    if (cose_alg_t::cose_unknown != keyalg) {
        cose_recipient& recipient = body.get_recipients().add(new cose_recipient);
        recipient.get_protected().add(cose_key_t::cose_alg, keyalg);

        // fill others and compose
        ret = cose.encrypt(handle, key, input, cbor);
    }

    cose.close(handle);

    _test_case.test(ret, __FUNCTION__, "cose %s", text);
}

void test_cose_sign(crypto_key* key, cose_alg_t alg, cose_alg_t keyalg, const binary_t& input, const char* text) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    binary_t cbor;

    cose_context_t* handle = nullptr;
    OPTION& option = _cmdline->value();

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }

    // sketch
    cose_layer& body = handle->composer->get_layer();
    body.get_protected().add(cose_key_t::cose_alg, alg);

    // fill others and compose
    ret = cose.encrypt(handle, key, input, cbor);

    cose.close(handle);

    _test_case.test(ret, __FUNCTION__, "cose %s", text);
}

void test_cose_mac(crypto_key* key, cose_alg_t alg, cose_alg_t keyalg, const binary_t& input, const char* text) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    binary_t cbor;

    cose_context_t* handle = nullptr;
    OPTION& option = _cmdline->value();

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }

    // sketch
    cose_layer& body = handle->composer->get_layer();
    body.get_protected().add(cose_key_t::cose_alg, alg);
    if (cose_alg_t::cose_unknown != keyalg) {
        cose_recipient& recipient = body.get_recipients().add(new cose_recipient);
        recipient.get_protected().add(cose_key_t::cose_alg, keyalg);

        // fill others and compose
        ret = cose.encrypt(handle, key, input, cbor);
    }

    cose.close(handle);

    _test_case.test(ret, __FUNCTION__, "cose %s", text);
}

void test_cose(crypto_key* key) {
    _test_case.begin("it's fun");

    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    cbor_object_signing_encryption cose;
    binary_t input = convert("hello world");
    size_t i = 0;
    size_t j = 0;

    for (i = 0; i < RTL_NUMBER_OF(enc_algs); i++) {
        cose_alg_t alg = enc_algs[i];

        for (j = 0; j < RTL_NUMBER_OF(key_algs); j++) {
            cose_alg_t keyalg = key_algs[j];
            std::string text = format("%i(%s) %i(%s)", alg, advisor->nameof_cose_algorithm(alg), keyalg, advisor->nameof_cose_algorithm(keyalg));
            test_cose_encrypt(key, alg, keyalg, input, text.c_str());
        }
    }
    for (i = 0; i < RTL_NUMBER_OF(sign_algs); i++) {
        cose_alg_t alg = sign_algs[i];

        std::string text = format("%i(%s)", alg, advisor->nameof_cose_algorithm(alg));
        test_cose_sign(key, alg, cose_alg_t::cose_unknown, input, text.c_str());
    }
    for (i = 0; i < RTL_NUMBER_OF(mac_algs); i++) {
        cose_alg_t alg = mac_algs[i];

        for (j = 0; j < RTL_NUMBER_OF(key_algs); j++) {
            cose_alg_t keyalg = key_algs[j];
            std::string text = format("%i(%s) %i(%s)", alg, advisor->nameof_cose_algorithm(alg), keyalg, advisor->nameof_cose_algorithm(keyalg));
            test_cose_mac(key, alg, keyalg, input, text.c_str());
        }
    }
}

void test_cwt_rfc8392() {
    _test_case.begin("CWT");

    // A.1.  Example CWT Claims Set
    constexpr char claim[] =
        "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9"
        "f007420b71";
    // A.2.1.  128-Bit Symmetric Key
    constexpr char symm128[] = "a42050231f4c4d4d3051fdc2ec0a3851d5b3830104024c53796d6d6574726963313238030a";
    // A.2.2.  256-Bit Symmetric Key
    constexpr char symm256[] = "a4205820403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d795693880104024c53796d6d6574726963323536030a";
    // A.2.3.  Elliptic Curve Digital Signature Algorithm (ECDSA) P-256 256-Bit COSE Key
    constexpr char ec256p[] =
        "a72358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c1922582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b921582014"
        "3329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f2001010202524173796d6d657472696345434453413235360326";
    // A.3.  Example Signed CWT
    constexpr char cwt_signed[] =
        "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c69676874"
        "2e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131"
        "680c429a01f85951ecee743a52b9b63632c57209120e1c9e30";
    // A.4.  Example MACed CWT
    constexpr char cwt_maced[] =
        "d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e657861"
        "6d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200";
    // A.5.  Example Encrypted CWT
    constexpr char cwt_encrypted[] =
        "d08343a1010aa2044c53796d6d6574726963313238054d99a0d7846e762c49ffe8a63e0b5858b918a11fd81e438b7f973d9e2e119bcb22424ba0f38a80f27562f400ee1d0d6c0fdb559c02"
        "421fd384fc2ebe22d7071378b0ea7428fff157444d45f7e6afcda1aae5f6495830c58627087fc5b4974f319a8707a635dd643b";
    // A.6.  Example Nested CWT
    constexpr char cwt_nested[] =
        "d08343a1010aa2044c53796d6d6574726963313238054d4a0694c0e69ee6b5956655c7b258b7f6b0914f993de822cc47e5e57a188d7960b528a747446fe12f0e7de05650dec74724366763"
        "f167a29c002dfd15b34d8993391cf49bc91127f545dba8703d66f5b7f1ae91237503d371e6333df9708d78c4fb8a8386c8ff09dc49af768b23179deab78d96490a66d5724fb33900c60799"
        "d9872fac6da3bdb89043d67c2a05414ce331b5b8f1ed8ff7138f45905db2c4d5bc8045ab372bff142631610a7e0f677b7e9b0bc73adefdcee16d9d5d284c616abeab5d8c291ce0";
    // A.7.  Example MACed CWT with a Floating-Point Value
    constexpr char cwt_maced_fp[] = "d18443a10104a1044c53796d6d65747269633235364ba106fb41d584367c20000048b8816f34c0542892";

    return_t ret = errorcode_t::success;
    OPTION& option = _cmdline->value();
    crypto_key key;
    cbor_web_key cwk;
    cwk.load(&key, symm128);
    cwk.load(&key, symm256);
    cwk.load(&key, ec256p);

    key.for_each(dump_crypto_key, nullptr);

    bool result = false;
    cose_context_t* handle = nullptr;
    cbor_object_signing_encryption cose;
    binary_t output;

    cose.open(&handle);
    if (option.verbose) {
        cose.set(handle, cose_flag_t::cose_flag_allow_debug);
    }
    ret = cose.verify(handle, &key, base16_decode(cwt_signed), result);
    _test_case.test(ret, __FUNCTION__, "RFC 8392 A.3.  Example Signed CWT");
    ret = cose.verify(handle, &key, base16_decode(cwt_maced), result);
    _test_case.test(ret, __FUNCTION__, "RFC 8392 A.4.  Example MACed CWT");
    ret = cose.decrypt(handle, &key, base16_decode(cwt_encrypted), output, result);
    _test_case.test(ret, __FUNCTION__, "RFC 8392 A.5.  Example Encrypted CWT");
    ret = cose.process(handle, &key, base16_decode(cwt_nested), output);
    _test_case.test(ret, __FUNCTION__, "RFC 8392 A.6.  Example Nested CWT");
    ret = cose.process(handle, &key, base16_decode(cwt_maced_fp), output);
    _test_case.test(ret, __FUNCTION__, "RFC 8392 A.7.  Example MACed CWT with a Floating-Point Value");
    cose.close(handle);
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new cmdline_t<OPTION>);
    *_cmdline << cmdarg_t<OPTION>("-v", "verbose", [&](OPTION& o, char* param) -> void { o.verbose = true; }).optional();
    *_cmdline << cmdarg_t<OPTION>("-k", "dump keys", [&](OPTION& o, char* param) -> void { o.dump_keys = true; }).optional();
    *_cmdline << cmdarg_t<OPTION>("-b", "skip basic encoding", [&](OPTION& o, char* param) -> void { o.skip_cbor_basic = true; }).optional();
    *_cmdline << cmdarg_t<OPTION>("-s", "skip validation w/ test vector", [&](OPTION& o, char* param) -> void { o.skip_validate = true; }).optional();
    *_cmdline << cmdarg_t<OPTION>("-g", "skip self-generated message", [&](OPTION& o, char* param) -> void { o.skip_gen = true; }).optional();
    (*_cmdline).parse(argc, argv);

    OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    _logger->writeln("option.verbose %i", option.verbose ? 1 : 0);
    _logger->writeln("option.dump_keys %i", option.dump_keys ? 1 : 0);
    _logger->writeln("option.skip_validate %i", option.skip_validate ? 1 : 0);
    _logger->writeln("option.skip_gen %i", option.skip_gen ? 1 : 0);

    if (option.verbose) {
        set_trace_option(trace_option_t::trace_bt | trace_option_t::trace_except);
    }

    openssl_startup();
    openssl_thread_setup();

    test_eckey_compressed();

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
    if (!option.skip_cbor_basic) {
        test_rfc8152_read_cbor();
    }

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

        test_rfc8152_b();
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
        // test_jose_from_cwk();
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
    if (!option.skip_validate) {
        test_github_example();
    }

    // part 4 encrypt/sign/mac
    if (!option.skip_gen) {
        crypto_key key;
        test_keygen(&key);
        test_selfgen(&key);
        test_cose(&key);
    }

    // part 5 CWT
    test_cwt_rfc8392();

    openssl_thread_cleanup();
    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
