/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

test_case _test_case;

/**
 * @brief   interface prototyping
 */
typedef struct _cose_item_t {
    variant_t key;
    variant_t value;
} cose_item_t;
typedef std::list <cose_item_t> cose_list_t;

class cbor_object_signing_encryption
{
public:
    cbor_object_signing_encryption ();
    ~cbor_object_signing_encryption ();

    return_t build_protected (cbor_data** object);
    return_t build_protected (cbor_data** object, cose_list_t& input);
    return_t build_protected (cbor_data** object, cbor_map* input);
    return_t build_unprotected (cbor_map** object);
    return_t build_unprotected (cbor_map** object, cose_list_t& input);
    return_t build_payload (cbor_data** object, const char* payload);
    return_t build_payload (cbor_data** object, const byte_t* payload, size_t size);
    return_t build_base16str (cbor_data** object, const char* str);
};

cbor_object_signing_encryption::cbor_object_signing_encryption ()
{
    // do nothing
}
cbor_object_signing_encryption::~cbor_object_signing_encryption ()
{
    // do nothing
}

return_t cbor_object_signing_encryption::build_protected (cbor_data** object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_data* part_protected = nullptr;
        binary_t dummy;
        __try_new_catch (part_protected, new cbor_data (dummy), ret, __leave2);
        *object = part_protected;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::build_protected (cbor_data** object, cose_list_t& input)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == input.size ()) {
            cbor_data* part_protected = nullptr;
            binary_t dummy;
            __try_new_catch (part_protected, new cbor_data (dummy), ret, __leave2);
            *object = part_protected;
        } else {
            binary_t bin_protected;
            cbor_map* part_protected = nullptr;

            __try_new_catch (part_protected, new cbor_map (), ret, __leave2);

            cose_list_t::iterator iter;
            for (iter = input.begin (); iter != input.end (); iter++) {
                cose_item_t& item = *iter;
                *part_protected << new cbor_pair (new cbor_data (item.key), new cbor_data (item.value));
            }

            build_protected (object, part_protected);

            part_protected->release ();
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::build_protected (cbor_data** object, cbor_map* input)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object || nullptr == input) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_protected;
        cbor_publisher publisher;
        publisher.publish (input, &bin_protected);

        *object = new cbor_data (bin_protected);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::build_unprotected (cbor_map** object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch (part_unprotected, new cbor_map (), ret, __leave2);

        *object = part_unprotected;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::build_unprotected (cbor_map** object, cose_list_t& input)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch (part_unprotected, new cbor_map (), ret, __leave2);

        cose_list_t::iterator iter;
        for (iter = input.begin (); iter != input.end (); iter++) {
            cose_item_t& item = *iter;
            *part_unprotected << new cbor_pair (new cbor_data (item.key), new cbor_data (item.value));
        }

        *object = part_unprotected;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::build_payload (cbor_data** object, const char* payload)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object || nullptr == payload) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch (*object, new cbor_data (convert (payload)), ret, __leave2);
    }
    __finally2
    {
    }
    return ret;
}

return_t cbor_object_signing_encryption::build_payload (cbor_data** object, const byte_t* payload, size_t size)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch (*object, new cbor_data (payload, size), ret, __leave2);
    }
    __finally2
    {
    }
    return ret;
}

return_t cbor_object_signing_encryption::build_base16str (cbor_data** object, const char* str)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object || nullptr == str) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch (*object, new cbor_data (base16_decode (str)), ret, __leave2);
    }
    __finally2
    {
    }
    return ret;
}

return_t compare (binary_t const& lhs, binary_t const& rhs)
{
    return_t ret = errorcode_t::success;

    if (lhs.size () == rhs.size ()) {
        if (0 == memcmp (&lhs[0], &rhs[0], lhs.size ())) {
            // do nothing
        } else {
            ret = errorcode_t::mismatch;
        }
    } else {
        ret = errorcode_t::mismatch;
    }
    return ret;
}

return_t dump_test_data (const char* text, buffer_stream& diagnostic)
{
    return_t ret = errorcode_t::success;

    if (text) {
        std::cout << text;
    } else {
        std::cout << "diagnostic";
    }
    std::cout << std::endl << diagnostic.c_str () << std::endl;

    return ret;
}

return_t dump_test_data (const char* text, binary_t const& cbor)
{
    return_t ret = errorcode_t::success;

    buffer_stream bs;

    dump_memory (cbor, &bs, 32);

    if (text) {
        std::cout << text;
    } else {
        std::cout << "diagnostic";
    }
    std::cout << std::endl << bs.c_str () << std::endl;

    return ret;
}

return_t test_generated_cbor (cbor_object* root, const char* expect_file, const char* text)
{
    return_t ret = errorcode_t::success;
    return_t test = errorcode_t::success;

    __try2
    {
        if (nullptr == root || nullptr == expect_file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_publisher publisher;

        // cbor_object* to diagnostic
        buffer_stream diagnostic;
        publisher.publish (root, &diagnostic);

        // cbor_object* to cbor
        binary_t bin;
        publisher.publish (root, &bin);

        // load cbor from file
        binary_t expect;
        {
            test_case_notimecheck notimecheck (_test_case);

            file_stream fs;
            ret = fs.open (expect_file);
            if (errorcode_t::success != ret) {
                __leave2;
            }
            fs.begin_mmap ();

            byte_t* file_contents = fs.data ();
            size_t file_size = fs.size ();
            expect.insert (expect.end (), file_contents, file_contents + file_size);

            dump_test_data ("test vector", expect);
        }

        // std::cout
        // compare
        {
            test_case_notimecheck notimecheck (_test_case);

            dump_test_data ("diagnostic #1", diagnostic);
            dump_test_data ("cbor #1", bin);

            test = compare (bin, expect);
        }
        _test_case.test (test, __FUNCTION__, "check1.cborcheck %s", text ? text : "");

        // parse
        buffer_stream bs_diagnostic_lv1;
        binary_t bin_cbor_lv1;

        cbor_reader reader;
        cbor_reader_context_t* handle = nullptr;
        cbor_object* newone = nullptr;

        reader.open (&handle);
        reader.parse (handle, bin);
        // cbor_reader_context_t* to diagnostic
        reader.publish (handle, &bs_diagnostic_lv1);
        // cbor_reader_context_t* to cbor
        reader.publish (handle, &bin_cbor_lv1);
        // cbor_reader_context_t* to cbor_object*
        reader.publish (handle, &newone);
        reader.close (handle);

        {
            test_case_notimecheck notimecheck (_test_case);

            dump_test_data ("diagnostic #2", bs_diagnostic_lv1);
            dump_test_data ("cbor #2", bin_cbor_lv1);

            test = compare (bin_cbor_lv1, expect);
        }
        _test_case.test (test, __FUNCTION__, "check2.cborparse %s", text ? text : "");

        // parsed cbor_object* to diagnostic
        buffer_stream bs_diagnostic_lv2;
        publisher.publish (newone, &bs_diagnostic_lv2);

        // parsed cbor_object* to cbor
        binary_t bin_cbor_lv2;
        publisher.publish (newone, &bin_cbor_lv2);

        {
            test_case_notimecheck notimecheck (_test_case);

            dump_test_data ("diagnostic #3", bs_diagnostic_lv2);
            dump_test_data ("cbor #3", bin_cbor_lv2);

            test = compare (bin_cbor_lv2, expect);
        }
        _test_case.test (test, __FUNCTION__, "check3.cborparse %s", text ? text : "");

        newone->release (); // release parsed object
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

void test_cbor_file (const char* expect_file, const char* text)
{
    _test_case.begin ("parse and generate diagnostic from RFC examples");

    console_color color;

    std::cout << color.turnon ().set_style (console_style_t::bold).set_fgcolor (console_color_t::cyan) << expect_file << std::endl;
    std::cout << color.turnoff ();

    return_t ret = errorcode_t::success;

    __try2
    {
        binary_t expect;
        file_stream fs;
        ret = fs.open (expect_file);
        if (errorcode_t::success == ret) {
            fs.begin_mmap ();

            byte_t* file_contents = fs.data ();
            size_t file_size = fs.size ();
            expect.insert (expect.end (), file_contents, file_contents + file_size);
        } else {
            __leave2;
        }

        buffer_stream bs_diagnostic;
        binary_t bin_cbor;

        cbor_reader reader;
        cbor_reader_context_t* handle = nullptr;
        cbor_object* root = nullptr;

        reader.open (&handle);
        reader.parse (handle, expect);
        reader.publish (handle, &bs_diagnostic);
        reader.publish (handle, &bin_cbor);
        //reader.publish (handle, &root);
        //root->release ();
        reader.close (handle);


        buffer_stream bs_dump;
        dump_memory (bin_cbor, &bs_dump, 32);

        std::cout   << "diagnostic " << std::endl
                    << bs_diagnostic.c_str () << std::endl
                    << bs_dump.c_str () << std::endl;

        ret = compare (bin_cbor, expect);
    }
    __finally2
    {
        // do nothing
    }
    _test_case.test (ret, __FUNCTION__, text ? text : "");
}

void test_rfc8152_c_1_1 ()
{
    _test_case.begin ("RFC 8152 C.1");

    // Signature Algorithm: ECDSA w/ SHA-256, Curve P-256

    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_data* cbor_data_protected = nullptr;
    cose.build_protected (&cbor_data_protected);

    cbor_data* cbor_data_payload = nullptr;
    cose.build_payload (&cbor_data_payload, "This is the content.");

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_sign);
    *root   << cbor_data_protected  // protected, bstr
            << new cbor_map ()      // unprotected, map
            << cbor_data_payload    // payload, bstr/nil(detached)
            << new cbor_array ();   // signatures

    cbor_array* signatures = (cbor_array*) (*root)[3];

    cbor_array* signature = new cbor_array ();
    {
        cbor_data* cbor_data_signature_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_es256);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_signature_protected, list_protected);
        }

        cbor_map* cbor_data_signature_unprotected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_unprotected;
            variant_set_int16 (item.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item.value, "11", 2);
            list_unprotected.push_back (item);
            cose.build_unprotected (&cbor_data_signature_unprotected, list_unprotected);
        }

        cbor_data* cbor_data_signature_signature = nullptr;
        {
            constexpr char constexpr_sig[] = "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a";
            cose.build_base16str (&cbor_data_signature_signature, constexpr_sig);
        }

        *signature  << cbor_data_signature_protected
                    << cbor_data_signature_unprotected
                    << cbor_data_signature_signature;
    }
    *signatures << signature;

    test_generated_cbor (root, "rfc8152_c_1_1.cbor", "RFC 8152 C.1.1.  Single Signature");

    root->release ();
}

void test_rfc8152_c_1_2 ()
{
    _test_case.begin ("RFC 8152 C.1");

    // Signature Algorithm: ECDSA w/ SHA-256, Curve P-256
    // Signature Algorithm: ECDSA w/ SHA-512, Curve P-521

    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_data* cbor_data_protected = nullptr;
    cose.build_protected (&cbor_data_protected);

    cbor_data* cbor_data_payload = nullptr;
    cose.build_payload (&cbor_data_payload, "This is the content.");

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_sign);
    *root   << cbor_data_protected  // protected
            << new cbor_map ()      // unprotected
            << cbor_data_payload    // payload
            << new cbor_array ();   // signatures

    cbor_array* signatures = (cbor_array*) (*root)[3];

    {
        cbor_array* signature = new cbor_array ();

        cbor_data* cbor_data_signature_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_es256);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_signature_protected, list_protected);
        }

        cbor_map* cbor_data_signature_unprotected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_unprotected;
            variant_set_int16 (item.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item.value, "11", 2);
            list_unprotected.push_back (item);
            cose.build_unprotected (&cbor_data_signature_unprotected, list_unprotected);
        }

        cbor_data* cbor_data_signature_signature = nullptr;
        {
            constexpr char constexpr_sig[] = "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a";
            cose.build_base16str (&cbor_data_signature_signature, constexpr_sig);
        }

        *signature  << cbor_data_signature_protected
                    << cbor_data_signature_unprotected
                    << cbor_data_signature_signature;

        *signatures << signature;
    }
    {
        cbor_array* signature = new cbor_array ();

        cbor_data* cbor_data_signature_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_es512);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_signature_protected, list_protected);
        }

        cbor_map* cbor_data_signature_unprotected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_unprotected;
            variant_set_int16 (item.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item.value, "bilbo.baggins@hobbiton.example", 30);
            list_unprotected.push_back (item);
            cose.build_unprotected (&cbor_data_signature_unprotected, list_unprotected);
        }

        cbor_data* cbor_data_signature_signature = nullptr;
        {
            constexpr char constexpr_sig[] = "00a2d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e8705524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf482270cc5771aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f83ab87bb4f7a0297";
            cose.build_base16str (&cbor_data_signature_signature, constexpr_sig);
        }

        *signature  << cbor_data_signature_protected
                    << cbor_data_signature_unprotected
                    << cbor_data_signature_signature;

        *signatures << signature;
    }

    test_generated_cbor (root, "rfc8152_c_1_2.cbor", "RFC 8152 C.1.2.  Multiple Signers");

    root->release ();
}

void test_rfc8152_c_1_3 ()
{
    _test_case.begin ("RFC 8152 C.1");

    // Signature Algorithm: ECDSA w/ SHA-256, Curve P-256
    // The same parameters are used for both the signature and the counter signature.

    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_data* cbor_data_protected = nullptr;
    cose.build_protected (&cbor_data_protected);

    cbor_data* cbor_data_payload = nullptr;
    cose.build_payload (&cbor_data_payload, "This is the content.");

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_sign);
    *root   << cbor_data_protected  // protected
            << new cbor_map ()      // unprotected
            << cbor_data_payload    // payload
            << new cbor_array ();   // signatures

    cbor_map* header_unprotected = (cbor_map*) (*root)[1];
    {
        cbor_array* countersign = new cbor_array ();
        *header_unprotected << new cbor_pair (cose_header_t::cose_header_counter_sig, countersign);

        cbor_data* cbor_data_countersignature_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_es256);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_countersignature_protected, list_protected);
        }

        cbor_map* cbor_data_countersignature_unprotected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_unprotected;
            variant_set_int16 (item.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item.value, "11", 2);
            list_unprotected.push_back (item);
            cose.build_unprotected (&cbor_data_countersignature_unprotected, list_unprotected);
        }

        cbor_data* cbor_data_countersignature_signature = nullptr;
        {
            constexpr char constexpr_sig[] = "5ac05e289d5d0e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887e8802bb6650cceb2c";
            cose.build_base16str (&cbor_data_countersignature_signature, constexpr_sig);
        }

        *countersign    << cbor_data_countersignature_protected
                        << cbor_data_countersignature_unprotected
                        << cbor_data_countersignature_signature;
    }

    cbor_array* signatures = (cbor_array*) (*root)[3];

    cbor_array* signature = new cbor_array ();
    {
        cbor_data* cbor_data_signature_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_es256);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_signature_protected, list_protected);
        }

        cbor_map* cbor_data_signature_unprotected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_unprotected;
            variant_set_int16 (item.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item.value, "11", 2);
            list_unprotected.push_back (item);
            cose.build_unprotected (&cbor_data_signature_unprotected, list_unprotected);
        }

        cbor_data* cbor_data_signature_signature = nullptr;
        {
            constexpr char constexpr_sig[] = "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a";
            cose.build_base16str (&cbor_data_signature_signature, constexpr_sig);
        }

        *signature  << cbor_data_signature_protected
                    << cbor_data_signature_unprotected
                    << cbor_data_signature_signature;

        *signatures << signature;
    }

    test_generated_cbor (root, "rfc8152_c_1_3.cbor", "RFC 8152 C.1.3.  Counter Signature");

    root->release ();
}

void test_rfc8152_c_1_4 ()
{
    _test_case.begin ("RFC 8152 C.1");

    // Signature Algorithm: ECDSA w/ SHA-256, Curve P-256
    // There is a criticality marker on the "reserved" header parameter

    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_sign);

    cbor_data* cbor_data_protected = nullptr;
    {
        cbor_map* cbor_map_protected = new cbor_map ();

        cbor_array* crit = new cbor_array ();
        *crit << new cbor_data ("reserved"); // [+ label]

        *cbor_map_protected << new cbor_pair ("reserved", new cbor_data (false))
                            << new cbor_pair (cose_header_t::cose_header_crit, crit);

        cose.build_protected (&cbor_data_protected, cbor_map_protected);

        cbor_map_protected->release ();
    }

    cbor_data* cbor_data_payload = nullptr;
    cose.build_payload (&cbor_data_payload, "This is the content.");

    *root   << cbor_data_protected  // protected
            << new cbor_map ()      // unprotected
            << cbor_data_payload    // payload
            << new cbor_array ();   // signatures

    cbor_array* signatures = (cbor_array*) (*root)[3];

    cbor_array* signature = new cbor_array ();
    {
        cbor_data* cbor_data_signature_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_es256);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_signature_protected, list_protected);
        }

        cbor_map* cbor_data_signature_unprotected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_unprotected;
            variant_set_int16 (item.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item.value, "11", 2);
            list_unprotected.push_back (item);
            cose.build_unprotected (&cbor_data_signature_unprotected, list_unprotected);
        }

        cbor_data* cbor_data_signature_signature = nullptr;
        {
            constexpr char constexpr_sig[] = "3fc54702aa56e1b2cb20284294c9106a63f91bac658d69351210a031d8fc7c5ff3e4be39445b1a3e83e1510d1aca2f2e8a7c081c7645042b18aba9d1fad1bd9c";
            cose.build_base16str (&cbor_data_signature_signature, constexpr_sig);
        }

        *signature  << cbor_data_signature_protected
                    << cbor_data_signature_unprotected
                    << cbor_data_signature_signature;

        *signatures << signature;
    }

    test_generated_cbor (root, "rfc8152_c_1_4.cbor", "RFC 8152 C.1.4.  Signature with Criticality");

    root->release ();
}

void test_rfc8152_c_2_1 ()
{
    _test_case.begin ("RFC 8152 C.2");
    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_sign1);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_es256);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_unprotected;
        variant_set_int16 (item.key, cose_header_t::cose_header_kid);
        variant_set_bstr_new (item.value, "11", 2);
        list_unprotected.push_back (item);
        cose.build_unprotected (&cbor_data_unprotected, list_unprotected);
    }

    cbor_data* cbor_data_payload = nullptr;
    cose.build_payload (&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_signature = nullptr;
    cose.build_base16str (&cbor_data_signature, "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36");

    *root   << cbor_data_protected
            << cbor_data_unprotected
            << cbor_data_payload
            << cbor_data_signature;

    test_generated_cbor (root, "rfc8152_c_2_1.cbor", "RFC 8152 C.2.1.  Single ECDSA Signature");

    root->release ();
}

void test_rfc8152_c_3_1 ()
{
    _test_case.begin ("RFC 8152 C.3");
    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_encrypt);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_aes_128_gcm);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    cbor_data* cbor_data_ciphertext = nullptr;
    cose.build_base16str (&cbor_data_ciphertext, "7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0");

    *root   << cbor_data_protected  // protected
            << new cbor_map ()      // unprotected
            << cbor_data_ciphertext // ciphertext
            << new cbor_array ();   // recipients

    cbor_map* header_unprotected = (cbor_map*) (*root)[1];
    {
        *header_unprotected << new cbor_pair (cose_header_t::cose_header_iv, new cbor_data (base16_decode ("c9cf4df2fe6c632bf7886413")));
    }

    cbor_array* recipients = (cbor_array*) (*root)[3];

    cbor_array* recipient = new cbor_array ();
    {
        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_ecdh_es_hkdf_256);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_recipient_protected, list_protected);
        }

        cbor_map* cbor_data_recipient_unprotected = new cbor_map ();
        {
            constexpr char constexpr_x [] = "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280";
            constexpr char constexpr_kid [] = "meriadoc.brandybuck@buckland.example";

            cbor_map* ephemeral = new cbor_map ();
            *ephemeral
                << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_ec2))       // kty
                << new cbor_pair (cose_key_lable_t::cose_ec_crv, new cbor_data (cose_ec_curve_t::cose_ec_p256))     // crv
                << new cbor_pair (cose_key_lable_t::cose_ec_x, new cbor_data (base16_decode (constexpr_x)))         // x
                << new cbor_pair (cose_key_lable_t::cose_ec_y, new cbor_data (true));                               // y

            *cbor_data_recipient_unprotected
                << new cbor_pair (cose_alg_param_t::cose_ephemeral_key, ephemeral)                              // epk
                << new cbor_pair (cose_header_t::cose_header_kid, new cbor_data (convert (constexpr_kid)));     // kid
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        cose.build_base16str (&cbor_data_recipient_ciphertext, "");

        *recipient  << cbor_data_recipient_protected    // protected
                    << cbor_data_recipient_unprotected  // unprotected
                    << cbor_data_recipient_ciphertext;  // ciphertext
    }
    *recipients << recipient;

    test_generated_cbor (root, "rfc8152_c_3_1.cbor", "RFC 8152 C.3.1.  Direct ECDH");

    root->release ();
}

void test_rfc8152_c_3_2 ()
{
    _test_case.begin ("RFC 8152 C.3");
    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_encrypt);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_aes_ccm_16_64_128);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_iv);
        binary_t b16;
        b16 = base16_decode ("89f52f65a1c580933b5261a76c");
        variant_set_bstr_new (item.value, &b16[0], b16.size ());
        list_protected.push_back (item);
        cose.build_unprotected (&cbor_data_unprotected, list_protected);
    }

    cbor_data* cbor_data_ciphertext = nullptr;
    cose.build_base16str (&cbor_data_ciphertext, "753548a19b1307084ca7b2056924ed95f2e3b17006dfe931b687b847");

    *root   << cbor_data_protected      // protected
            << cbor_data_unprotected    // unprotected
            << cbor_data_ciphertext     // ciphertext
            << new cbor_array ();       // recipients

    cbor_array* recipients = (cbor_array*) (*root)[3];

    {
        cbor_array* recipient = new cbor_array ();
        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_direct_hkdf_sha_256);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_recipient_protected, list_protected);
        }
        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_item_t item1;
            cose_item_t item2;
            cose_list_t list_unprotected;
            variant_set_int16 (item1.key, cose_alg_param_t::cose_salt);
            variant_set_bstr_new (item1.value, "aabbccddeeffgghh", 16);
            list_unprotected.push_back (item1);
            variant_set_int16 (item2.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item2.value, "our-secret", 10);
            list_unprotected.push_back (item2);
            cose.build_unprotected (&cbor_data_recipient_unprotected, list_unprotected);
        }

        *recipient  << cbor_data_recipient_protected        // protected
                    << cbor_data_recipient_unprotected      // unprotected
                    << new cbor_data (base16_decode (""));  // ciphertext

        *recipients << recipient;
    }

    test_generated_cbor (root, "rfc8152_c_3_2.cbor", "RFC 8152 C.3.2.  Direct Plus Key Derivation");

    root->release ();
}

void test_rfc8152_c_3_3 ()
{
    _test_case.begin ("RFC 8152 C.3");
    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_encrypt);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_aes_128_gcm);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    constexpr char constexpr_ciphertext[] = "7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0";
    cbor_data* cbor_data_ciphertext = nullptr;
    cose.build_base16str (&cbor_data_ciphertext, constexpr_ciphertext);

    *root   << cbor_data_protected      // protected
            << new cbor_map ()          // unprotected
            << cbor_data_ciphertext     // ciphertext
            << new cbor_array ();       // recipients

    cbor_map* cbor_data_unprotected = (cbor_map*) (*root)[1];
    {
        cbor_array* countersign = new cbor_array ();
        *cbor_data_unprotected << new cbor_pair (cose_header_t::cose_header_iv, new cbor_data (base16_decode ("c9cf4df2fe6c632bf7886413")));
        *cbor_data_unprotected << new cbor_pair (cose_header_t::cose_header_counter_sig, countersign);

        cbor_data* cbor_data_countersignature_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_es512);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_countersignature_protected, list_protected);
        }

        cbor_map* cbor_data_countersignature_unprotected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_unprotected;
            variant_set_int16 (item.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item.value, "bilbo.baggins@hobbiton.example", 30);
            list_unprotected.push_back (item);
            cose.build_unprotected (&cbor_data_countersignature_unprotected, list_unprotected);
        }

        constexpr char constexpr_signature[] = "00929663c8789bb28177ae28467e66377da12302d7f9594d2999afa5dfa531294f8896f2b6cdf1740014f4c7f1a358e3a6cf57f4ed6fb02fcf8f7aa989f5dfd07f0700a3a7d8f3c604ba70fa9411bd10c2591b483e1d2c31de003183e434d8fba18f17a4c7e3dfa003ac1cf3d30d44d2533c4989d3ac38c38b71481cc3430c9d65e7ddff";
        cbor_data* cbor_data_countersignature_signature = nullptr;
        cose.build_base16str (&cbor_data_countersignature_signature, constexpr_signature);

        *countersign    << cbor_data_countersignature_protected     // protected
                        << cbor_data_countersignature_unprotected   // unprotected
                        << cbor_data_countersignature_signature;    // signature
    }

    cbor_array* recipients = (cbor_array*) (*root)[3];
    {
        cbor_array* recipient = new cbor_array ();

        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_ecdh_es_hkdf_256);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_recipient_protected, list_protected);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        cose.build_base16str (&cbor_data_recipient_ciphertext, "");

        *recipient  << cbor_data_recipient_protected    // protected
                    << new cbor_map ()                  // unprotected
                    << cbor_data_recipient_ciphertext;  // ciphertext

        cbor_map* cbor_data_recipient_unprotected = (cbor_map*) (*recipient)[1];
        {
            constexpr char constexpr_x[] = "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280";
            constexpr char constexpr_kid[] = "meriadoc.brandybuck@buckland.example";
            cbor_map* ephemeral = new cbor_map ();
            *ephemeral
                << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_ec2))       // kty
                << new cbor_pair (cose_key_lable_t::cose_ec_crv, new cbor_data (cose_ec_curve_t::cose_ec_p256))     // crv
                << new cbor_pair (cose_key_lable_t::cose_ec_x, new cbor_data (base16_decode (constexpr_x)))         // x
                << new cbor_pair (cose_key_lable_t::cose_ec_y, new cbor_data (true));                               // y

            *cbor_data_recipient_unprotected
                << new cbor_pair (cose_alg_param_t::cose_ephemeral_key, ephemeral)                              // epk
                << new cbor_pair (cose_header_t::cose_header_kid, new cbor_data (convert (constexpr_kid)));     // kid
        }

        *recipients << recipient;
    }

    test_generated_cbor (root, "rfc8152_c_3_3.cbor", "RFC 8152 C.3.3.  Counter Signature on Encrypted Content");

    root->release ();
}

void test_rfc8152_c_3_4 ()
{
    _test_case.begin ("RFC 8152 C.3");

    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_encrypt);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_aes_128_gcm);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_iv);
        binary_t b16;
        b16 = base16_decode ("02d1f7e6f26c43d4868d87ce");
        variant_set_bstr_new (item.value, &b16[0], b16.size ());
        list_protected.push_back (item);
        cose.build_unprotected (&cbor_data_unprotected, list_protected);
    }

    constexpr char constexpr_ciphertext[] = "64f84d913ba60a76070a9a48f26e97e863e28529d8f5335e5f0165eee976b4a5f6c6f09d";
    cbor_data* cbor_data_ciphertext = nullptr;
    cose.build_base16str (&cbor_data_ciphertext, constexpr_ciphertext);

    *root   << cbor_data_protected      // protected
            << cbor_data_unprotected    // unprotected
            << cbor_data_ciphertext     // ciphertext
            << new cbor_array ();       // recipients

    cbor_array* recipients = (cbor_array*) (*root)[3];
    {
        cbor_array* recipient = new cbor_array ();

        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_ecdh_ss_a128kw);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_recipient_protected, list_protected);
        }

        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_item_t item1;
            cose_item_t item2;
            cose_item_t item3;
            cose_list_t list_protected;
            variant_set_int16 (item1.key, cose_alg_param_t::cose_static_key_id);
            variant_set_bstr_new (item1.value, "peregrin.took@tuckborough.example", 33);
            list_protected.push_back (item1);
            variant_set_int16 (item2.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item2.value, "meriadoc.brandybuck@buckland.example", 36);
            list_protected.push_back (item2);
            variant_set_int16 (item3.key, cose_alg_param_t::cose_partyu_nonce);
            binary_t b16;
            b16 = base16_decode ("0101");
            variant_set_bstr_new (item3.value, &b16[0], b16.size ());
            list_protected.push_back (item3);
            cose.build_unprotected (&cbor_data_recipient_unprotected, list_protected);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        cose.build_base16str (&cbor_data_recipient_ciphertext, "41e0d76f579dbd0d936a662d54d8582037de2e366fde1c62");

        *recipient  << cbor_data_recipient_protected    // protected
                    << cbor_data_recipient_unprotected  // unprotected
                    << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }

    test_generated_cbor (root, "rfc8152_c_3_4.cbor", "RFC 8152 C.3.4.  Encrypted Content with External Data");

    root->release ();
}

void test_rfc8152_c_4_1 ()
{
    _test_case.begin ("RFC 8152 C.4");

    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_encrypt0);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_aes_ccm_16_64_128);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_iv);
        binary_t b16;
        b16 = base16_decode ("89f52f65a1c580933b5261a78c");
        variant_set_bstr_new (item.value, &b16[0], b16.size ());
        list_protected.push_back (item);
        cose.build_unprotected (&cbor_data_unprotected, list_protected);
    }

    constexpr char constexpr_ciphertext[] = "5974e1b99a3a4cc09a659aa2e9e7fff161d38ce71cb45ce460ffb569";
    cbor_data* cbor_data_ciphertext = nullptr;
    cose.build_base16str (&cbor_data_ciphertext, constexpr_ciphertext);

    *root   << cbor_data_protected      // protected
            << cbor_data_unprotected    // unprotected
            << cbor_data_ciphertext;    // ciphertext

    test_generated_cbor (root, "rfc8152_c_4_1.cbor", "RFC 8152 C.4.1.  Simple Encrypted Message");

    root->release ();
}

void test_rfc8152_c_4_2 ()
{
    _test_case.begin ("RFC 8152 C.4");

    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_encrypt0);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_aes_ccm_16_64_128);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_partial_iv);
        binary_t b16;
        b16 = base16_decode ("61a7");
        variant_set_bstr_new (item.value, &b16[0], b16.size ());
        list_protected.push_back (item);
        cose.build_unprotected (&cbor_data_unprotected, list_protected);
    }

    constexpr char constexpr_ciphertext[] = "252a8911d465c125b6764739700f0141ed09192de139e053bd09abca";
    cbor_data* cbor_data_ciphertext = nullptr;
    cose.build_base16str (&cbor_data_ciphertext, constexpr_ciphertext);

    *root   << cbor_data_protected      // protected
            << cbor_data_unprotected    // unprotected
            << cbor_data_ciphertext;    // ciphertext

    test_generated_cbor (root, "rfc8152_c_4_2.cbor", "RFC 8152 C.4.2.  Encrypted Message with a Partial IV");

    root->release ();
}

void test_rfc8152_c_5_1 ()
{
    _test_case.begin ("RFC 8152 C.5");

    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_mac);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_aes_cbc_mac_256_64);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose.build_unprotected (&cbor_data_unprotected);
    }

    cbor_data* cbor_data_payload = nullptr;
    cose.build_payload (&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_tag = nullptr;
    cose.build_base16str (&cbor_data_tag, "9e1226ba1f81b848");

    *root   << cbor_data_protected      // protected
            << cbor_data_unprotected    // unprotected
            << cbor_data_payload        // payload
            << cbor_data_tag            // tag
            << new cbor_array ();       // recipients

    cbor_array* recipients = (cbor_array*) (*root)[4];
    {
        cbor_array* recipient = new cbor_array ();

        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose.build_protected (&cbor_data_recipient_protected);
        }

        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_item_t item1;
            cose_item_t item2;
            cose_list_t list_unprotected;
            variant_set_int16 (item1.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item1.value, cose_alg_t::cose_direct);
            list_unprotected.push_back (item1);
            variant_set_int16 (item2.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item2.value, "our-secret", 10);
            list_unprotected.push_back (item2);
            cose.build_unprotected (&cbor_data_recipient_unprotected, list_unprotected);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        cose.build_base16str (&cbor_data_recipient_ciphertext, "");

        *recipient  << cbor_data_recipient_protected    // protected
                    << cbor_data_recipient_unprotected  // unprotected
                    << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }

    test_generated_cbor (root, "rfc8152_c_5_1.cbor", "RFC 8152 C.5.1.  Shared Secret Direct MAC");

    root->release ();
}

void test_rfc8152_c_5_2 ()
{
    _test_case.begin ("RFC 8152 C.5");

    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_mac);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_hmac_256_256);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose.build_unprotected (&cbor_data_unprotected);
    }

    cbor_data* cbor_data_payload = nullptr;
    cose.build_payload (&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_tag = nullptr;
    cose.build_base16str (&cbor_data_tag, "81a03448acd3d305376eaa11fb3fe416a955be2cbe7ec96f012c994bc3f16a41");

    *root   << cbor_data_protected      // protected
            << cbor_data_unprotected    // unprotected
            << cbor_data_payload        // payload
            << cbor_data_tag            // tag
            << new cbor_array ();       // recipients

    cbor_array* recipients = (cbor_array*) (*root)[4];
    {
        cbor_array* recipient = new cbor_array ();

        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_ecdh_ss_hkdf_256);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_recipient_protected, list_protected);
        }

        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_item_t item1;
            cose_item_t item2;
            cose_item_t item3;
            cose_list_t list_protected;
            variant_set_int16 (item1.key, cose_alg_param_t::cose_static_key_id);
            variant_set_bstr_new (item1.value, "peregrin.took@tuckborough.example", 33);
            list_protected.push_back (item1);
            variant_set_int16 (item2.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item2.value, "meriadoc.brandybuck@buckland.example", 36);
            list_protected.push_back (item2);
            variant_set_int16 (item3.key, cose_alg_param_t::cose_partyu_nonce);
            binary_t b16;
            b16 = base16_decode ("4d8553e7e74f3c6a3a9dd3ef286a8195cbf8a23d19558ccfec7d34b824f42d92bd06bd2c7f0271f0214e141fb779ae2856abf585a58368b017e7f2a9e5ce4db5");
            variant_set_bstr_new (item3.value, &b16[0], b16.size ());
            list_protected.push_back (item3);
            cose.build_unprotected (&cbor_data_recipient_unprotected, list_protected);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        cose.build_base16str (&cbor_data_recipient_ciphertext, "");

        *recipient  << cbor_data_recipient_protected    // protected
                    << cbor_data_recipient_unprotected  // unprotected
                    << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }

    test_generated_cbor (root, "rfc8152_c_5_2.cbor", "RFC 8152 C.5.2.  ECDH Direct MAC");

    root->release ();
}

void test_rfc8152_c_5_3 ()
{
    _test_case.begin ("RFC 8152 C.5");

    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_mac);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_aes_cbc_mac_128_64);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose.build_unprotected (&cbor_data_unprotected);
    }

    cbor_data* cbor_data_payload = nullptr;
    cose.build_payload (&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_tag = nullptr;
    cose.build_base16str (&cbor_data_tag, "36f5afaf0bab5d43");

    *root   << cbor_data_protected      // protected
            << cbor_data_unprotected    // unprotected
            << cbor_data_payload        // payload
            << cbor_data_tag            // tag
            << new cbor_array ();       // recipients

    cbor_array* recipients = (cbor_array*) (*root)[4];
    {
        cbor_array* recipient = new cbor_array ();

        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose.build_protected (&cbor_data_recipient_protected);
        }

        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_item_t item1;
            cose_item_t item2;
            cose_list_t list_protected;
            variant_set_int16 (item1.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item1.value, cose_alg_t::cose_a256kw);
            list_protected.push_back (item1);
            variant_set_int16 (item2.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item2.value, "018c0ae5-4d9b-471b-bfd6-eef314bc7037", 36);
            list_protected.push_back (item2);
            cose.build_unprotected (&cbor_data_recipient_unprotected, list_protected);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        cose.build_base16str (&cbor_data_recipient_ciphertext, "711ab0dc2fc4585dce27effa6781c8093eba906f227b6eb0");

        *recipient  << cbor_data_recipient_protected    // protected
                    << cbor_data_recipient_unprotected  // unprotected
                    << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }

    test_generated_cbor (root, "rfc8152_c_5_3.cbor", "RFC 8152 C.5.3.  Wrapped MAC");

    root->release ();
}

void test_rfc8152_c_5_4 ()
{
    _test_case.begin ("RFC 8152 C.5");

    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_mac);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_hmac_256_256);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    cbor_map* cbor_data_unprotected = nullptr;
    {
        cose.build_unprotected (&cbor_data_unprotected);
    }

    cbor_data* cbor_data_payload = nullptr;
    cose.build_payload (&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_tag = nullptr;
    cose.build_base16str (&cbor_data_tag, "bf48235e809b5c42e995f2b7d5fa13620e7ed834e337f6aa43df161e49e9323e");

    *root   << cbor_data_protected      // protected
            << cbor_data_unprotected    // unprotected
            << cbor_data_payload        // payload
            << cbor_data_tag            // tag
            << new cbor_array ();       // recipients

    cbor_array* recipients = (cbor_array*) (*root)[4];
    {
        cbor_array* recipient = new cbor_array ();

        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose_item_t item;
            cose_list_t list_protected;
            variant_set_int16 (item.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item.value, cose_alg_t::cose_ecdh_es_a128kw);
            list_protected.push_back (item);
            cose.build_protected (&cbor_data_recipient_protected, list_protected);
        }

        cbor_map* cbor_data_recipient_unprotected = new cbor_map ();
        {
            constexpr char constexpr_x[] = "0043b12669acac3fd27898ffba0bcd2e6c366d53bc4db71f909a759304acfb5e18cdc7ba0b13ff8c7636271a6924b1ac63c02688075b55ef2d613574e7dc242f79c3";
            constexpr char constexpr_kid[] = "bilbo.baggins@hobbiton.example";
            cbor_map* ephemeral = new cbor_map ();
            *ephemeral
                << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_ec2))       // kty
                << new cbor_pair (cose_key_lable_t::cose_ec_crv, new cbor_data (cose_ec_curve_t::cose_ec_p521))     // crv
                << new cbor_pair (cose_key_lable_t::cose_ec_x, new cbor_data (base16_decode (constexpr_x)))         // x
                << new cbor_pair (cose_key_lable_t::cose_ec_y, new cbor_data (true));                               // y

            *cbor_data_recipient_unprotected
                << new cbor_pair (cose_alg_param_t::cose_ephemeral_key, ephemeral)                              // epk
                << new cbor_pair (cose_header_t::cose_header_kid, new cbor_data (convert (constexpr_kid)));     // kid
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        cose.build_base16str (&cbor_data_recipient_ciphertext, "339bc4f79984cdc6b3e6ce5f315a4c7d2b0ac466fcea69e8c07dfbca5bb1f661bc5f8e0df9e3eff5");

        *recipient  << cbor_data_recipient_protected    // protected
                    << cbor_data_recipient_unprotected  // unprotected
                    << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }
    {
        cbor_array* recipient = new cbor_array ();

        cbor_data* cbor_data_recipient_protected = nullptr;
        {
            cose.build_protected (&cbor_data_recipient_protected);
        }

        cbor_map* cbor_data_recipient_unprotected = nullptr;
        {
            cose_item_t item1;
            cose_item_t item2;
            cose_list_t list_protected;
            variant_set_int16 (item1.key, cose_header_t::cose_header_alg);
            variant_set_int16 (item1.value, cose_alg_t::cose_a256kw);
            list_protected.push_back (item1);
            variant_set_int16 (item2.key, cose_header_t::cose_header_kid);
            variant_set_bstr_new (item2.value, "018c0ae5-4d9b-471b-bfd6-eef314bc7037", 36);
            list_protected.push_back (item2);
            cose.build_unprotected (&cbor_data_recipient_unprotected, list_protected);
        }

        cbor_data* cbor_data_recipient_ciphertext = nullptr;
        cose.build_base16str (&cbor_data_recipient_ciphertext, "0b2c7cfce04e98276342d6476a7723c090dfdd15f9a518e7736549e998370695e6d6a83b4ae507bb");

        *recipient  << cbor_data_recipient_protected    // protected
                    << cbor_data_recipient_unprotected  // unprotected
                    << cbor_data_recipient_ciphertext;  // ciphertext

        *recipients << recipient;
    }

    test_generated_cbor (root, "rfc8152_c_5_4.cbor", "RFC 8152 C.5.4.  Multi-Recipient MACed Message");

    root->release ();
}

void test_rfc8152_c_6_1 ()
{
    _test_case.begin ("RFC 8152 C.6");
    // C.6.1.  Shared Secret Direct MAC
    cbor_publisher publisher;

    cbor_object_signing_encryption cose;

    cbor_array* root = new cbor_array ();
    root->tag (true, cbor_tag_t::cose_tag_mac0);

    cbor_data* cbor_data_protected = nullptr;
    {
        cose_item_t item;
        cose_list_t list_protected;
        variant_set_int16 (item.key, cose_header_t::cose_header_alg);
        variant_set_int16 (item.value, cose_alg_t::cose_aes_cbc_mac_256_64);
        list_protected.push_back (item);
        cose.build_protected (&cbor_data_protected, list_protected);
    }

    cbor_data* cbor_data_payload = nullptr;
    cose.build_payload (&cbor_data_payload, "This is the content.");

    cbor_data* cbor_data_tag = nullptr;
    cose.build_base16str (&cbor_data_tag, "726043745027214f");

    *root   << cbor_data_protected  // protected
            << new cbor_map ()      // unprotected
            << cbor_data_payload    // payload
            << cbor_data_tag;       // tag

    test_generated_cbor (root, "rfc8152_c_6_1.cbor", "RFC 8152 C.6.1.  Shared Secret Direct MAC");

    root->release ();
}

return_t BIO_to_string (BIO* bio, std::string& data)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        data.clear ();

        if (nullptr == bio) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::vector<char> buf;
        char temp[16];
        int l = 0;
        while (1) {
            l = BIO_read (bio, temp, sizeof (temp));
            if (0 >= l) {
                break;
            }
            buf.insert (buf.end (), temp, temp + l);
        }
        data.append (&buf[0], buf.size ());
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t EVP_PKEY_public_to_string (EVP_PKEY* pkey, std::string& data, int indent)
{
    return_t ret = errorcode_t::success;
    BIO* bio = nullptr;

    __try2
    {
        data.clear ();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bio = BIO_new (BIO_s_mem ());
        EVP_PKEY_print_public (bio, pkey, indent, nullptr);

        BIO_to_string (bio, data);
    }
    __finally2
    {
        if (nullptr != bio) {
            BIO_free (bio);
        }
    }

    return ret;
}

void dump_crypto_key (crypto_key_object_t* key, void*)
{
    uint32 nid = 0;
    std::string temp;

    nidof_evp_pkey (key->pkey, nid);
    printf ("nid %i kid %s alg %s use %i\n", nid, key->kid.c_str (), key->alg.c_str (), key->use);
    EVP_PKEY_public_to_string (key->pkey, temp, 0);
    printf ("%s\n", temp.c_str ());
}

void test_rfc8152_c_7_1 ()
{
    _test_case.begin ("RFC 8152 C.7");

    cbor_array* root = new cbor_array ();
    {
        cbor_map* key = new cbor_map ();

        *key
            << new cbor_pair (cose_key_lable_t::cose_ec_crv, new cbor_data (cose_ec_curve_t::cose_ec_p256))
            << new cbor_pair (cose_key_lable_t::cose_ec_x, new cbor_data (base16_decode ("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")))
            << new cbor_pair (cose_key_lable_t::cose_ec_y, new cbor_data (base16_decode ("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")))
            << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_ec2))
            << new cbor_pair (cose_key_lable_t::cose_lable_kid, new cbor_data (convert ("meriadoc.brandybuck@buckland.example")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map ();

        *key
            << new cbor_pair (cose_key_lable_t::cose_ec_crv, new cbor_data (cose_ec_curve_t::cose_ec_p256))
            << new cbor_pair (cose_key_lable_t::cose_ec_x, new cbor_data (base16_decode ("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff")))
            << new cbor_pair (cose_key_lable_t::cose_ec_y, new cbor_data (base16_decode ("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")))
            << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_ec2))
            << new cbor_pair (cose_key_lable_t::cose_lable_kid, new cbor_data (convert ("11")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map ();

        *key
            << new cbor_pair (cose_key_lable_t::cose_ec_crv, new cbor_data (cose_ec_curve_t::cose_ec_p521))
            << new cbor_pair (cose_key_lable_t::cose_ec_x, new cbor_data (base16_decode ("0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad")))
            << new cbor_pair (cose_key_lable_t::cose_ec_y, new cbor_data (base16_decode ("01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475")))
            << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_ec2))
            << new cbor_pair (cose_key_lable_t::cose_lable_kid, new cbor_data (convert ("bilbo.baggins@hobbiton.example")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map ();

        *key
            << new cbor_pair (cose_key_lable_t::cose_ec_crv, new cbor_data (cose_ec_curve_t::cose_ec_p256))
            << new cbor_pair (cose_key_lable_t::cose_ec_x, new cbor_data (base16_decode ("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")))
            << new cbor_pair (cose_key_lable_t::cose_ec_y, new cbor_data (base16_decode ("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb")))
            << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_ec2))
            << new cbor_pair (cose_key_lable_t::cose_lable_kid, new cbor_data (convert ("peregrin.took@tuckborough.example")));

        *root << key;
    }

    test_generated_cbor (root, "rfc8152_c_7_1.cbor", "RFC 8152 C.7.1.  Public Keys");

    root->release ();
}

void test_rfc8152_c_7_2 ()
{
    _test_case.begin ("RFC 8152 C.7");

    cbor_array* root = new cbor_array ();
    {
        cbor_map* key = new cbor_map ();

        *key
            << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_ec2))
            << new cbor_pair (cose_key_lable_t::cose_lable_kid, new cbor_data (convert ("meriadoc.brandybuck@buckland.example")))
            << new cbor_pair (cose_key_lable_t::cose_ec_crv, new cbor_data (cose_ec_curve_t::cose_ec_p256))
            << new cbor_pair (cose_key_lable_t::cose_ec_x, new cbor_data (base16_decode ("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")))
            << new cbor_pair (cose_key_lable_t::cose_ec_y, new cbor_data (base16_decode ("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")))
            << new cbor_pair (cose_key_lable_t::cose_ec_d, new cbor_data (base16_decode ("aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map ();

        *key
            << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_ec2))
            << new cbor_pair (cose_key_lable_t::cose_lable_kid, new cbor_data (convert ("11")))
            << new cbor_pair (cose_key_lable_t::cose_ec_crv, new cbor_data (cose_ec_curve_t::cose_ec_p256))
            << new cbor_pair (cose_key_lable_t::cose_ec_x, new cbor_data (base16_decode ("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff")))
            << new cbor_pair (cose_key_lable_t::cose_ec_y, new cbor_data (base16_decode ("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")))
            << new cbor_pair (cose_key_lable_t::cose_ec_d, new cbor_data (base16_decode ("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map ();

        *key
            << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_ec2))
            << new cbor_pair (cose_key_lable_t::cose_lable_kid, new cbor_data (convert ("bilbo.baggins@hobbiton.example")))
            << new cbor_pair (cose_key_lable_t::cose_ec_crv, new cbor_data (cose_ec_curve_t::cose_ec_p521))
            << new cbor_pair (cose_key_lable_t::cose_ec_x, new cbor_data (base16_decode ("0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad")))
            << new cbor_pair (cose_key_lable_t::cose_ec_y, new cbor_data (base16_decode ("01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475")))
            << new cbor_pair (cose_key_lable_t::cose_ec_d, new cbor_data (base16_decode ("00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map ();

        *key
            << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_symm))
            << new cbor_pair (cose_key_lable_t::cose_lable_kid, new cbor_data (convert ("our-secret")))
            << new cbor_pair (cose_key_lable_t::cose_symm_k, new cbor_data (base16_decode ("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map ();

        *key
            << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_ec2))
            << new cbor_pair (cose_key_lable_t::cose_ec_crv, new cbor_data (cose_ec_curve_t::cose_ec_p256))
            << new cbor_pair (cose_key_lable_t::cose_lable_kid, new cbor_data (convert ("peregrin.took@tuckborough.example")))
            << new cbor_pair (cose_key_lable_t::cose_ec_x, new cbor_data (base16_decode ("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280")))
            << new cbor_pair (cose_key_lable_t::cose_ec_y, new cbor_data (base16_decode ("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb")))
            << new cbor_pair (cose_key_lable_t::cose_ec_d, new cbor_data (base16_decode ("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map ();

        *key
            << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_symm))
            << new cbor_pair (cose_key_lable_t::cose_lable_kid, new cbor_data (convert ("our-secret2")))
            << new cbor_pair (cose_key_lable_t::cose_symm_k, new cbor_data (base16_decode ("849b5786457c1491be3a76dcea6c4271")));

        *root << key;
    }
    {
        cbor_map* key = new cbor_map ();

        *key
            << new cbor_pair (cose_key_lable_t::cose_lable_kty, new cbor_data (cose_key_t::cose_key_symm))
            << new cbor_pair (cose_key_lable_t::cose_lable_kid, new cbor_data (convert ("018c0ae5-4d9b-471b-bfd6-eef314bc7037")))
            << new cbor_pair (cose_key_lable_t::cose_symm_k, new cbor_data (base16_decode ("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188")));

        *root << key;
    }

    test_generated_cbor (root, "rfc8152_c_7_2.cbor", "RFC 8152 C.7.2.  Private Keys");

    root->release ();
}

void test_rfc_examples ()
{
    test_cbor_file ("rfc8152_b.cbor", "RFC 8152 Appendix B.  Two Layers of Recipient Information");
    test_cbor_file ("rfc8152_c_1_1.cbor", "RFC 8152 C.1.1.  Single Signature");
    test_cbor_file ("rfc8152_c_1_2.cbor", "RFC 8152 C.1.2.  Multiple Signers");
    test_cbor_file ("rfc8152_c_1_3.cbor", "RFC 8152 C.1.3.  Counter Signature");
    test_cbor_file ("rfc8152_c_1_4.cbor", "RFC 8152 C.1.4.  Signature with Criticality");
    test_cbor_file ("rfc8152_c_2_1.cbor", "RFC 8152 C.2.1.  Single ECDSA Signature");
    test_cbor_file ("rfc8152_c_3_1.cbor", "RFC 8152 C.3.1.  Direct ECDH");
    test_cbor_file ("rfc8152_c_3_2.cbor", "RFC 8152 C.3.2.  Direct Plus Key Derivation");
    test_cbor_file ("rfc8152_c_3_3.cbor", "RFC 8152 C.3.3.  Counter Signature on Encrypted Content");
    test_cbor_file ("rfc8152_c_3_4.cbor", "RFC 8152 C.3.4.  Encrypted Content with External Data");
    test_cbor_file ("rfc8152_c_4_1.cbor", "RFC 8152 C.4.1.  Simple Encrypted Message");
    test_cbor_file ("rfc8152_c_4_2.cbor", "RFC 8152 C.4.2.  Encrypted Message with a Partial IV");
    test_cbor_file ("rfc8152_c_5_1.cbor", "RFC 8152 C.5.1.  Shared Secret Direct MAC");
    test_cbor_file ("rfc8152_c_5_2.cbor", "RFC 8152 C.5.2.  ECDH Direct MAC");
    test_cbor_file ("rfc8152_c_5_3.cbor", "RFC 8152 C.5.3.  Wrapped MAC");
    test_cbor_file ("rfc8152_c_5_4.cbor", "RFC 8152 C.5.4.  Multi-Recipient MACed Message");
    test_cbor_file ("rfc8152_c_6_1.cbor", "RFC 8152 C.6.1.  Shared Secret Direct MAC");
    test_cbor_file ("rfc8152_c_7_1.cbor", "RFC 8152 C.7.1.  Public Keys");
    test_cbor_file ("rfc8152_c_7_2.cbor", "RFC 8152 C.7.2.  Private Keys");
    test_cbor_file ("rfc8778_a_1.cbor", "RFC 8778 A.1.  Example COSE Full Message Signature");
    test_cbor_file ("rfc8778_a_2.cbor", "RFC 8778 A.2.  Example COSE_Sign1 Message");
    test_cbor_file ("rfc9338_a_1_1.cbor", "RFC 9338 A.1.1.  Countersignature");
    test_cbor_file ("rfc9338_a_2_1.cbor", "RFC 9338 A.2.1.  Countersignature");
    test_cbor_file ("rfc9338_a_3_1.cbor", "RFC 9338 A.3.1.  Countersignature on Encrypted Content");
    test_cbor_file ("rfc9338_a_4_1.cbor", "RFC 9338 A.4.1.  Countersignature on Encrypted Content");
    test_cbor_file ("rfc9338_a_5_1.cbor", "RFC 9338 A.5.1.  Countersignature on MAC Content");
    test_cbor_file ("rfc9338_a_6_1.cbor", "RFC 9338 A.6.1.  Countersignature on MAC0 Content"); // typo ? not 159 bytes, but 139 bytes
}

void test_cbor_key (const char* file, const char* text)
{
    _test_case.begin ("CBOR encoded keys - order not guaranteed");
    return_t ret = errorcode_t::success;
    crypto_key key;
    cbor_web_key cwk;

    binary_t cbor;
    file_stream fs;

    ret = fs.open (file);
    if (errorcode_t::success == ret) {
        fs.begin_mmap ();

        byte_t* file_contents = fs.data ();
        size_t file_size = fs.size ();
        cbor.insert (cbor.end (), file_contents, file_contents + file_size);

        ret = cwk.load (&key, cbor);
        key.for_each (dump_crypto_key, nullptr);
        _test_case.test (ret, __FUNCTION__, "step.load %s", text ? text : "");

        binary_t cbor_written;
        ret = cwk.write (&key, cbor_written);
        _test_case.test (ret, __FUNCTION__, "step.write %s", text ? text : "");

        if (1) {
            test_case_notimecheck notimecheck (_test_case);

            buffer_stream bs;
            dump_memory (cbor, &bs, 32);
            std::cout << "from file" << std::endl << bs.c_str () << std::endl;
            dump_memory (cbor_written, &bs, 32);
            std::cout << "from cwk" << std::endl << bs.c_str () << std::endl;

            buffer_stream diagnostic;
            cbor_reader reader;
            cbor_reader_context_t* handle = nullptr;

            reader.open (&handle);
            reader.parse (handle, cbor);
            reader.publish (handle, &diagnostic);
            std::cout << "from file" << std::endl << diagnostic.c_str () << std::endl;

            reader.parse (handle, cbor_written);
            reader.publish (handle, &diagnostic);
            std::cout << "from cwk" << std::endl << diagnostic.c_str () << std::endl;

            reader.close (handle);
        }
    }
    _test_case.test (ret, __FUNCTION__, text ? text : "");
}

void test_cbor_web_key ()
{
    test_cbor_key ("rfc8152_c_7_1.cbor", "RFC 8152 C.7.1.  Public Keys");
    test_cbor_key ("rfc8152_c_7_2.cbor", "RFC 8152 C.7.2.  Private Keys");
}


void try_refactor_jose_sign ()
{
    _test_case.begin ("crypto_key");

    // load keys from CBOR
    cbor_web_key cwk;
    crypto_key pubkey;
    cwk.load_file (&pubkey, "rfc8152_c_7_1.cbor");
    crypto_key privkey;
    cwk.load_file (&privkey, "rfc8152_c_7_2.cbor");

    // dump keys JWK formatted
    json_web_key jwk;
    size_t size = 0;
    buffer_stream json;
    jwk.write (&privkey, &json, 1);
    printf ("JWK from CBOR key\n%s\n", json.c_str ());

    // JWS
    constexpr char contents[] = "This is the content.";
    std::string jws;

    jose_context_t* handle = nullptr;
    json_object_signing_encryption jose;

    jose.open (&handle, &privkey);
    jose.sign (handle, jws_t::jws_es512, contents, jws, jose_serialization_t::jose_json);
    jose.close (handle);

    bool result = false;
    jose.open (&handle, &pubkey);
    jose.verify (handle, jws, result);
    jose.close (handle);

    std::cout << "contents" << std::endl << contents << std::endl;
    std::cout << "jws" << std::endl << jws.c_str () << std::endl;

    // refactoring
    return_t ret = errorcode_t::success;
    openssl_sign sign;
    binary_t signature;
    buffer_stream bs;
    crypt_sig_t sig = crypt_sig_t::sig_es512;
    EVP_PKEY* pkey = privkey.select (sig);
    sign.sign (pkey, convert (contents), signature, sig);
    dump_memory (signature, &bs);
    std::cout << "signature" << std::endl << bs.c_str () << std::endl;
    ret = sign.verify (pkey, convert (contents), signature, sig);
    _test_case.test (ret, __FUNCTION__, "signing");

    // cose formatting
    // ...
    // interface design
}

int main ()
{
    set_trace_option (trace_option_t::trace_bt | trace_option_t::trace_except);

    openssl_startup ();
    openssl_thread_setup ();

    // check format
    // install
    //      pacman -S rubygems (MINGW)
    //      yum install rubygems (RHEL)
    //      gem install cbor-diag
    // diag2cbor.rb < inputfile > outputfile
    // compare
    //      cat outputfile | xxd
    //      xxd -ps outputfile

    // interface design
    // what kind of member methods required ?
    // need more simple ones
    // and then refactor JOSE

    // part 1 .. following cases
    // cbor_array* to CBOR and diagnostic
    // Test Vector comparison
    // cbor_array* from CBOR
    test_rfc8152_c_1_1 ();
    test_rfc8152_c_1_2 ();
    test_rfc8152_c_1_3 ();
    test_rfc8152_c_1_4 ();
    test_rfc8152_c_2_1 ();
    test_rfc8152_c_3_1 ();
    test_rfc8152_c_3_2 ();
    test_rfc8152_c_3_3 ();
    test_rfc8152_c_3_4 ();
    test_rfc8152_c_4_1 ();
    test_rfc8152_c_4_2 ();
    test_rfc8152_c_5_1 ();
    test_rfc8152_c_5_2 ();
    test_rfc8152_c_5_3 ();
    test_rfc8152_c_5_4 ();
    test_rfc8152_c_6_1 ();
    test_rfc8152_c_7_1 ();
    test_rfc8152_c_7_2 ();
    // part 2 .. parse
    test_rfc_examples ();

    // part 3 .. load keys from cbor and write to CBOR
    // step.1 parse CBOR and load EVP_PKEY
    // step.2 write EVP_PKEY to CBOR

    test_cbor_web_key ();
    try_refactor_jose_sign ();

    openssl_thread_cleanup ();
    openssl_cleanup ();

    _test_case.report (5);
    return _test_case.result ();
}
