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

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

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
    const OPTION option = _cmdline->value();  // (*_cmdline).value () is ok
    if (option.dump_keys) {
        uint32 nid = 0;

        nidof_evp_pkey(key->get_pkey(), nid);
        _logger->writeln("\e[1;32mnid %i kid \"%s\" alg %s use %i\e[0m", nid, key->get_desc().get_kid_cstr(), key->get_desc().get_alg_cstr(),
                         key->get_desc().get_use());

        basic_stream bs;
        dump_key(key->get_pkey(), &bs);
        _logger->writeln("%s", bs.c_str());
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.enable_verbose(); }).optional()
#if defined DEBUG
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.enable_debug(); }).optional()
                << t_cmdarg_t<OPTION>("-D", "trace level 0|2", [](OPTION& o, char* param) -> void { o.enable_trace(atoi(param)); }).optional().preced()
                << t_cmdarg_t<OPTION>("--trace", "trace level [trace]", [](OPTION& o, char* param) -> void { o.enable_trace(loglevel_trace); }).optional()
                << t_cmdarg_t<OPTION>("--debug", "trace level [debug]", [](OPTION& o, char* param) -> void { o.enable_trace(loglevel_debug); }).optional()
#endif
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("-k", "dump keys", [](OPTION& o, char* param) -> void { o.dump_keys = true; }).optional()
                << t_cmdarg_t<OPTION>("-u", "dump diagnostic", [](OPTION& o, char* param) -> void { o.dump_diagnostic = true; }).optional()
                << t_cmdarg_t<OPTION>("-b", "skip basic encoding", [](OPTION& o, char* param) -> void { o.skip_cbor_basic = true; }).optional()
                << t_cmdarg_t<OPTION>("-s", "skip validation w/ test vector", [](OPTION& o, char* param) -> void { o.skip_validate = true; }).optional()
                << t_cmdarg_t<OPTION>("-g", "skip self-generated message", [](OPTION& o, char* param) -> void { o.skip_gen = true; }).optional();
    (*_cmdline).parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log").attach(&_test_case);
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());
    _logger->setcolor(bold, cyan);

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
        set_trace_level(option.trace_level);
    }

    _logger->writeln("option.verbose %i", option.verbose ? 1 : 0);
    _logger->writeln("option.dump_keys %i", option.dump_keys ? 1 : 0);
    _logger->writeln("option.skip_validate %i", option.skip_validate ? 1 : 0);
    _logger->writeln("option.skip_gen %i", option.skip_gen ? 1 : 0);

    openssl_startup();

    test_validate_resource();

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
    if (false == option.skip_cbor_basic) {
        test_rfc8152_read_cbor();
    }

    // part 1 .. following cases
    // encode and decode
    // Test Vector comparison
    {
        cbor_web_key cwk;
        cwk.load_file(&rfc8152_privkeys, key_ownspec, "rfc8152_c_7_2.cbor");
        cwk.load_file(&rfc8152_pubkeys, key_ownspec, "rfc8152_c_7_1.cbor");

        // RFC8152/Appendix_C_4_1.json
        cwk.add_oct_b64u(&rfc8152_privkeys_c4, "hJtXhkV8FJG-Onbc6mxCcY", keydesc("our-secret2", crypto_use_t::use_enc));

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
    if (false == option.skip_validate) {
        test_github_example();
    }

    // part 4 encrypt/sign/mac
    if (false == option.skip_gen) {
        crypto_key key;
        test_keygen(&key);
        test_selfgen(&key);
        test_cose(&key);
    }

    // part 5 CWT
    test_cwt_rfc8392();

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
