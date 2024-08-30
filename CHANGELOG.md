# history

* Revision 595
  * [changed] rename cmdline_t to t_cmdline_t
  * [changed] rename cmdarg_t to t_cmdarg_t
  * [changed] rename tls_server_socket::listen to tls_server_socket::open
  * [changed] network_server::open prototype changed

* Revision 594
  * [changed] semaphore::signal, semaphore::wait return return_t
  * [changed] thread::join to thread::wait
  * [changed] signalwait_threads::join
  * [changed] logger::consumer
  * [changed] replace the expired self-certificate (server.crt and server.key)
  * [deprecated] signalwait_threads::signal

* Revision 593
  * [added] crypto_advisor::cipher_for_each
  * [added] crypto_advisor::md_for_each
  * [added] crypto_advisor::cose_for_each
  * [added] crypto_advisor::curve_for_each
  * [added] crypto_advisor::query_feature
  * [added] crypto_advisor::at_least_openssl_version

* Revision 590
  * [changed] multiplexer_epoll

* Revision 589
  * [added] udp_server_socket based on IOCP
  * [changed] linux get_errno, get_eai_error integrated into get_lasterror

* Revision 588
  * [changed] close_socket
  * [changed] rename set_ttl, get_ttl to set_wto, get_wto (wait-time-out, see tcp_client_socket, http_client)
  * [changed] x509_open_simple, x509cert_open, x509cert prototype changed (see x509cert_flag_tls, x509cert_flag_dtls)

* Revision 585
  * [changed] x509cert_open check errorcode_t::expired

* Revision 584
  * [changed] thread::join prototype changed
  * [changed] authenticode_verifier::verify
    * rename std::equal to operator ==
    * std::equal (a.begin(), a.end(), empty.begin()) stack overflow
  * [changed] crypto_advisor::hintof_digest
    * lower case digest algorithm
  * [changed] file_stream::open (windows)

* Revision 578
  * [changed] t_aho_corasick_wildcard support wildcard any *

* Revision 574
  * [added] range_t
  * [added] find_lessthan_or_equal
  * [changed] parser::psearch, parser::context::psearch changed return type
    * rename std::multimap<size_t, unsigned> to std::multimap<range_t, unsigned>

* Revision 568
  * [added] print_pair
  * [added] empty, occupied (stream_t, bufferio, basic_stream, ansi_string, wide_string, file_stream)
  * [added] basic_stream operator ==
  * [added] parser::context::wsearch
  * [changed] rename t_kmp_pattern to t_kmp
  * [changed] rename t_kmp::match to t_kmp::search
  * [changed] t_aho_corasick_wildcard support wildcard single ?

* Revision 567
  * [added] datetime::gettime, datetime::gmtime_to_timespec, timespan_m, timespan_s

* Revision 565
  * [added] double_from_fp16
  * [changed] rename fp16_from_fp32 to fp16_from_float
  * [changed] rename fp32_from_fp16 to float_from_fp16
  * [changed] rename fp16_ieee_from_fp32_value to fp16_from_fp32
  * [changed] rename is_typeof to ieee754_typeof

* Revision 561
  * [added] t_trie::find, t_trie::rfind

* Revision 560
  * [added] t_trie::lookup
  * [added] parser::compare

* Revision 558
  * [added] t_merge_ovl_intervals

* Revision 554
  * [added] t_wildcards

* Revision 553
  * [added] t_ukkonen

* Revision 551
  * [added] t_suffixtree

* Revision 550
  * [added] t_trie

* Revision 548
  * [added] t_aho_corasick
  * [added] variant::set_datetime, variant::operator =, variant::to_str, variant::to_hex, variant::to_bin

* Revision 545
  * [added] oid_t, str_to_oid, oid_to_str

* Revision 543
  * [added] bit_length, byte_capacity, byte_capacity_signed

* Revision 541
  * [changed] t_graph::graph_dijkstra alternative paths

* Revision 540
  * [added] RTL_FIELD_TYPE

* Revision 539
  * [added] ieee754_typeof_t is_typeof

* Revision 536
  * [added] parser

* Revision 535
  * [changed] rename convert to tostring/tobin

* Revision 534
  * [added] void test_case::attach(logger* log)

* Revision 531
  * [added] binary_push, binary_append

* Revision 528
  * [added] for_each_const

* Revision 526
  * [changed] const T& cmdline_t::option() const

* Revision 524
  * [added] logger

* Revision 523
  * [changed] HTTP/2
  * [changed] network_stream changed

* Revision 522
  * [changed] network_session changed

* Revision 516
  * [changed] hpack_session implementation changed

* Revision 514
  * [added] enable_alpn_h2

* Revision 510
  * [added] hpack_encoder

* Revision 508
  * [added] http_server_builder, hpack_session

* Revision 506
  * [changed] HPACK

* Revision 504
  * [added] huffman_coding

* Revision 499
  * [changed] rename uint24_32 to i32_b24
  * [changed] rename uint32_24 to i32_b24

* Revision 498
  * [added] uint32_24_t, payload

* Revision 495
  * [changed] network_stream implementation changed

* Revision 492
  * [deprecated] network_priority_queue

* Revision 490
  * [added] server_conf

* Revision 486
  * [changed] OAuth 2.0 (RFC 6749)

* Revision 483
  * [changed] constexpr_obf

* Revision 481
  * [added] http_server::get_ipaddr_acl
  * [changed] http_authentication_resolver::get_basic_credentials, http_authentication_resolver::get_digest_credentials, http_authentication_resolver::get_bearer_credentials

* Revision 479
  * [added] Authorization Code Grant (RFC 6749 4.1)

* Revision 476
  * [added] error_advisor

* Revision 472
  * [added] RS1

* Revision 469
  * [added] network_protocol::set_constraints, network_protocol::get_constraints

* Revision 466
  * [changed] html_documents

* Revision 465
  * [added] x509cert

* Revision 455
  * [changed] http_digest_access_authenticate_provider (RFC 7616, userhash)

* Revision 454
  * [changed] http_basic_authenticate_provider (RFC 2617)

* Revision 452
  * [added] rfc2617_digest

* Revision 449
  * [changed] http_protocol::read_stream

* Revision 445
  * [added] http_resource

* Revision 443
  * [added] critical_section_guard

* Revision 442
  * [changed] COSE (valgrind tested)

* Revision 436
  * [added] crypto_key::generate_nid, crypto_key::generate_cose
  * [added] ES256K (RFC8812)

* Revision 416
  * [changed] openssl_chacha20_iv

* Revision 415
  * [changed] base16_decode_rfc

* Revision 414
  * [added] crypto_keychain::choose

* Revision 411
  * [changed] RFC 8152 Appendix B. Two Layers of Recipient Information

* Revision 400
  * [changed] openssl_kdf::hkdf_expand_aes

* Revision 399
  * [changed] preserve leading zero (JKW, CWK)

* Revision 392
  * [changed] mingw terminal delay fixed

* Revision 354
  * [added] kdf_ckdf, ckdf_extract, ckdf_expand

* Revision 353
  * [added] hkdf_extract, hkdf_expand

* Revision 348
  * [changed] COSE RSA-OAEP

* Revision 346
  * [changed] AES CCM (openssl-1.1.1)

* Revision 343
  * [changed] COSE static_key, static_keyid

* Revision 342
  * [changed] COSE ECDH-ES using OKP

* Revision 340
  * [changed] COSE AES-CCM, AES-GCM

* Revision 335
  * [changed] RFC 8152 C.3.2 C.4.1 C.4.2 decryption

* Revision 333
  * [changed] RFC 8152 C.3.1 C.3.3 decryption

* Revision 325
  * [changed] RFC 8152 4.3 Externally Supplied Data

* Revision 320
  * [added] [COSE examples](https://github.com/cose-wg/Examples)

* Revision 305
  * [added] elliptic curves B-163, K-163, P-192 

* Revision 303
  * [changed] ECDSA NIST CAVP - tested (truncated sha)

* Revision 302
  * [added] elliptic curves K-233, K-283, K-409, K-571, B-233, B-283, B-409, B-571
  * [changes] ECDSA NIST CAVP - tested

* Revision 292
  * [changed] RFC7520 5.10

* Revision 289
  * [changed] RFC7520 5.10, 5.11

* Revision 287
  * [added] JOSE deflate

* Revision 286
  * [changed] preserve leading zero (crypto_key)

* Revision 283
  * [changed] cose_sign1

* Revision 262
  * [added] kdf_argon2, kdf_argon2d, kdf_argon2i, kdf_argon2id

* Revision 257
  * [added] CMAC

* Revision 249
  * [changed] cbor_web_key

* Revision 211
  * [added] RFC 8152 examples (.cbor, .diag)

* Revision 205
  * [added] fp16_from_fp32, fp16_ieee_from_fp32_value, ieee754_format_as_small_as_possible

* Revision 164
  * [added] CCM (Block cipher mode of operation)

* Revision 125
  * [added] obfuscate_string, test_case_notimecheck

* Revision 108
  * [added] authenticode

* Revision 107
  * [added] CBOR

* Revision 106
  * [added] ODBC

* Revision 101
  * [changed] test_case::time_report

* Revision 84
  * [changed] network_session (windows fix)

* Revision 38
  * [added] HOTP, TOTP

* Revision 34
  * [changed] base64_encode

* Revision 31
  * [changed] rename hex2bin to base16

* Revision 21
  * [changed] precompiled header

* Revision 9
  * [changed] bufferio

* Revision 5
  * [added] t_shared_instance


