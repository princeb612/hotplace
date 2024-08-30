
* Revision 595
  * [changed] substitute cmdline_t with t_cmdline_t
  * [changed] substitute cmdarg_t with t_cmdarg_t
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

* Revision 589
  * [added] udp_server_socket
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
    * substitute std::equal with operator ==
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
    * substitute std::multimap<size_t, unsigned> with std::multimap<range_t, unsigned>

* Revision 568
  * [added] print_pair
  * [added] empty, occupied (stream_t, bufferio, basic_stream, ansi_string, wide_string, file_stream)
  * [added] basic_stream operator ==
  * [added] parser::context::wsearch
  * [changed] substitute t_kmp_pattern with t_kmp
  * [changed] substitute t_kmp::match with t_kmp::search
  * [changed] t_aho_corasick_wildcard support wildcard single ?

* Revision 567
  * [added] datetime::gettime, datetime::gmtime_to_timespec, timespan_m, timespan_s

* Revision 565
  * [added] double_from_fp16
  * [changed] substitute fp16_from_fp32 with fp16_from_float
  * [changed] substitute fp32_from_fp16 with float_from_fp16
  * [changed] substitute fp16_ieee_from_fp32_value with fp16_from_fp32
  * [changed] substitute is_typeof with ieee754_typeof

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
  * [changed] substitute convert with tostring/tobin

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
  * [changed] substitute uint24_32 with i32_b24
  * [changed] substitute uint32_24 with i32_b24

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
