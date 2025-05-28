/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

// tls13/tls13.pcapng

pcap_testvector capture_tls13[] = {
    {
        from_client,
        "client_hello",
        "16 03 01 00 e7 01 00 00 e3 03 03 b9 39 8c 3a f3"
        "5d 14 01 fe 4a a6 2e a9 4b 26 43 37 f1 85 bc 84"
        "4e 1b c2 dd ed 35 86 b8 da e2 25 20 43 9a cd c3"
        "2a 47 ca 3c 67 bf d9 ae dc fa ee 66 3b 49 bc f8"
        "c7 da 1c 8e 36 ed 29 c9 d9 43 62 30 00 06 13 02"
        "13 03 13 01 01 00 00 94 00 0b 00 04 03 00 01 02"
        "00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18"
        "01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 16"
        "00 00 00 17 00 00 00 0d 00 24 00 22 04 03 05 03"
        "06 03 08 07 08 08 08 1a 08 1b 08 1c 08 09 08 0a"
        "08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b"
        "00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00"
        "24 00 1d 00 20 54 10 c0 fe 90 88 d2 f5 df 0f c5"
        "dc bf 60 75 9b 96 f5 75 f8 aa 91 14 37 5f d5 e6"
        "d7 e9 b0 94 23 00 1b 00 03 02 00 01",
    },
    {
        from_server,
        "server_hello, change_cipher_spec, encrypted_extensions, certificate, certificate_verify, finished",
        "16 03 03 00 7a 02 00 00 76 03 03 73 8a 10 e3 4d"
        "0a d3 4b 5c 0c 9b b5 6b 9b 20 f9 b6 1e 55 73 6e"
        "35 ca cb a3 14 7d ff 09 f8 5a 9a 20 43 9a cd c3"
        "2a 47 ca 3c 67 bf d9 ae dc fa ee 66 3b 49 bc f8"
        "c7 da 1c 8e 36 ed 29 c9 d9 43 62 30 13 02 00 00"
        "2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 60"
        "63 09 ac 36 97 58 a7 33 00 a4 68 13 ce 40 6f e8"
        "3c 90 a0 0c 5b 9a be a2 52 64 00 2d 79 ec 00 14"
        "03 03 00 01 01 17 03 03 00 17 a1 f9 36 57 36 ea"
        "54 b8 3b 6f b2 eb 7b 3b 6e 1a 2a e4 88 1b 24 64"
        "03 17 03 03 03 7e 39 1a 84 b4 f7 2d 0b ee 0e 47"
        "f1 9d 78 19 a5 bc 24 f8 02 51 48 1c 61 df 5d c0"
        "2d d2 76 02 1f 39 30 49 b9 66 72 67 d0 58 67 d3"
        "25 f9 20 53 1c 31 3b c2 a7 98 86 d7 20 1a f1 bf"
        "30 89 a4 d1 de f3 1d ff 91 04 2f 6e d5 f8 97 69"
        "ef 99 96 5e b7 7c 2f 9d 4c 79 2a 47 8a 75 11 65"
        "ff c8 cf cb 24 eb b8 e1 10 36 b6 ec bd f1 19 cd"
        "bb 12 c0 e2 8b 7d db 8b 03 83 19 1c 6e 24 87 38"
        "6c cb 2a 79 9b 89 f0 e2 4a 73 21 61 3d e2 45 19"
        "99 bf 46 64 60 d5 50 10 10 32 ec 3d 9b d3 4e 00"
        "0c 28 47 9a f6 d7 ca 7e 42 2b 6d 50 ca f3 56 8d"
        "5f 6a 43 3f e7 2c 81 57 7b 2a 27 db 2b 86 79 16"
        "a3 04 6a 2f 1a 6d a9 06 da 58 0a a2 c2 47 42 16"
        "e5 81 1d b2 cf fe 81 c9 d9 e0 bf 8b 11 49 86 33"
        "13 be 57 78 7c 8f 8a 3e 06 06 75 b3 bc 8f 6b 0f"
        "f6 5a 58 be 49 d4 d4 da 17 8a 89 5b c4 9c 6f c6"
        "0a c9 15 9d 87 31 0e c5 7b e3 a3 2d 13 2c d9 9c"
        "58 0b a5 1f f7 c1 ba ae b7 66 9a 90 09 11 f4 ba"
        "cc f1 84 79 e2 c7 bd 5c 9a cf 11 1d c1 7f 20 97"
        "68 7f 87 8b 63 28 af 35 60 d1 ab c2 aa f8 cb 90"
        "c3 69 7b 6f e4 c2 a9 69 e5 fb e6 9f 39 9a 8b ff"
        "07 4c ab a4 48 93 1f 63 7e 3e e8 ae 86 26 0a 36"
        "9a bd cb a6 9a 22 28 bc a3 d9 c9 16 ed e6 48 da"
        "22 50 eb 17 75 52 fc 6e 95 eb d1 a2 e4 4e e9 8e"
        "49 37 e6 81 56 53 19 ff e8 7d ac f1 fb e2 10 45"
        "37 93 6a f4 39 d0 17 ea 30 0a c2 e6 7d 60 81 ab"
        "02 32 6c aa a1 2e 7c c4 ee 24 47 40 e5 2a 64 c4"
        "f2 37 a9 9e 54 89 7a cd 74 22 6b 96 b8 e2 0d 1e"
        "93 31 83 fe 63 06 3d 20 e9 8f c7 cd 79 de 03 ca"
        "d3 37 c8 a7 f5 8b f1 aa c4 63 ef fa 2e d1 31 1b"
        "04 1b ef e1 51 40 8c c6 c7 38 c8 be 02 34 42 bf"
        "66 a2 7f 1a f7 5f c8 c9 47 90 91 9a 3f 9f 6b 1c"
        "6b e0 3c 8c ed f9 aa de bc 92 c9 26 2f f6 d3 e8"
        "0e 04 77 b2 d0 cb 10 72 4a 9e 96 00 fd 5c 04 91"
        "08 c7 05 d0 8f 00 68 35 1e 6b 46 b8 66 f0 f9 62"
        "46 59 cf a7 e2 15 7a 3c a2 47 a8 f4 8e e8 b5 90"
        "95 4a 75 8d f5 5d cb d0 7d 69 9f 0a 3c 34 a5 41"
        "8c 99 6d e4 4b 66 d9 d1 18 8d 39 f1 19 25 43 1e"
        "6e 1d a4 92 04 64 f5 03 92 2d 75 e7 58 d0 f7 83"
        "83 2e ca 39 f5 99 fc 2d 4b 7d 1b e7 f6 a0 32 ea"
        "54 03 20 16 37 b2 65 c0 b6 51 a3 a8 d4 e2 8e 3a"
        "97 83 86 4e ad 16 fe d9 45 91 79 ce 84 f6 f7 40"
        "4e 2e 61 c3 1d 04 7c 04 4e 99 d5 61 98 6a bd 17"
        "b8 2f 3a c9 e4 db 43 02 6a 28 63 cc 12 19 e0 5f"
        "18 62 31 c9 c3 93 fd e4 79 d6 f2 6c c0 fc 18 1e"
        "31 6f 1b 9d 72 f0 91 f5 b7 89 20 79 cb 0e 1d d2"
        "70 3a a5 dd bc 5a 60 a3 0d 01 4b a7 d9 68 d9 32"
        "58 6a db 0d 67 6f 9a 54 5f 97 c2 02 87 07 30 2e"
        "38 15 33 a5 90 d1 1e 75 fe 9d e3 97 e5 b9 80 d4"
        "7d b0 33 13 53 6a 8d e7 a1 7d 8c d8 bc 05 3f ac"
        "0a d4 07 d4 d1 00 45 be 97 ec a0 a1 3a d1 c1 c6"
        "48 48 5a ff b2 4a 9e 00 f9 a8 09 b0 08 86 9a ca"
        "d0 5d 79 dc 20 5b a5 87 5c 68 45 e2 52 31 22 36"
        "0f cf 98 45 9c b0 81 ee e0 2f eb 02 8e b0 7b 21"
        "58 a0 d2 02 12 c2 99 82 bf 15 b1 93 cb 3a df 88"
        "88 9e 44 a5 4a dc 12 35 2f 77 95 04 44 9d 90 b2"
        "d5 c2 29 a0 17 03 03 01 19 ed 30 de 7c 10 91 7d"
        "7d 38 0a 9b cf 9c ed 40 d8 c0 30 3e 01 ed 3f 2a"
        "a8 c0 b1 a1 3c 1f 88 a4 fb 9e 77 2e 9a b9 78 ed"
        "22 82 4c c4 7f 65 74 ba b4 5f 90 91 35 0a f8 16"
        "41 ef 5f 83 a1 a5 fd 78 e7 9f f0 10 79 f4 e7 5c"
        "2c 50 e1 6b 22 ff c3 62 03 e9 b8 7f 67 79 3b bd"
        "b4 0d f1 83 89 2e f4 fa 99 41 a4 1b 6f d0 ee b2"
        "db 56 1c 5d 24 80 6f 1e 03 be 13 1d 4d 17 70 d2"
        "27 81 72 31 34 e4 cf cf 3c 60 fb 07 60 18 a8 92"
        "17 61 95 be b7 f4 e9 1f 16 9a ae 41 2c 35 d8 71"
        "7c 62 2a 42 17 70 eb e9 c4 ee cc 42 4c 6b 4d 3a"
        "c4 2a 5c c6 df ff 11 45 6a b8 61 2b 84 eb 3b 37"
        "ae a7 ff b5 4b 5a 3b c7 83 32 6a e1 76 4d c6 78"
        "10 9b be e7 85 90 5d 80 b6 ff e7 04 77 e6 28 41"
        "f6 69 a8 17 1d 02 8e 6d eb 79 f9 34 8b bf 9c 10"
        "2b 5d 51 6e 61 e5 2a e7 7c db d7 ea 2d e9 28 5f"
        "0d 07 6d e1 05 8d 2e 71 f0 7d 53 87 ba 7e 31 11"
        "d8 38 93 83 05 f2 95 7b 58 99 89 df 82 2c 2d 74"
        "82 40 17 03 03 00 45 9b df d7 61 a6 0d 5d b2 76"
        "7c f2 ae c5 b6 c4 ee 63 21 23 6a 56 0d 9e c8 c4"
        "69 36 2a e1 1c 52 a7 9d e0 64 75 60 04 94 c9 6a"
        "bf 43 e0 0e 36 17 ca a9 93 39 c9 d7 59 d2 9e 37"
        "d1 47 b5 dd ca 40 69 4a 7d 48 8b ad",
    },
    {
        from_client,
        "change_cipher_spec, finished",
        "14 03 03 00 01 01 17 03 03 00 45 3e 55 2d be a4"
        "88 ba 1f 12 73 73 f8 84 75 05 d9 9f d2 1a 84 aa"
        "b7 7c e4 3f f4 ea 4e de fa 94 da c7 3c 66 fc 29"
        "95 13 f1 23 48 a0 20 68 d5 db 44 d8 99 df 30 45"
        "ea f9 f1 f5 ed 8e 39 5a d6 d8 ae 3a 21 6e ac b1",
    },
    {
        from_server,
        "new_session_ticket",
        "17 03 03 00 fa e1 f5 d3 d5 fc 93 f7 11 d4 e9 0c"
        "dc 95 00 2d 83 56 34 e6 dc 11 98 7f 89 ad 9c 36"
        "95 e0 52 f4 59 4a a7 96 c9 69 63 1c b7 68 79 f6"
        "58 86 84 91 00 bb 22 e6 58 ac 03 3f 87 58 08 fa"
        "16 ce 29 fc d4 1a 67 df 21 8e 4d b7 0f 48 86 46"
        "66 2d fe d8 cd 13 16 f5 95 53 0d f2 f9 3b 24 0e"
        "c7 fd 5d 9e 56 88 ce 8b f0 45 a1 bc 7e 18 8e f9"
        "ab 94 8b 6e fb c6 4a 1d d6 3d ca 7d cb 30 30 83"
        "4d cc 17 0d b6 47 b1 32 4f c7 49 c8 f6 d9 b8 4f"
        "d1 83 f1 e8 d4 0d fb d0 6f 44 f5 da db a2 05 7e"
        "4d 5a 62 81 e8 38 0b ba f5 58 c4 5c b4 3a 14 0c"
        "b6 fe 34 c2 c3 9a f2 9e ee 36 66 84 be af fb 8d"
        "4a 4f 1e ec f9 b6 73 84 7e 51 5a d8 23 f1 a4 0c"
        "9b ee a8 c8 32 52 68 64 d5 92 2d a4 ed b2 ed fd"
        "2c be a4 ff 71 5b 8f 79 7e a0 d5 69 a1 33 65 e4"
        "d1 ef 20 be 29 1f f9 56 15 be 2a f8 12 25 9c",
    },
    {
        from_server,
        "new_session_ticket",
        "17 03 03 00 fa 73 0c 72 9b 71 6d b8 a1 02 19 32"
        "1d bf fa 05 89 82 b6 bb 0c c5 fd 9c 00 14 20 5c"
        "2c e7 2a cb d5 f9 a5 b2 e7 68 d5 76 e3 ca 0c 71"
        "ca 7e 83 1c 1f fa 62 da b8 fb e7 58 9f 2a 81 92"
        "d9 73 82 a5 9d dc 21 4b 1e c0 27 52 63 03 b3 83"
        "15 bc 2b c8 08 8a 94 09 95 f2 49 ba 60 92 eb 3d"
        "8a a9 eb eb b8 eb 42 08 e0 32 17 c3 ad 63 5c 2b"
        "fa e5 68 47 32 19 a5 d3 15 26 2b 1c d2 48 b3 7b"
        "f4 a5 c2 2c 3e 61 0e b3 c1 81 c7 5e 87 5c 6b da"
        "14 65 9e 3d 1f c1 f7 56 9b 08 f2 af cc f6 d8 c6"
        "7f 94 c8 f1 5a 1b 6a 1e 57 0e 07 f2 2c dc 78 88"
        "76 7b e7 95 6c 00 9d 76 5e 4e 62 9c e7 45 31 66"
        "cf 84 eb bc 77 a5 4d 31 61 91 49 c1 a5 70 a7 c4"
        "99 1d 1e 05 9e 96 e2 e4 7d d6 f6 4b 56 ac 24 87"
        "9c 33 22 62 08 1c ac d6 34 85 0e 08 81 ea 48 1b"
        "cd 41 31 35 a4 28 34 c8 d9 43 06 9c c9 e3 1c",
    },
    {
        from_client,
        "application data",
        "17 03 03 00 18 f1 40 f0 3b 33 67 09 18 be 0a 57"
        "fc 94 64 08 ae b5 4f 02 20 fe 01 46 ec",
    },
    {
        from_client,
        "alert",
        "17 03 03 00 13 a0 d4 71 0a 7a 11 44 63 97 ff 63"
        "2c 0c b5 b1 23 cb a9 01",
    },
    {
        from_server,
        "alert",
        "17 03 03 00 13 6e ca 59 6f 00 37 ca bd 87 17 10"
        "1a ab 9c d9 1c 38 23 9d",
    },
};

pcap_testvector capture_tls13_ccm[] = {
    {
        from_client,
        "client_hello",
        "16 03 01 00 e3 01 00 00 df 03 03 20 e4 66 26 7b"
        "48 0e d9 19 49 cb 1c 27 50 38 02 6b e8 16 b9 b4"
        "bb d4 90 cc 1c e5 64 5e b5 c6 b7 20 f0 13 dc e6"
        "e5 5b ab 34 72 73 fe 10 b9 7e 51 f4 6e 1c 23 1b"
        "58 0e df d9 98 85 f6 c3 2a 39 7b fc 00 02 13 04"
        "01 00 00 94 00 0b 00 04 03 00 01 02 00 0a 00 16"
        "00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01"
        "01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17"
        "00 00 00 0d 00 24 00 22 04 03 05 03 06 03 08 07"
        "08 08 08 1a 08 1b 08 1c 08 09 08 0a 08 0b 08 04"
        "08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03"
        "04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00"
        "20 e0 5f 8f d5 1d d4 35 d2 27 44 d5 6e 0f cc 4b"
        "cd d4 d2 54 97 8c 1b b5 08 82 8e c6 ed fb 8d d4"
        "24 00 1b 00 03 02 00 01",
    },
    {
        from_server,
        "server_hello, change_cipher_spec, encrypted_extensions, certificate, certificate_verify, finished",
        "16 03 03 00 7a 02 00 00 76 03 03 49 33 3c d0 4d"
        "ce b0 2a 1e f7 19 5d d7 3f 2f f1 0f 14 be 20 c6"
        "4a 5b 4d 61 a2 6c 39 ac c3 9c 47 20 f0 13 dc e6"
        "e5 5b ab 34 72 73 fe 10 b9 7e 51 f4 6e 1c 23 1b"
        "58 0e df d9 98 85 f6 c3 2a 39 7b fc 13 04 00 00"
        "2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 c0"
        "53 5b 9d e6 5b ce 35 fe db 74 0a 10 5a 45 0b 6a"
        "50 63 fa eb 08 ae 18 3d 74 27 8e fd c7 c7 65 14"
        "03 03 00 01 01 17 03 03 00 17 76 b9 00 be 11 57"
        "da a3 5d 08 05 ba bf 35 48 9c 0c 24 35 dd 7b eb"
        "46 17 03 03 02 2a 48 b0 dd f7 01 16 13 d1 7a db"
        "26 51 c9 58 eb ef 22 48 f8 eb 46 8b 89 3d dc 91"
        "28 1a 99 66 35 34 56 af f2 91 8d 42 cc a3 4e 73"
        "cd 87 af 6b f7 10 c4 07 c4 82 21 f9 10 15 ae 57"
        "91 bd 0a f2 06 96 db 1c b2 15 a6 06 73 0b 4b 13"
        "be b1 13 11 e6 d9 60 d7 3f 69 73 1d 83 c8 d9 cf"
        "b5 ba a0 38 ae 3d b3 ff cf 13 96 2f df 8d c3 ca"
        "a8 7c 3c 65 a3 dd ff 04 53 09 88 82 64 50 1a e9"
        "b3 27 b6 20 c3 8c 49 bd 17 d6 c1 04 a7 2b c5 d4"
        "f5 6d 38 55 e1 37 5a ff fb 02 b9 98 36 2b fb 6b"
        "00 9b 87 82 4f 1d d1 7f da c2 be 19 a5 41 68 6e"
        "16 6e 94 7f ce 70 12 96 16 98 57 92 3d 6e db 8c"
        "82 49 be f2 51 79 6e 9c 50 db ed 1b f6 42 ee 9c"
        "31 a9 53 c9 35 47 34 93 e2 ee 74 78 c1 5c 17 16"
        "b5 3c 39 79 a2 79 c2 56 b3 31 2a d0 8d 26 56 37"
        "d0 86 cd 87 b8 d4 e3 20 40 f2 a0 a8 e3 d0 39 84"
        "c9 38 de 02 34 de 04 9b bc dc 65 4a cf c2 df 69"
        "cc 87 80 6c 05 ff 1c be 51 6b 23 38 90 c9 92 d9"
        "e6 52 f8 8a 3d 13 b5 f0 29 83 37 86 72 39 78 45"
        "e9 6f ba e2 6a 96 41 fe 9d 08 56 4d b5 7b d1 cf"
        "86 95 4e b4 ae f9 84 2e 3e ae 80 bb 0d aa 81 64"
        "f3 e2 ee 86 c8 ba 88 6e e2 49 ce f4 8c c0 6a 81"
        "fe 62 35 ff e7 d1 11 47 e3 d6 da 57 3d 71 18 9e"
        "93 cb 9d b4 0d a7 39 c8 16 51 fb c6 7c 02 92 00"
        "1a de 0a 7f 68 22 b8 62 20 23 94 69 0e 46 b5 63"
        "52 bf 27 87 79 d1 d4 b3 6f 63 87 ad c6 a0 d5 9d"
        "11 c4 6a 99 69 55 34 6f d2 fb 68 7e d5 9e 5c a8"
        "aa 79 6d 93 07 10 c9 2f 5c 79 e3 33 82 86 5a c2"
        "26 10 e2 b3 51 c0 05 c1 38 6d dc 7e 38 b1 70 8f"
        "c5 7d 0c 2c c5 af 78 2c 34 26 a9 57 17 07 4f 94"
        "e7 ea 53 b6 93 73 a2 e9 a9 cd b4 af e5 73 d9 a4"
        "a0 bc 9f a9 d4 d5 f4 73 65 25 22 6c ca 66 e3 94"
        "8e e1 0c a1 e4 33 3f 4e 20 c5 72 47 dc 1c 08 57"
        "86 9c 95 3b ec 2a dc 8a b0 38 02 f8 07 65 52 fd"
        "06 86 56 eb f7 08 0a d3 5a 84 98 09 af 93 1c 86"
        "17 03 03 00 60 c0 a6 0d 74 0e a9 c1 68 66 0c 1c"
        "e2 d6 d6 cf 29 c0 2a c1 b6 36 d6 13 af 26 be 2d"
        "a8 0f 1d bc 8f 05 3e 8d bd f0 e9 6f f8 f4 76 32"
        "c7 cb 93 52 15 0e ad ed 83 79 04 1f 98 c4 f0 fe"
        "28 87 fb fd f1 dd 2f 08 c8 e6 d3 eb 98 22 43 b0"
        "c2 6e 54 ae 4f 79 02 ad e4 16 cb 84 10 d0 8b c5"
        "67 28 5d 79 66 17 03 03 00 35 e7 34 ee 17 47 04"
        "7a fa d7 b8 c5 ef 8d 1d 9f 9f c3 93 ed a3 d0 92"
        "9a 4a 25 3c 98 f6 1e ec 58 df 54 76 01 ac 4e 5f"
        "4d d5 32 31 1f 68 83 45 33 88 f7 15 ae f6 45",
    },
    {
        from_client,
        "change_cipher_spec, finished",
        "14 03 03 00 01 01 17 03 03 00 35 10 e1 6d b0 73"
        "df 52 90 e2 d5 a6 3c 5a c5 ea 2c b6 5f b4 2b 8b"
        "92 ba 84 6d 27 aa d7 de 4e cb dd 8a 4f 8f 4b a5"
        "0d 84 44 22 2a 01 f5 87 45 b3 5c e0 1f 6a 44 a8",
    },
    {
        from_server,
        "new_session_ticket",
        "17 03 03 00 ea 74 57 a5 a5 37 db 2a 8f b9 0c d4"
        "ce d9 ad 0f 81 d7 a3 ee c6 39 fb 18 fb 77 8e 07"
        "d5 c0 5c c6 74 05 9e b9 ef 99 13 ad c6 fb c8 96"
        "b6 5c 1f 85 6c b2 6e 15 45 24 d3 1b 52 de 2c 2f"
        "ee da 4c 3c c6 90 7e f3 aa 58 19 09 05 76 a7 0b"
        "79 f5 cd 50 30 bb e1 d1 75 e1 85 dd 3e 02 eb 8f"
        "66 ed a4 ff 20 49 6d 33 42 1e cd 64 db 02 84 1d"
        "45 aa b1 6f 21 55 47 ca 4c 2b 2d c9 30 68 d0 f3"
        "02 aa 49 73 d6 e5 a5 07 a5 82 5a c8 15 6a 66 d7"
        "b7 ff 52 03 fc 1a 24 1b 2c c9 21 71 eb ff 58 76"
        "db b8 af a2 af e5 e3 10 58 c2 15 0e 9a f6 e2 8e"
        "28 06 84 26 41 04 37 9f 5f a7 e8 1e 41 16 14 ad"
        "8b a9 19 f1 49 18 a7 12 37 37 eb 3d 6d 49 6a 07"
        "98 e4 6c 24 83 94 96 28 7b 12 fa 6e 51 e8 df 11"
        "ef ed 53 87 e0 c9 58 07 1e 97 9c 7e 42 d8 2e",
    },
    {
        from_server,
        "new_session_ticket",
        "17 03 03 00 ea 57 44 a5 b6 b5 84 4c ad e0 e3 0e"
        "37 af 8d ac 4b 80 95 a4 d7 bd a0 45 34 44 ac e7"
        "46 17 99 85 98 63 f2 8e d3 69 bc f9 37 82 35 99"
        "be 13 ee ed f1 e8 01 52 90 9a fb f1 0a 5e 47 eb"
        "f9 96 1d ff 7d 6a 08 ef e5 0d a9 32 78 6e 69 41"
        "d4 73 14 13 d6 7c e1 0c e2 0f 1e 43 0b 80 60 f4"
        "d8 a7 a8 c4 59 7b a9 34 5c a1 6f 1c ab a4 07 b9"
        "77 a3 bb 1f f5 c6 9e 9a 0b 0b 58 5d 94 03 d0 8a"
        "9e 34 7e 14 c9 29 02 d5 67 71 49 a2 6c dd a8 f9"
        "05 6d d4 89 e5 79 78 eb ea 23 85 d5 7e a3 59 02"
        "a8 ed fb 71 ec b0 f3 00 76 f6 6f 4c 87 d5 da 3e"
        "da 9e 27 e5 5a 37 3e 84 f7 0b 0d 75 39 49 74 57"
        "6d f8 c3 e6 fe aa 9e 1d 4f 24 d9 a5 6f 4a e4 f7"
        "dc d6 32 f0 ed 66 53 54 1b 16 ae 7d 89 07 13 43"
        "ff 36 7d 3d 73 9d c8 8f 53 0a 0d ab 1f a0 3e",
    },
    {
        from_client,
        "application data",
        "17 03 03 00 17 de c7 2b 92 cd 5a eb d7 09 23 79"
        "c2 ea 39 32 5f 3c ea 2e ea 6e 6d 28",
    },
    {
        from_client,
        "close_notify",
        "17 03 03 00 13 8d c4 d6 ce d5 f1 0c 0f b5 2d 3f"
        "9d 99 1c fd 95 42 04 87",
    },
    {
        from_server,
        "close_notify",
        "17 03 03 00 13 06 a9 a4 a9 6f fd f2 cb 13 00 c1"
        "b0 3c 79 52 15 fb d8 db",
    },
};

pcap_testvector capture_tls13_chacha20_poly1305[] = {
    {
        from_client,
        "client_hello",
        "16 03 01 00 e3 01 00 00 df 03 03 c5 5d 7d e4 cc"
        "a2 ee 3f 72 5c a0 27 cb b3 0a 1b f3 b8 57 f2 96"
        "2a a4 b7 bc cf 31 06 bb c9 e7 b3 20 cd b0 2b 3b"
        "2b 06 fe cc 9f fc 32 0c 46 e7 55 cc 51 41 7a 30"
        "84 e4 bd 8a 64 78 53 ff 34 37 6e 86 00 02 13 03"
        "01 00 00 94 00 0b 00 04 03 00 01 02 00 0a 00 16"
        "00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01"
        "01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17"
        "00 00 00 0d 00 24 00 22 04 03 05 03 06 03 08 07"
        "08 08 08 1a 08 1b 08 1c 08 09 08 0a 08 0b 08 04"
        "08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03"
        "04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00"
        "20 90 08 ff 08 34 3c ab 2b 32 2e a0 b5 02 ca c0"
        "9c 34 bd 07 30 39 98 f9 1f 96 c6 ef 14 c5 f6 cf"
        "43 00 1b 00 03 02 00 01",
    },
    {
        from_server,
        "server_hello, change_cipher_spec, encrypted_extensions, certificate, certificate_verify, finished",
        "16 03 03 00 7a 02 00 00 76 03 03 94 d9 85 bd 42"
        "8c 53 b2 85 92 da cd 71 d6 95 96 78 17 80 19 8e"
        "94 d4 f0 4f cc 89 62 71 5f 6a f6 20 cd b0 2b 3b"
        "2b 06 fe cc 9f fc 32 0c 46 e7 55 cc 51 41 7a 30"
        "84 e4 bd 8a 64 78 53 ff 34 37 6e 86 13 03 00 00"
        "2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 20"
        "72 6f 25 f8 d7 c3 08 35 83 10 1b 81 b7 c5 4e 02"
        "cc d4 13 1b 7d 16 84 8a 8c e7 25 68 94 27 50 14"
        "03 03 00 01 01 17 03 03 00 17 49 e7 75 95 d0 5d"
        "20 cc 42 7d ba 15 2c ef 4d 28 0b 38 93 c1 18 9d"
        "42 17 03 03 02 2a e3 37 0e 36 1a 40 06 56 9c 69"
        "b9 f8 50 3e 30 0d ce 59 8b c5 6d fb b0 a6 72 c3"
        "10 13 9f d4 a9 de a8 44 a2 f6 bf 1a e8 5e 52 64"
        "bd b3 f4 e1 93 8e e3 52 a5 25 05 c4 b1 6d 87 94"
        "41 0e 71 60 bb 22 8c a1 82 0f 5f 40 44 74 ed 2b"
        "44 59 3b b3 7f f2 23 f4 1d 86 17 96 c2 20 7a 0b"
        "2b c8 ff 4e 0e 4d eb a0 44 dc ea f7 64 95 df d3"
        "2e e0 b0 84 70 35 e6 ba 80 a5 4b 82 db 49 7c f9"
        "57 02 3c 50 c0 05 22 1e 84 e8 bc 11 53 da 5c 0a"
        "8c 36 45 b0 60 d5 04 2d ea bb c7 82 d5 3c 08 cc"
        "96 b4 99 dc 7b 60 37 27 37 66 19 09 a5 9d 27 d4"
        "d8 7a 24 2c 6f 23 1a 63 ab b1 c3 e3 6c 07 e4 1e"
        "7e 9b bf 29 d5 85 91 89 4c ef 14 a3 7f 20 22 99"
        "f5 5d f1 47 db b4 57 e6 07 38 7e 9f de 0f 2b ec"
        "e9 d0 24 a1 a2 e2 ef a2 1f df ed 0c 2d 6d c4 a9"
        "a5 0c 89 ce 61 bc 64 5e d3 2e 4d cc 5a ed 29 a9"
        "fa d1 33 8d 1b 3f 48 b4 7c 79 bf af f9 fe 71 85"
        "6d 60 1e 0e 2f c8 2a cd 80 d2 ec f0 86 f4 df 9e"
        "2f 72 9b 84 13 9b b1 6e 87 ae 58 f0 75 06 30 83"
        "22 74 82 09 1b b8 01 66 65 49 41 70 ab 9e e8 12"
        "08 57 f3 af 51 9c 56 15 c5 b3 75 00 4d 9d e5 b3"
        "e0 c5 b5 59 4c ea 2d a8 2d 06 bf 88 3a 50 7e 5e"
        "f4 19 5e 1b 4a ce a6 e9 8d f9 ed 3d e1 57 ea b0"
        "10 a4 f9 18 94 cc 7e 65 88 f3 0d e3 cb b4 bd fb"
        "f5 d4 c5 7a 68 3f 22 82 30 a1 90 37 7d 9c b5 f0"
        "6b 4e 6f f2 c8 c9 b0 79 a3 d1 c4 05 a6 ed e0 a5"
        "37 93 6b da 43 a7 ee c0 ed 60 32 16 0f 0c 7a d4"
        "67 71 3c d3 68 0f f2 b6 1d d7 31 a4 87 8d 42 06"
        "d9 38 6c a1 ec a4 ab 91 3f 77 a9 67 c1 7f c6 27"
        "6c 5b d2 7f 53 8d c5 d8 5c 07 eb c0 a9 0d 35 59"
        "6c 4e d7 f4 f2 0c 2d f8 4d 1c 78 16 dc 5c 48 b6"
        "85 f2 ff af 17 17 b1 2c 7f 08 86 bf 89 c6 a7 70"
        "80 f1 fb d2 af 7a e9 09 08 b9 df f1 03 54 76 66"
        "15 4b 9d 5b a1 61 8f 6c 7b 4e 63 46 55 a7 b0 0a"
        "58 fb fb c4 c2 d5 c2 37 e2 2c bd 46 23 7f c6 1e"
        "17 03 03 00 60 cb 6b 7d 79 1e 14 47 a5 d1 78 b9"
        "b2 59 37 83 59 90 dc 46 8e f3 28 19 a3 cd 7b d5"
        "25 80 39 8e f7 dd 6a b0 9c 91 c8 6d 66 af 00 a2"
        "76 ea 26 0d 31 e1 61 9a bd 11 f6 42 fe 9d 76 ad"
        "7d 62 50 da 42 fe d5 52 37 0f 67 de ec bf e1 e1"
        "98 ed 69 91 2f 9e 37 20 ef cd 8b 68 8c 2f e9 5b"
        "5c 32 21 9f 2c 17 03 03 00 35 86 67 ea e2 4f 8a"
        "bb 08 87 59 b8 4a 27 fc 26 51 43 ba 68 cb 94 01"
        "13 bc db 9a 41 4a 50 c4 26 49 fa b6 73 e6 88 d5"
        "55 1e 3c e7 2c 10 fb fe 53 8d ff cd dc d4 40",
    },
    {
        from_client,
        "change_cipher_spec, finished",
        "14 03 03 00 01 01 17 03 03 00 35 de 19 ea 02 75"
        "ab 10 91 7a 37 c2 77 50 9e ac 25 8a 2e 0c 72 b5"
        "15 62 5c d0 db df 0d b7 c2 2c 26 73 d6 a6 10 61"
        "34 c0 ad cf 26 90 cf b4 65 c5 bf 7c af 61 9d 85",
    },
    {
        from_server,
        "new_session_ticket",
        "17 03 03 00 ea 2e 66 ba 03 04 78 98 2f eb 84 96"
        "67 70 5d 2f 63 d9 cf f1 df f8 d3 8a 83 eb c6 87"
        "f4 b2 a0 f0 b3 aa b7 fe 00 68 a7 9f 53 45 20 da"
        "c6 1d e0 54 33 8e 2b 25 ee 5a d3 92 42 d3 ae 89"
        "d3 b6 61 c6 b0 a4 f8 36 a0 05 ef a3 d8 db 67 c6"
        "0b bc 48 43 8b 62 e4 53 e7 78 85 11 ec ef 41 3d"
        "32 92 32 5a 8e f9 7c 33 96 1f 8b 5f 02 f8 1c b7"
        "ca 33 72 44 c5 50 0f 66 d6 06 a9 bc aa d2 b1 0b"
        "3e 54 90 0c a8 d9 4c f9 e0 83 df 0c 23 70 5a 59"
        "15 c7 51 50 ad 44 77 c3 d7 bf f6 04 d7 42 06 2f"
        "1a 03 ca 3b cc 41 04 98 36 3c c9 f3 04 3f 95 32"
        "3d e3 b1 11 4b 9e 6c 94 bf e3 a7 ea c4 61 97 d5"
        "9c 6b 3f 06 20 a1 f7 0f 65 8a 3f 4b 05 f1 a4 d2"
        "88 51 65 71 2f 7d bd ff 31 88 cc 58 a9 4c 70 08"
        "e5 c2 21 06 3c a2 b6 09 9e 7f ad 63 78 20 70",
    },
    {
        from_server,
        "new_session_ticket",
        "17 03 03 00 ea 2b 97 be 44 5a ca 9a 5f 14 18 76"
        "46 ec 29 5f 01 69 8f b6 ac aa 2f fb 32 00 d8 ca"
        "b0 ea 77 e5 2b 60 0f 72 4f 85 a4 a9 b2 d3 c6 d9"
        "ab ad 4b a9 b2 f0 f0 94 07 c5 c2 48 a6 65 d8 91"
        "2d 66 83 e6 f2 44 a2 48 bf 64 76 ba e4 db 45 0b"
        "3a e3 39 6e ae 9d db b6 00 ec 7f 07 a2 94 a3 3c"
        "6d 87 33 99 4e 86 30 52 4e 14 0e 05 f1 f7 67 eb"
        "d9 78 ec 54 a0 4d 8b 52 45 96 1f 25 9a 30 29 cc"
        "3d 80 40 fc 01 c4 cc 1d 9b 91 82 64 32 84 be e8"
        "08 ef ff 66 0e 34 66 2c 94 80 cf f4 7b 89 b5 1a"
        "c4 57 df b8 f8 89 01 53 6b ca f8 dc 86 7b 30 ae"
        "6b 3f af d8 9f fe 7c 2b 69 26 40 b2 42 87 31 e1"
        "07 e1 e6 14 26 cb 31 9f bc e6 5f 67 53 4c 62 9e"
        "7f e8 75 0a 4b ea af 6b 09 1b 72 87 82 3a f5 d4"
        "14 f4 3b 72 98 46 07 ce 9d 34 1c 52 ee ce e8",
    },
    {
        from_client,
        "application_data",
        "17 03 03 00 17 a7 08 39 a3 f8 53 2b 8b 1e e8 20"
        "bb 86 cc ef 9f 8d a4 7c e7 b7 68 79",
    },
    {
        from_client,
        "close_notify",
        "17 03 03 00 13 f9 81 52 9f a2 78 a7 b9 c4 f1 74"
        "16 f2 28 bf f2 e8 ed bc",
    },
    {
        from_server,
        "close_notify",
        "17 03 03 00 13 ec dc 93 21 f5 3b ce e3 dd 8b 6f"
        "db e6 c6 20 b5 6c d8 a8",
    },
};

void test_captured_tls13() {
    {
        _test_case.begin("TLS 1.3 pre master secret");

        tls_session session_sclient(session_type_tls);
        auto& protection = session_sclient.get_tls_protection();

        protection.use_pre_master_secret(true);
        // SERVER_HANDSHAKE_TRAFFIC_SECRET (server_handshake_traffic_secret)
        protection.set_item(server_handshake_traffic_secret,
                            base16_decode_rfc("e232d8af6204b54f5e85d8c93cb3b2f69fc13ff439e029b6d9ec95a0175451bf333c312ebfa032fa44624a688bf954b8"));
        // CLIENT_HANDSHAKE_TRAFFIC_SECRET (client_handshake_traffic_secret)
        protection.set_item(client_handshake_traffic_secret,
                            base16_decode_rfc("1a469cb11a59d969868f7e62a939233422ad82ee6d866eebb5dc17cd2f32b2916be8706c9e63fe24294763e36ae1ea38"));
        // EXPORTER_SECRET
        protection.set_item(tls_secret_exp_master,
                            base16_decode_rfc("02e5c7ebbe3315502d186dfb8385092e303472483e861aeb2c89accefead3e249b55150bb195bd82c7f1e05b017ca6fa"));
        // SERVER_TRAFFIC_SECRET_0 (server_application_traffic_secret_0)
        protection.set_item(server_application_traffic_secret_0,
                            base16_decode_rfc("cc899e0330367316bb2ab23949dc71a991b38b42025dc1fa9a05643b161c9ec1f0c6696f60b5ed8ef76524779b0e5abb"));
        // CLIENT_TRAFFIC_SECRET_0 (client_application_traffic_secret_0)
        protection.set_item(client_application_traffic_secret_0,
                            base16_decode_rfc("7c6e80aea2d0f6f9411f921fcd28963383a82d54d01cd8f2a822ee8dce354fb7984b7211785e36de6ec19fcb9bcd1cb8"));

        play_pcap(&session_sclient, capture_tls13, RTL_NUMBER_OF(capture_tls13));
    }

    {
        _test_case.begin("TLS 1.3 pre master secret TLS_AES_128_CCM_SHA256");

        tls_session session_sclient(session_type_tls);
        auto& protection = session_sclient.get_tls_protection();

        protection.use_pre_master_secret(true);
        // SERVER_HANDSHAKE_TRAFFIC_SECRET (server_handshake_traffic_secret)
        protection.set_item(server_handshake_traffic_secret, base16_decode_rfc("d1e102620ceaf58facc136927bbf631591a4d2204cecf17352aacc0561a05e02"));
        // CLIENT_HANDSHAKE_TRAFFIC_SECRET (client_handshake_traffic_secret)
        protection.set_item(client_handshake_traffic_secret, base16_decode_rfc("a65f00bc1f1f76927fe6b21c286b164781a63190555b54cbb9c45e8f4001e8d2"));
        // EXPORTER_SECRET
        protection.set_item(tls_secret_exp_master, base16_decode_rfc("26e19951270472527de1aebf58db1f537892d96287d4e8458d8f145b6f20168d"));
        // SERVER_TRAFFIC_SECRET_0 (server_application_traffic_secret_0)
        protection.set_item(server_application_traffic_secret_0, base16_decode_rfc("f4da140ae8c6fbed7a59ea863b3a459e5e15fc9ddd5a2baa8021dfe1de635713"));
        // CLIENT_TRAFFIC_SECRET_0 (client_application_traffic_secret_0)
        protection.set_item(client_application_traffic_secret_0, base16_decode_rfc("ec139d3054dbb41adcbf6b185ad737668d29ab4a517ce5eddc7083336dbbd857"));

        play_pcap(&session_sclient, capture_tls13_ccm, RTL_NUMBER_OF(capture_tls13_ccm));
    }

    {
        _test_case.begin("TLS 1.3 pre master secret TLS_CHACHA20_POLY1305_SHA256");

        tls_session session_sclient(session_type_tls);
        auto& protection = session_sclient.get_tls_protection();

        protection.use_pre_master_secret(true);
        // SERVER_HANDSHAKE_TRAFFIC_SECRET (server_handshake_traffic_secret)
        protection.set_item(server_handshake_traffic_secret, base16_decode_rfc("601dd4dcc3277dbb3969a464b716f1fe868d2af6424d1f04481a472103bc899b"));
        // CLIENT_HANDSHAKE_TRAFFIC_SECRET (client_handshake_traffic_secret)
        protection.set_item(client_handshake_traffic_secret, base16_decode_rfc("965272c3a3c1a8df580ec6edb4eeb5b779ea32ea2b702a65016356816d5f1a81"));
        // EXPORTER_SECRET
        protection.set_item(tls_secret_exp_master, base16_decode_rfc("f6488a46c930058d717a710036b10de556560eac12805a6c39238e980c02a40b"));
        // SERVER_TRAFFIC_SECRET_0 (server_application_traffic_secret_0)
        protection.set_item(server_application_traffic_secret_0, base16_decode_rfc("bad5f6924fa2ab3a258e1c8c4168fddd09c05fb8cd29573ef24850d1b4ad73a4"));
        // CLIENT_TRAFFIC_SECRET_0 (client_application_traffic_secret_0)
        protection.set_item(client_application_traffic_secret_0, base16_decode_rfc("788b2e29a6ce9dff91b21231e775a59e345aaf79bbdc5e9d371afeb6548142b9"));

        play_pcap(&session_sclient, capture_tls13_chacha20_poly1305, RTL_NUMBER_OF(capture_tls13_chacha20_poly1305));
    }
}
