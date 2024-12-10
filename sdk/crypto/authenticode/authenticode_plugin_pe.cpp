/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/authenticode/authenticode.hpp>
#include <sdk/crypto/authenticode/authenticode_plugin_pe.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/io/stream/file_stream.hpp>
#include <sdk/io/system/winpe.hpp>

namespace hotplace {
namespace crypto {

authenticode_plugin_pe::authenticode_plugin_pe() : authenticode_plugin() {
    // do nothing
}

authenticode_plugin_pe::~authenticode_plugin_pe() {
    // do nothing
}

bool authenticode_plugin_pe::is_kind_of(file_stream* filestream) {
    return_t ret = errorcode_t::success;
    bool ret_value = false;

    __try2 {
        if (nullptr == filestream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (true != filestream->is_open()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        if (false == filestream->is_mmapped()) {
            ret = filestream->begin_mmap();
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        byte_t* stream_data = nullptr;
        size_t stream_size = 0;
        stream_data = filestream->data();
        stream_size = filestream->size();

        if (stream_size < sizeof(IMAGE_DOS_HEADER)) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(stream_data);
        if (IMAGE_DOS_SIGNATURE == dos_header->e_magic) {
            if (stream_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
                ret = errorcode_t::bad_format;
                __leave2;
            }
            IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(stream_data + dos_header->e_lfanew);
            if (IMAGE_NT_SIGNATURE == nt_headers->Signature) {
                ret_value = true;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

return_t authenticode_plugin_pe::read_authenticode(file_stream* filestream, size_t& authenticode_begin, size_t& authenticode_size) {
    return_t ret = errorcode_t::success;

    __try2 {
        authenticode_begin = (size_t)-1;
        authenticode_size = 0;

        if (nullptr == filestream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (true != filestream->is_open()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        if (false == filestream->is_mmapped()) {
            ret = filestream->begin_mmap();
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        byte_t* stream_data = nullptr;
        size_t stream_size = 0;
        stream_data = filestream->data();
        stream_size = filestream->size();

        if (stream_size < sizeof(IMAGE_DOS_HEADER)) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(stream_data);
        if (IMAGE_DOS_SIGNATURE == dos_header->e_magic) {
            if (stream_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
                ret = errorcode_t::bad_format;
                __leave2;
            }
            IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(stream_data + dos_header->e_lfanew);
            if (IMAGE_NT_SIGNATURE == nt_headers->Signature) {
                size_t directory_rva = 0;
                size_t directory_size = 0;

                IMAGE_OPTIONAL_HEADER* optional_header = &nt_headers->OptionalHeader;
                if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == optional_header->Magic) {
                    if (stream_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_OPTIONAL_HEADER64)) {
                        ret = errorcode_t::bad_format;
                        __leave2;
                    }

                    IMAGE_OPTIONAL_HEADER64* optional_header64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optional_header);
                    directory_rva = optional_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                    directory_size = optional_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
                } else if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == optional_header->Magic) {
                    if (stream_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_OPTIONAL_HEADER32)) {
                        ret = errorcode_t::bad_format;
                        __leave2;
                    }

                    IMAGE_OPTIONAL_HEADER32* optional_header32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(optional_header);

                    directory_rva = optional_header32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                    directory_size = optional_header32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
                }

                if (0 == directory_rva || 0 == directory_size) {
                    ret = errorcode_t::no_data;
                    __leave2;
                }

                if (stream_size < directory_rva + directory_size) {
                    ret = errorcode_t::bad_format;
                    __leave2;
                }

                authenticode_begin = directory_rva;
                authenticode_size = directory_size;
            } else {
                ret = errorcode_t::bad_format;
                __leave2;
            }
        } else {
            ret = errorcode_t::bad_format;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_plugin_pe::read_authenticode(file_stream* filestream, binary_t& data) {
    return_t ret = errorcode_t::success;

    __try2 {
        data.resize(0);

        size_t authenticode_begin = 0;
        size_t authenticode_size = 0;
        ret = read_authenticode(filestream, authenticode_begin, authenticode_size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        byte_t* stream_data = nullptr;
        // size_t stream_size = 0;
        stream_data = filestream->data();
        // stream_size = filestream->size();

        /* Extracting and Verifying PKCS #7
         *
         * The Authenticode signature is in a location that is specified by the Certificates Table entry in Optional Header Data
         * Directories and the associated Attribute Certificate Table.
         *
         * The Authenticode signature is in a WIN_CERTIFICATE structure, which is declared in Wintrust.h
         */
        WIN_CERTIFICATE* win_certificate = reinterpret_cast<WIN_CERTIFICATE*>(stream_data + authenticode_begin);
        if (WIN_CERT_REVISION_2_0 == win_certificate->wRevision) {
            if (WIN_CERT_TYPE_PKCS_SIGNED_DATA == win_certificate->wCertificateType) {
                size_t blob_start = FIELD_OFFSET(WIN_CERTIFICATE, bCertificate);
                size_t blob_size = win_certificate->dwLength - blob_start;
                data.resize(blob_size);
                memcpy(&data[0], stream_data + authenticode_begin + blob_start, blob_size);
            } else {
                ret = errorcode_t::bad_format;
                __leave2;
            }
        } else {
            ret = errorcode_t::bad_format;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_plugin_pe::write_authenticode(file_stream* filestream, binary_t data) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == filestream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (true != filestream->is_open()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        size_t authenticode_begin = 0;
        size_t authenticode_size = 0;
        ret = read_authenticode(filestream, authenticode_begin, authenticode_size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        WIN_CERTIFICATE* win_certificate = reinterpret_cast<WIN_CERTIFICATE*>(filestream->data() + authenticode_begin);
        if ((WIN_CERT_REVISION_2_0 != win_certificate->wRevision) || (WIN_CERT_TYPE_PKCS_SIGNED_DATA != win_certificate->wCertificateType)) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        size_t blob_start = FIELD_OFFSET(WIN_CERTIFICATE, bCertificate);
        byte_t* stream_data = nullptr;
        size_t stream_size = 0;

        size_t size_new = authenticode_begin + blob_start + data.size();

        if (true == filestream->is_mmapped()) {
            filestream->end_mmap();
        }
        filestream->truncate(size_new);
        ret = filestream->begin_mmap();
        if (errorcode_t::success != ret) {
            __leave2;
        }

        stream_data = filestream->data();
        stream_size = filestream->size();
        IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(stream_data);
        if (IMAGE_DOS_SIGNATURE == dos_header->e_magic) {
            if (stream_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
                ret = errorcode_t::bad_format;
                __leave2;
            }
            IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(stream_data + dos_header->e_lfanew);
            if (IMAGE_NT_SIGNATURE == nt_headers->Signature) {
                // size_t directory_rva = 0;
                size_t directory_size = 0;

                IMAGE_OPTIONAL_HEADER* optional_header = &nt_headers->OptionalHeader;
                if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == optional_header->Magic) {
                    IMAGE_OPTIONAL_HEADER64* optional_header64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optional_header);

                    // directory_rva = optional_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                    directory_size = blob_start + data.size();
                    optional_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = directory_size;
                } else if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == optional_header->Magic) {
                    IMAGE_OPTIONAL_HEADER32* optional_header32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(optional_header);

                    // directory_rva = optional_header32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                    directory_size = blob_start + data.size();
                    optional_header32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = directory_size;
                }

                /* Extracting and Verifying PKCS #7
                 *
                 * The Authenticode signature is in a location that is specified by the Certificates Table entry in Optional Header Data
                 * Directories and the associated Attribute Certificate Table.
                 *
                 * The Authenticode signature is in a WIN_CERTIFICATE structure, which is declared in Wintrust.h
                 */
                // WIN_CERTIFICATE* win_certificate = reinterpret_cast<WIN_CERTIFICATE*>(stream_data + directory_rva);
                // win_certificate->dwLength = data.size();
                // win_certificate->wRevision = WIN_CERT_REVISION_2_0;
                // win_certificate->wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA;

                memcpy(stream_data + authenticode_begin + blob_start, &data[0], data.size());
            } else {
                ret = errorcode_t::bad_format;
                __leave2;
            }
        } else {
            ret = errorcode_t::bad_format;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t authenticode_plugin_pe::digest(file_stream* filestream, const char* algorithm, binary_t& output) {
    return_t ret = errorcode_t::success;
    hash_context_t* hash_handle = nullptr;
    openssl_hash hash;
    byte_t* stream_data = nullptr;
    size_t stream_size = 0;
    size_t authenticode_begin = 0;
    size_t checksum_offset = 0;
    size_t securitydir_offset = 0;

    __try2 {
        if (nullptr == filestream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (true != filestream->is_open()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        if (false == filestream->is_mmapped()) {
            ret = filestream->begin_mmap();
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        stream_data = filestream->data();
        stream_size = filestream->size();

        IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(stream_data);
        if (IMAGE_DOS_SIGNATURE == dos_header->e_magic) {
            if (stream_size <= dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
                ret = errorcode_t::bad_format;
                __leave2;
            }
            IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(stream_data + dos_header->e_lfanew);
            if (IMAGE_NT_SIGNATURE == nt_headers->Signature) {
                uint32* checksum_pointer = nullptr; /* *checksum_pointer is CheckSum */
                uint32* securitydir_pointer = nullptr;
                IMAGE_OPTIONAL_HEADER* optional_header = &nt_headers->OptionalHeader;
                if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == optional_header->Magic) {
                    if (stream_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_OPTIONAL_HEADER64)) {
                        ret = errorcode_t::bad_format;
                        __leave2;
                    }

                    IMAGE_OPTIONAL_HEADER64* optional_header64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optional_header);
                    checksum_pointer = &optional_header64->CheckSum; /* address */
                    securitydir_pointer = &optional_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                    authenticode_begin = optional_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                } else if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == optional_header->Magic) {
                    if (stream_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_OPTIONAL_HEADER32)) {
                        ret = errorcode_t::bad_format;
                        __leave2;
                    }
                    IMAGE_OPTIONAL_HEADER32* optional_header32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(optional_header);
                    checksum_pointer = &optional_header32->CheckSum; /* address */
                    securitydir_pointer = &optional_header32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                    authenticode_begin = optional_header32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                } else {
                    ret = errorcode_t::bad_format;
                    __leave2;
                }

                checksum_offset = (arch_t)checksum_pointer - (arch_t)stream_data;
                securitydir_offset = (arch_t)securitydir_pointer - (arch_t)stream_data;
            } else {
                ret = errorcode_t::bad_format;
                __leave2;
            }
        } else {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        ret = hash.open(&hash_handle, algorithm);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (true != filestream->is_open()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        byte_t* stream_data = nullptr;
        // size_t stream_size = 0;

        if (false == filestream->is_mmapped()) {
            ret = filestream->begin_mmap();
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        stream_data = filestream->data();
        stream_size = filestream->size();

        /*
         * hash following blocks
         * block1 0~block2
         * block2 checksum_offset~+4bytes (skip)
         * block3 block2+1~block4
         * block4 authenticode_offset~+8bytes (skip)
         * block5 block4+1~authenticode_begin
         */
        hash.init(hash_handle);
        hash.update(hash_handle, stream_data, checksum_offset);                                                         // block1
        hash.update(hash_handle, stream_data + checksum_offset + 4, securitydir_offset - (checksum_offset + 4));        // block3
        hash.update(hash_handle, stream_data + securitydir_offset + 8, authenticode_begin - (securitydir_offset + 8));  // block5
        hash.finalize(hash_handle, output);
    }
    __finally2 { hash.close(hash_handle); }

    return ret;
}

bool authenticode_plugin_pe::separated() { return false; }

return_t authenticode_plugin_pe::find_if_separated(std::string filepathname_not_signed, std::list<std::string> pathlist, std::list<std::string>& filelist) {
    return errorcode_t::not_available;
}

return_t authenticode_plugin_pe::verify_if_separated(std::string file_not_signed, std::string file_signed, uint32* result) {
    return errorcode_t::not_available;
}

return_t authenticode_plugin_pe::read_checksum(file_stream* filestream, uint32* out_checksum_value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == filestream || nullptr == out_checksum_value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (true != filestream->is_open()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        byte_t* stream_data = nullptr;
        size_t stream_size = 0;

        if (false == filestream->is_mmapped()) {
            ret = filestream->begin_mmap();
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        stream_data = filestream->data();
        stream_size = filestream->size();

        IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(stream_data);
        if (IMAGE_DOS_SIGNATURE == dos_header->e_magic) {
            if (stream_size <= dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
                ret = errorcode_t::bad_format;
                __leave2;
            }
            IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(stream_data + dos_header->e_lfanew);
            if (IMAGE_NT_SIGNATURE == nt_headers->Signature) {
                uint32* checksum_pointer = nullptr; /* *checksum_pointer is CheckSum */
                IMAGE_OPTIONAL_HEADER* optional_header = &nt_headers->OptionalHeader;
                if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == optional_header->Magic) {
                    IMAGE_OPTIONAL_HEADER64* optional_header64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optional_header);
                    checksum_pointer = &optional_header64->CheckSum; /* address */
                } else if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == optional_header->Magic) {
                    IMAGE_OPTIONAL_HEADER32* optional_header32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(optional_header);
                    checksum_pointer = &optional_header32->CheckSum; /* address */
                } else {
                    ret = errorcode_t::bad_format;
                    __leave2;
                }

                *out_checksum_value = *checksum_pointer;
            } else {
                ret = errorcode_t::bad_format;
                __leave2;
            }
        } else {
            ret = errorcode_t::bad_format;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t authenticode_plugin_pe::calc_checksum(file_stream* filestream, uint32* out_checksum_value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == filestream || nullptr == out_checksum_value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (true != filestream->is_open()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        byte_t* stream_data = nullptr;
        size_t stream_size = 0;

        if (false == filestream->is_mmapped()) {
            ret = filestream->begin_mmap();
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        stream_data = filestream->data();
        stream_size = filestream->size();

        IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(stream_data);
        if (IMAGE_DOS_SIGNATURE == dos_header->e_magic) {
            IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(stream_data + dos_header->e_lfanew);
            if (IMAGE_NT_SIGNATURE == nt_headers->Signature) {
                uint32* checksum_pointer = nullptr; /* *checksum_pointer is CheckSum */
                IMAGE_OPTIONAL_HEADER* optional_header = &nt_headers->OptionalHeader;
                if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == optional_header->Magic) {
                    IMAGE_OPTIONAL_HEADER64* optional_header64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optional_header);
                    checksum_pointer = &optional_header64->CheckSum; /* address */
                } else if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == optional_header->Magic) {
                    IMAGE_OPTIONAL_HEADER32* optional_header32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(optional_header);
                    checksum_pointer = &optional_header32->CheckSum; /* address */
                } else {
                    ret = errorcode_t::bad_format;
                    __leave2;
                }

                winpe_checksum pecs;
                uint32 value = 0;
                uint32 checksum = 0;
                size_t boundry = (byte_t*)checksum_pointer - (byte_t*)stream_data;

                pecs.init();
                pecs.update(stream_data, boundry);
                pecs.update((byte_t*)&value, 4);
                pecs.update(stream_data + boundry + 4, stream_size - boundry - 4);
                pecs.finalize(checksum);

                *out_checksum_value = checksum; /* out parameter */

            } else {
                ret = errorcode_t::bad_format;
                __leave2;
            }
        } else {
            ret = errorcode_t::bad_format;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t authenticode_plugin_pe::update_checksum(file_stream* filestream, uint32* out_checksum_value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == filestream || nullptr == out_checksum_value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (true != filestream->is_open()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        byte_t* stream_data = nullptr;
        size_t stream_size = 0;

        if (false == filestream->is_mmapped()) {
            ret = filestream->begin_mmap();
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        stream_data = filestream->data();
        stream_size = filestream->size();

        IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(stream_data);
        if (IMAGE_DOS_SIGNATURE == dos_header->e_magic) {
            IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(stream_data + dos_header->e_lfanew);
            if (IMAGE_NT_SIGNATURE == nt_headers->Signature) {
                uint32* checksum_pointer = nullptr; /* *checksum_pointer is CheckSum */
                IMAGE_OPTIONAL_HEADER* optional_header = &nt_headers->OptionalHeader;
                if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == optional_header->Magic) {
                    IMAGE_OPTIONAL_HEADER64* optional_header64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optional_header);
                    checksum_pointer = &optional_header64->CheckSum; /* address */
                } else if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == optional_header->Magic) {
                    IMAGE_OPTIONAL_HEADER32* optional_header32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(optional_header);
                    checksum_pointer = &optional_header32->CheckSum; /* address */
                } else {
                    ret = errorcode_t::bad_format;
                    __leave2;
                }

                winpe_checksum pecs;
                uint32 value = 0;
                uint32 checksum = 0;
                size_t boundry = (byte_t*)checksum_pointer - (byte_t*)stream_data;

                pecs.init();
                pecs.update(stream_data, boundry);
                pecs.update((byte_t*)&value, 4);
                pecs.update(stream_data + boundry + 4, stream_size - boundry - 4);
                pecs.finalize(checksum);

                *out_checksum_value = checksum; /* out parameter */
                *checksum_pointer = checksum;
            } else {
                ret = errorcode_t::bad_format;
                __leave2;
            }
        } else {
            ret = errorcode_t::bad_format;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

authenticode_engine_id_t authenticode_plugin_pe::id() { return authenticode_engine_id_t::authenticode_engine_id_pe; }

}  // namespace crypto
}  // namespace hotplace
