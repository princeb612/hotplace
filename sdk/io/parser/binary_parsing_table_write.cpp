/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   binary_parsing_table_write.cpp
 * @author  Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <fstream>
#include <hotplace/sdk/base/basic/crc.hpp>
#include <hotplace/sdk/base/stream/binary_stream.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/io/parser/binary_parsing_table.hpp>
#include <hotplace/sdk/io/parser/cfg_grammar.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>

namespace hotplace {
namespace io {

return_t binary_parsing_table::write(const std::string& filename, parser_t& parser) {
    return_t ret = errorcode_t::success;

    binary_t bin;

    // BLOCK1 - string table
    {
        binary_stream bs;
        bs.set_endian(true).append(uint32(_string_index.size()));  // entries
        for (const auto& item : _string_index) {
            const auto& symbol = item.first;
            auto len = symbol.size();
            bs.append(uint16(len)).append((byte_t*)symbol.c_str(), len);  // len, char[len]
        }
        auto size = bs.size();
        bs.prefix(uint64(size));  // block size

        binary_append(bin, bs.get());
    }
    // BLOCK2 - terminals
    {
        binary_stream bs;
        bs.set_endian(true).append(uint32(_terminals.size()));  // entries
        for (const auto& item : _terminals) {
            bs.append(item);
        }
        auto size = bs.size();
        bs.prefix(uint64(size));  // block size

        binary_append(bin, bs.get());
    }
    // BLOCK3 - productions
    {
        binary_stream bs;
        bs.set_endian(true).append(uint32(_production_table.size()));  // entries
        for (const auto& item : _production_table) {
            bs.append(uint32(item.id)).append(uint32(item.lhs)).append(uint32(item.rhs.size()));  // production id, lhs, count of rhs
            for (const auto& elem : item.rhs) {
                bs.append(uint32(elem));  // rhs
            }
        }
        auto size = bs.size();
        bs.prefix(uint64(size));  // block size

        binary_append(bin, bs.get());
    }
    // BLOCK4 - action
    {
        binary_stream bs;
        bs.set_endian(true).append(uint32(_action_table.size()));  // entries
        for (const auto& item : _action_table) {
            bs.append(item.state).append(item.lookahead).append(uint8(item.action)).append(item.target);  // state, lookahead, action, target
        }
        auto size = bs.size();
        bs.prefix(uint64(size));  // block size

        binary_append(bin, bs.get());
    }
    // BLOCK5 - goto
    {
        binary_stream bs;
        bs.set_endian(true).append(uint32(_goto_table.size()));  // entries
        for (const auto& item : _goto_table) {
            bs.append(item.state).append(item.nonterminal).append(item.next_state);  // state, non-terminal, next_state
        }
        auto size = bs.size();
        bs.prefix(uint64(size));  // block size

        binary_append(bin, bs.get());
    }
    // header
    {
        auto crc = crc32(bin.data(), bin.size());
        auto size = bin.size();
        binary_stream bs;
        bs.set_endian(true)
            .append(uint32(0x48505400))
            .append(uint16(parser.get_cfg_grammar().get_revision()))
            .append(uint16(0x1234))
            .append(uint32(crc))
            .append(uint64(size));

        const auto& temp = bs.get();
        bin.insert(bin.begin(), temp.begin(), temp.end());
    }

    std::ofstream ofs(filename, std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(bin.data()), bin.size());

    return ret;
}

}  // namespace io
}  // namespace hotplace
