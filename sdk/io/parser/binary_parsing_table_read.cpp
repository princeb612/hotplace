/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   binary_parsing_table_read.cpp
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

return_t binary_parsing_table::read(const std::string& filename, parser_t& parser) {
    return_t ret = errorcode_t::success;

    clear();
    parser.get_cfg_grammar().clear();
    parser.clear();

    file_stream fs;
    ret = fs.open(filename.c_str());
    if (errorcode_t::success != ret) {
        return ret;
    }

    ret = fs.begin_mmap();
    if (errorcode_t::success != ret) {
        return ret;
    }

    auto stream = fs.data();
    auto size = fs.size();
    size_t pos = 0;
    uint32 crc = 0;
    uint64 bodysize = 0;  // sum(BLOCK1 + BLOCK2 + .. + BLOCK5)

    // Header
    {
        payload pl;
        pl << new payload_member(uint32(0), true, "magic")    // "PTB\0"
           << new payload_member(uint16(0), true, "version")  // 0
           << new payload_member(uint16(0), true, "endian")   // endian
           << new payload_member(uint32(0), true, "crc32")    // crc32(block1..block5)
           << new payload_member(uint64(0), true, "size");    // sum(block1..block5)
        //
        // 0x1234

        ret = pl.read(stream, size, pos);
        if (errorcode_t::success != ret) {
            return ret;
        }
        if (pos < 20) {
            return errorcode_t::bad_format;
        }

        auto magic = pl.t_value_of<uint32>("magic");
        if (0x48505400 != magic) {
            return errorcode_t::bad_format;
        }
        auto version = pl.t_value_of<uint16>("version");
        if (version < parser.get_cfg_grammar().get_revision()) {
            return errorcode_t::low_version;
        }
        auto endian = pl.t_value_of<uint16>("endian");
        if (0x1234 != endian) {
            return errorcode_t::bad_format;
        }
        crc = pl.t_value_of<uint32>("crc32");
        bodysize = pl.t_value_of<uint64>("size");
    }

    if ((size - pos) != bodysize) {
        return errorcode_t::bad_format;
    }
    auto checksum = crc32(stream + pos, size - pos);
    if (checksum != crc) {
        return errorcode_t::integrity_error;
    }

    // BLOCK1 - string table
    {
        uint32 entries = 0;
        {
            payload pl;
            pl << new payload_member(uint64(0), true, "block size")  // block size
               << new payload_member(uint32(0), true, "entries");    // entries
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                return ret;
            }

            entries = pl.t_value_of<uint32>("entries");
        }

        for (uint32 idx = 0; idx < entries; ++idx) {
            binary_t data;
            {
                payload pl;
                pl << new payload_member(uint16(0), true, "len")  // len
                   << new payload_member(binary_t(), "symbol");   // char[len]
                pl.set_reference_value("symbol", "len");
                ret = pl.read(stream, size, pos);
                if (errorcode_t::success != ret) {
                    return ret;
                }
                pl.get_binary("symbol", data);
            }

            std::string symbol = to_string(data);
            _string_index.emplace(symbol, idx);
            _reverse_map.emplace(idx, std::move(symbol));
        }
    }
    // BLOCK2 - terminals
    {
        uint32 entries = 0;
        {
            payload pl;
            pl << new payload_member(uint64(0), true, "block size")  // block size
               << new payload_member(uint32(0), true, "entries");    // entries
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                return ret;
            }

            entries = pl.t_value_of<uint32>("entries");
        }

        for (uint32 idx = 0; idx < entries; ++idx) {
            payload pl;
            pl << new payload_member(uint32(0), true, "item");
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                return ret;
            }
            auto id = pl.t_value_of<uint32>("item");
            _terminals.push_back(id);

            auto symbol = rlookup(id);
            parser.get_cfg_grammar().add_terminal(symbol);
        }
    }
    // BLOCK3 - productions
    {
        uint32 entries = 0;
        {
            payload pl;
            pl << new payload_member(uint64(0), true, "block size")  // block size
               << new payload_member(uint32(0), true, "entries");    // entries
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                return ret;
            }

            entries = pl.t_value_of<uint32>("entries");
        }

        for (uint32 idx = 0; idx < entries; ++idx) {
            production_t production;
            uint32 count = 0;
            {
                payload pl;
                pl << new payload_member(uint32(0), true, "id")      //
                   << new payload_member(uint32(0), true, "lhs")     //
                   << new payload_member(uint32(0), true, "count");  //
                ret = pl.read(stream, size, pos);
                if (errorcode_t::success != ret) {
                    return ret;
                }
                production.id = pl.t_value_of<uint32>("id");
                production.lhs = pl.t_value_of<uint32>("lhs");
                count = pl.t_value_of<uint32>("count");
            }

            for (uint32 c = 0; c < count; ++c) {
                payload pl;
                pl << new payload_member(uint32(0), true, "elem");
                ret = pl.read(stream, size, pos);
                if (errorcode_t::success != ret) {
                    return ret;
                }
                auto elem = pl.t_value_of<uint32>("elem");
                production.rhs.push_back(elem);
            }

            auto lhs = rlookup(production.lhs);
            std::vector<std::string> rhs;
            for (const auto& item : production.rhs) {
                auto temp = rlookup(item);
                rhs.push_back(std::move(temp));
            }
            parser.get_cfg_grammar().add_production(lhs, rhs);
        }
    }
    // BLOCK4 - action
    {
        uint32 entries = 0;
        {
            payload pl;
            pl << new payload_member(uint64(0), true, "block size")  // block size
               << new payload_member(uint32(0), true, "entries");    // entries
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                return ret;
            }

            entries = pl.t_value_of<uint32>("entries");
        }
        for (uint32 idx = 0; idx < entries; ++idx) {
            payload pl;
            pl << new payload_member(uint32(0), true, "state")      //
               << new payload_member(uint32(0), true, "lookahead")  //
               << new payload_member(uint8(0), "action")            //
               << new payload_member(uint32(0), true, "target");    //
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                return ret;
            }

            bpt_action_item_t item;
            item.state = pl.t_value_of<uint32>("state");
            item.lookahead = pl.t_value_of<uint32>("lookahead");
            item.action = pl.t_value_of<uint8>("action");
            item.target = pl.t_value_of<uint32>("target");

            _action_table.push_back(std::move(item));

            parser_action_state action_state;
            action_state.type = (parser_action_t)item.action;
            action_state.target = item.target;
            parser.buildup_action(item.state, rlookup(item.lookahead), std::move(action_state));
        }
    }
    // BLOCK5 - goto
    {
        uint32 entries = 0;
        {
            payload pl;
            pl << new payload_member(uint64(0), true, "block size")  // block size
               << new payload_member(uint32(0), true, "entries");    // entries
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                return ret;
            }

            entries = pl.t_value_of<uint32>("entries");
        }
        for (uint32 idx = 0; idx < entries; ++idx) {
            payload pl;
            pl << new payload_member(uint32(0), true, "state")        //
               << new payload_member(uint32(0), true, "nonterm")      //
               << new payload_member(uint32(0), true, "next_state");  //
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                return ret;
            }

            bpt_goto_item_t item;
            item.state = pl.t_value_of<uint32>("state");
            item.nonterminal = pl.t_value_of<uint32>("nonterm");
            item.next_state = pl.t_value_of<uint32>("next_state");

            _goto_table.push_back(std::move(item));
            parser.buildup_goto(item.state, rlookup(item.nonterminal), item.next_state);
        }

        parser.import_completed();
    }

    return ret;
}

}  // namespace io
}  // namespace hotplace
