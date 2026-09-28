/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file    binary_parsing_table.cpp
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
#include <hotplace/sdk/io/parser/glr_parser.hpp>
#include <hotplace/sdk/io/parser/lalr1_parser.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>

namespace hotplace {
namespace io {

binary_parsing_table::binary_parsing_table() {}

return_t binary_parsing_table::learn(parser_t* parser) {
    if (nullptr == parser) return errorcode_t::invalid_parameter;

    critical_section_guard guard(_lock);

    clear();

    auto& grammar = parser->get_cfg_grammar();
    for (const auto& production : grammar.get_productions()) {
        _string_index.emplace(production.lhs, 0);
        for (const auto& item : production.rhs) {
            _string_index.emplace(item, 0);
        }
    }
    for (const auto& terminal : grammar.get_terminals()) {
        _string_index.emplace(terminal, 0);
    }

    // lexicographically ascending
    uint32 idx = 0;
    for (auto& pair : _string_index) {
        pair.second = idx;
        _reverse_map.emplace(idx, pair.first);
        ++idx;
    }

    // production
    for (const auto& production : grammar.get_productions()) {
        buildup_production(production);
    }
    // terminal
    for (const auto& terminal : grammar.get_terminals()) {
        buildup_terminal(terminal);
    }

    // action and goto
    return parser->build(this);
}

uint32 binary_parsing_table::lookup(const std::string& symbol) {
    uint32 idx = (uint32)-1;
    critical_section_guard guard(_lock);
    auto iter = _string_index.find(symbol);
    if (_string_index.end() != iter) {
        idx = iter->second;
    }
    return idx;
}

std::string binary_parsing_table::rlookup(uint32 index) {
    std::string symbol;
    critical_section_guard guard(_lock);
    auto iter = _reverse_map.find(index);
    if (_reverse_map.end() != iter) {
        symbol = iter->second;
    }
    return symbol;
}

bool binary_parsing_table::ready() const {
    critical_section_guard guard(_lock);
    return ((false == _production_table.empty()) && (false == _action_table.empty()) && (false == _goto_table.empty()));
}

return_t binary_parsing_table::buildup_production(const parser_production& item) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    production_t production;
    production.id = _production_table.size();
    production.lhs = lookup(item.lhs);
    for (const auto& item : item.rhs) {
        auto idx = lookup(item);
        production.rhs.push_back(idx);
    }
    _production_table.push_back(std::move(production));
    return ret;
}

return_t binary_parsing_table::buildup_terminal(const std::string& term) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    auto idx = lookup(term);
    if ((uint32)-1 == idx) {
        ret = errorcode_t::bad_data;
    } else {
        _terminals.push_back(idx);
    }
    return ret;
}

return_t binary_parsing_table::buildup_action(uint32 state, const std::string& lookahead, const parser_action_state& action) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    bpt_action_item_t bpt;
    bpt.state = state;
    bpt.lookahead = lookup(lookahead);
    bpt.action = static_cast<uint8>(action.type);
    bpt.target = action.target;
    _action_table.push_back(std::move(bpt));
    return ret;
}
return_t binary_parsing_table::buildup_goto(uint32 state, const std::string& nonterm, uint32 next_state) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    bpt_goto_item_t bpt;
    bpt.state = state;
    bpt.nonterminal = lookup(nonterm);
    bpt.next_state = next_state;
    _goto_table.push_back(std::move(bpt));
    return ret;
}

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
            ret = errorcode_t::bad_data;
            return ret;
        }

        auto magic = pl.t_value_of<uint32>("magic");
        if (0x48505400 != magic) {
            ret = errorcode_t::bad_data;
            return ret;
        }
        auto endian = pl.t_value_of<uint32>("endian");
        if (0x1234 != endian) {
            ret = errorcode_t::bad_data;
            return ret;
        }
        crc = pl.t_value_of<uint32>("crc32");
        bodysize = pl.t_value_of<uint32>("size");
    }

    if ((size - pos) != bodysize) {
        ret = errorcode_t::bad_data;
        return ret;
    }
    auto checksum = crc32(stream + pos, size - pos);
    if (checksum != crc) {
        ret = errorcode_t::mismatch;
        return ret;
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

        parser.imported();
    }

    return ret;
}

return_t binary_parsing_table::write(const std::string& filename) {
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
        bs.set_endian(true).append(uint32(0x48505400)).append(uint16(0)).append(uint16(0x1234)).append(uint32(crc)).append(uint64(size));

        const auto& temp = bs.get();
        bin.insert(bin.begin(), temp.begin(), temp.end());
    }

    std::ofstream ofs(filename, std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(bin.data()), bin.size());

    return ret;
}

void binary_parsing_table::clear() {
    critical_section_guard guard(_lock);
    _string_index.clear();
    _reverse_map.clear();
    _terminals.clear();
    _production_table.clear();
    _action_table.clear();
    _goto_table.clear();
}

}  // namespace io
}  // namespace hotplace
