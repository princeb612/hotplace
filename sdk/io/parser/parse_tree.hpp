/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   parse_tree.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026-09-02   Soo Han and Gemini  study
 *
 */

#ifndef __HOTPLACE_SDK_IO_PARSER_PARSERTREE__
#define __HOTPLACE_SDK_IO_PARSER_PARSERTREE__

#include <hotplace/sdk/base/nostd/tree.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/io/parser/cfg_grammar.hpp>
#include <memory>
#include <stack>

namespace hotplace {
namespace io {

struct parse_treenode;
class parse_tree;
class parse_tree_visitor;

struct parse_treenode {
    std::string symbol;
    std::string value;
    std::list<parse_treenode*> children;

    parse_treenode(const std::string& sym, const std::string& val = "");
    ~parse_treenode();

    parse_treenode(const parse_treenode&) = delete;
    parse_treenode& operator=(const parse_treenode&) = delete;

    void accept(parse_tree_visitor* visitor);

    void print(basic_stream& bs, int depth = 0) const;
};

class parse_tree {
   private:
    std::list<parse_treenode*> _node_stack;

   public:
    ~parse_tree();

    void clear();
    /**
     * shift: creates an input token as a terminal node and pushes it onto the node stack.
     */
    void on_shift(const std::string& token_symbol, const std::string& token_value);
    /**
     * 1. Pop $k$ child nodes from the node stack, which is the number of symbols on the right side of the production.
     * 2. Create a parent node $A$ (Non-Terminal) and connect the popped nodes as its children.
     * 3. Push the newly created parent node $A$ back onto the node stack.
     */
    void on_reduce(const std::string& lhs_symbol, size_t rhs_count);

    parse_treenode* get_root() const;

    void accept(parse_tree_visitor* visitor);
};

class parse_tree_visitor {
   public:
    parse_tree_visitor(std::function<void(parse_treenode*)>);

    void visit(parse_tree* tree);
    void describe(parse_treenode* node);

   private:
    std::function<void(parse_treenode*)> _func;
};

}  // namespace io
}  // namespace hotplace

#endif
