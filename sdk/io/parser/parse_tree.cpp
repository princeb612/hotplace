/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   parse_tree.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026-08-29   Soo Han and Gemini  study
 *
 */

#include <hotplace/sdk/io/parser/parse_tree.hpp>

namespace hotplace {
namespace io {

parse_treenode::parse_treenode(const std::string& sym, const std::string& val) : symbol(sym), value(val) {}

parse_treenode::~parse_treenode() {
    for (parse_treenode* child : children) {
        delete child;
    }
    children.clear();
}

void parse_treenode::accept(parse_tree_visitor* visitor) { visitor->describe(this); }

void parse_treenode::print(basic_stream& bs, int depth) const {
    bs.fill(depth << 1, ' ');
    bs << symbol;
    if ((false == value.empty()) && (symbol != value)) bs << " (" << value << ")";
    bs << "\n";
    for (const parse_treenode* child : children) {
        child->print(bs, depth + 1);
    }
}

parse_tree::~parse_tree() { clear(); }

void parse_tree::clear() {
    for (parse_treenode* node : _node_stack) {
        delete node;
    }
    _node_stack.clear();
}

void parse_tree::on_shift(const std::string& token_symbol, const std::string& token_value) { _node_stack.push_back(new parse_treenode(token_symbol, token_value)); }

void parse_tree::on_reduce(const std::string& lhs_symbol, size_t rhs_count) {
    parse_treenode* parent = new parse_treenode(lhs_symbol);

    if (rhs_count > 0) {
        auto first = std::prev(_node_stack.end(), rhs_count);
        auto last = _node_stack.end();

        // no elements are copied or moved, only the internal pointers of the list nodes are re-pointed.
        parent->children.splice(parent->children.end(), _node_stack, first, last);
    }

    _node_stack.push_back(parent);
}

parse_treenode* parse_tree::get_root() const {
    if (false == _node_stack.empty()) {
        return _node_stack.back();
    }
    return nullptr;
}

void parse_tree::accept(parse_tree_visitor* visitor) {
    if (visitor) {
        auto root = get_root();
        if (root) root->accept(visitor);
    }
}

parse_tree_visitor::parse_tree_visitor(std::function<void(parse_treenode*)> func) : _func(func) {}

void parse_tree_visitor::visit(parse_tree* tree) {
    if (_func && tree) tree->accept(this);
}

void parse_tree_visitor::describe(parse_treenode* node) { _func(node); }

}  // namespace io
}  // namespace hotplace
