/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_construct.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 */

#include "sample.hpp"

void test_construct_babystep() {
    _test_case.begin("construct");
    /**
     *  Type1 ::= VisibleString
     * state stack           token          action
     * -------------------------------------------------------------------
     * [ 0 ]                 Type1 (id)     shift -> State 52
     * [ 0 52 ]              ::=            shift -> State 97
     * [ 0 52 97 ]           VisibleString  shift -> State 50
     * [ 0 52 97 50 ]        $              reduce -> Rule 81 (SimpleType) RHS[1]
     * [ 0 52 97 31 ]        $              reduce -> Rule 44 (TypeBase) RHS[1]
     * [ 0 52 97 44 ]        $              reduce -> Rule 37 (TypeSpec) RHS[1]
     * [ 0 52 97 137 ]       $              reduce -> Rule 6 (Assignment) RHS[3]
     * [ 0 3 ]               $              reduce -> Rule 1 (Statement) RHS[1]
     * [ 0 32 ]              $              accept
     * -------------------------------------------------------------------
     * parser tree
     * Statement
     *   Assignment
     *     id (Type1)
     *     ::=
     *     TypeSpec
     *       TypeBase
     *         SimpleType
     *           VisibleString
     */
    _logger->colorln("parse tree");
    parse_tree pt;
    pt.on_shift("id", "Type1");
    pt.on_shift("::=", "::=");
    pt.on_shift("VisibleString", "VisibleString");
    pt.on_reduce("SimpleType", 1);
    pt.on_reduce("TypeBase", 1);
    pt.on_reduce("TypeSpec", 1);
    pt.on_reduce("Assignment", 3);
    pt.on_reduce("Statement", 1);

    basic_stream bs;
    pt.get_root()->print(bs);
    _logger->write(bs);

    _logger->colorln("replay");
    int idx = 0;
    auto lambda = [&idx](parser_action_t type, parse_treenode* node) -> void {
        _logger->writeln([&](basic_stream& dbs) -> void {
            dbs << "[" << idx++ << "] ";
            switch (type) {
                case parser_action_t::shift:
                    dbs << "shift  ";
                    break;
                case parser_action_t::reduce:
                    dbs << "reduce ";
                    break;
                default:
                    break;
            }
            valist va;
            va << node->symbol << node->value;
            dbs.vaprintf("{1}", va);
            if ((false == node->value.empty()) && (node->symbol != node->value)) {
                dbs.vaprintf(" ({2})", va);
            }
            if (parser_action_t::reduce == type) {
                dbs << " RHS [" << node->children.size() << "]";
            }
        });
    };
    parse_tree_visitor visitor(lambda);
    pt.accept(&visitor);
}

void testcase_construct() { test_construct_babystep(); }
