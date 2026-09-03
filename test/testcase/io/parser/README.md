### Guidelines for CFG/LALR Grammars & Token Mapping

#### 1. Alignment Between Lexer Tokens and LALR Terminal Symbols

* **Prevent Token Mapping Omissions**: Ensure that all token types extracted by the lexer (`token_quoted`, `token_string`, `token_floatingpoint`, etc.) are mapped to parser terminal symbols (`quot_string`, `fp`, `num`, `id`) in the conversion loop (`dump_handler` / `switch-case`) without exception.
* **Multi-character Token Precedence**: Ensure multi-character operators or tokens such as `..` (fromto), `::=` (assign), and `--` (comments) are registered and evaluated before single-character tokens.

#### 2. Tagged Types and Recursive Grammar Structuring

* **TagSpec and Class Combination Branches**: Explicitly define all possible combinations in production rules regarding the presence of class names and `EXPLICIT`/`IMPLICIT` specifiers:
  * `[ TagClass num ] TagSpec TypeSpec`
  * `[ TagClass num ] TypeSpec`
  * `[ num ] TagSpec TypeSpec`
  * `[ num ] TagSpec TypeSpec`
* **Recursive Path Resolution**: Ensure seamless recursion for nested structures or choice types within TaggedTypes (e.g., `TypeSpec` -> `TypeBase` -> `TaggedType` -> `TypeSpec`).

#### 3. Constraints & Literal Range Expansion

* **Subtype / Constraint Elements**: Include all literals and keywords used in constraint expressions (`ConstraintExpr`) under the `ValueElement` production rule:
  * Identifiers (`id`), Numbers (`num`), Floating points (`fp`), Quoted strings (`quot_string`)
  * Boundary keywords (`MIN`, `MAX`) and Booleans (`TRUE`, `FALSE`)

#### 4. Mitigating Shift/Reduce and Reduce/Reduce Conflicts

* **Hierarchical Rules and Operator Precedence**: Eliminate ambiguity when using compound operators like `INTERSECTION`, `EXCEPT`, and `|` (UNION) by strictly separating grammar levels (`ConstraintExpr` -> `SubtypeElementSet` -> `IntersectionElement` -> `PrimaryElement`).
* **Single Augmented Start Symbol (Root Unification)**: Avoid defining multiple direct productions for the augmented start symbol (`S'`). Group top-level entry points into a single non-terminal (e.g., `S' -> Statement`) before branching into specific statements (`Assignment`, `TypeSpec`, `Constraint`). This prevents Lookahead set overlap at State 0 and avoids unintentional action table drops.
* **First-Token Lookahead Disambiguation**: When multiple top-level productions share the same leading token type (e.g., `symid`), ensure the grammar path can be uniquely resolved without causing Reduce/Reduce conflicts during LALR table generation.

#### 5. Rules for Robust Production Creation

* **Avoid Overlapping Left-Hand Side (LHS) Entry Paths**: Ensure top-level standalone expressions and assignment expressions do not cause lookahead collisions when parsed without context.
* **Explicit Non-Terminal Wrapping**: Wrap structural statements (e.g., `SEQUENCE`, `SET`, `CHOICE`) into dedicated non-terminals (such as `StatementSequence`, `StatementSet`) rather than directly embedding them as raw token sequences across disparate production rules.
* **Completeness of Optional/Default Branches**: For productions containing optional attributes or field qualifiers (`OPTIONAL`, `DEFAULT`), ensure all terminal and non-terminal fallback paths are explicitly mapped to prevent early parser reduction failures.

#### 6. Checklist for Adding New Grammar Patterns

1. **Lexer**: Register new keyword/symbol tokens and verify `get_config()` flags.
2. **Grammar**: Declare terminal symbols via `add_terminal()` and construct production rules via `add_production()`.
3. **Start Symbol Integrity**: Verify that `S'` delegates to a unified root non-terminal to prevent initial state conflicts.
4. **Mapper**: Update the token translation `switch-case` block for Lexer output -> Parser input.
5. **Test Vector**: Create minimal test vectors and inspect dynamic execution traces to confirm parsing success.

### Study

```
state = stack.top();
token = lookahead;

action = ACTION[state][token];

switch (action.type) {
case SHIFT:
    push(token);
    state = action.state;
    read_next_token();
    break;

case REDUCE:
    pop(rhs_size);
    lhs = rule.lhs;
    state = GOTO[stack.top()][lhs];
    push(lhs);
    break;

case ACCEPT:
    return success;

case ERROR:
    return error;
}
```

#### Type1 ::= VisibleString

```
[000] line 1 type 33(lvalue) index 0 pos 0 len 5 (Type1)
[001] line 1 type 32(assign) index 1 pos 6 len 3 (::=)
[002] line 1 type 4124(VisibleString) index 2 pos 10 len 13 (VisibleString)
LALR(1) Dynamic Parsing Execution Trace
state stack           token                 action
--------------------------------------------------------------------------
[ 0 ]                 Type1 (29)            shift -> State 49
[ 0 49 ]              ::= (32)              shift -> State 84
[ 0 49 84 ]           VisibleString (4124)  shift -> State 47
[ 0 49 84 47 ]        $ (4294967295)        reduce -> Rule 75 (SimpleType)
[ 0 49 84 30 ]        $ (4294967295)        reduce -> Rule 38 (TypeBase)
[ 0 49 84 41 ]        $ (4294967295)        reduce -> Rule 32 (TypeSpec)
[ 0 49 84 118 ]       $ (4294967295)        reduce -> Rule 4 (Assignment)
[ 0 3 ]               $ (4294967295)        reduce -> Rule 1 (Statement)
[ 0 31 ]              $ (4294967295)        accept

parser tree
Statement
  Assignment
    id (Type1)
    ::=
    TypeSpec
      TypeBase
        SimpleType
          VisibleString
```

trace
```
state       lookahead                   action
----------------------------------------------------------------
0           ... id (S49) ...            shift 49, push 49
0 49        ... ::= (S84) ...           shift 84, push 84
0 49 84     ... VisibleString (S47) ... shift 47, push 47
0 49 84 47  ... $ (R75) ...             reduce 75
0 49 84     pop size(rhs of 75),        stacktop 84, push 84:SimpleType -> 30
0 49 84 30  ... $ (R38) ...             reduce 38
0 49 84     pop size(rhs of 38),        stacktop 84, push 84:TypeBase -> 41
0 49 84 41  ... $ (R32) ...             reduce 32
0 49 84     pop size(rhs of 32),        stacktop 84, push 84:TypeSpec -> 118
0 49 84 118 ... $ (R4) ...              reduce 4
0           pop size(rhs of 4),         stacktop 0, push 0:Assignment -> 3
0 3         ... $ (R1) ...              reduce 1
0           pop size(rhs of 1),         stacktop 0, 0:Statement -> 31
0 31        ... $ (A0) ...              accept
----------------------------------------------------------------

ACTION table
  {(0:id) -> shift target 49},
  {(49:::=) -> shift target 84},
  {(84:VisibleString) -> shift target 47},
  {(47:$) -> reduce target 75},
  {(30:$) -> reduce target 38},
  {(41:$) -> reduce target 32},
  {(118:$) -> reduce target 4},
  {(3:$) -> reduce target 1},
  {(31:$) -> accept target 0},

GOTO table
  {(84:SimpleType) -> 30},
  {(84:TypeBase) -> 41},
  {(84:TypeSpec) -> 118},
  {(0:Assignment) -> 3},
  {(0:Statement) -> 31},

production set
  [75] lhs:SimpleType rhs:{VisibleString}
  [38] lhs:TypeBase rhs:{SimpleType}
  [32] lhs:TypeSpec rhs:{TypeBase}
  {(84:TypeSpec) -> 118},
  [4] lhs:Assignment rhs:{id,::=,TypeSpec}
  [1] lhs:Statement rhs:{Assignment}
```
