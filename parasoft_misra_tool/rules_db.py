"""
rules_db.py — SQLite database layer for MISRA C:2012 and AUTOSAR C++14 rules.

Responsibilities
----------------
* Create the `rules` and `violations` tables on first run.
* Populate the `rules` table with the full set of MISRA C:2012 directives /
  rules and AUTOSAR C++14 guidelines (representative coverage; extend the
  RULES list below to add more entries).
* Expose a clean query API used by analyzer.py, fixer.py and reporter.py.
"""

import sqlite3
from contextlib import contextmanager
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
DDL = """
CREATE TABLE IF NOT EXISTS rules (
    rule_id       TEXT PRIMARY KEY,
    standard      TEXT    NOT NULL,   -- MISRA_C_2012 | AUTOSAR_CPP14
    category      TEXT    NOT NULL,   -- Mandatory | Required | Advisory
    description   TEXT    NOT NULL,
    rationale     TEXT,
    severity      TEXT    NOT NULL,   -- Critical | Major | Minor
    fix_template  TEXT                -- NULL => manual review only
);

CREATE TABLE IF NOT EXISTS violations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path     TEXT    NOT NULL,
    line_number   INTEGER NOT NULL DEFAULT 0,
    col_number    INTEGER NOT NULL DEFAULT 0,
    rule_id       TEXT    NOT NULL REFERENCES rules(rule_id),
    snippet       TEXT,
    status        TEXT    NOT NULL DEFAULT 'open',  -- open | auto-fixed | manual-review
    fixed_snippet TEXT,
    scan_ts       DATETIME DEFAULT (datetime('now'))
);
"""

# ---------------------------------------------------------------------------
# Master rule catalogue
# ---------------------------------------------------------------------------
# Each entry: (rule_id, standard, category, description, rationale, severity, fix_template)
# fix_template is a short human-readable description of the automated fix;
# the actual code transformation lives in fixer.py.
RULES: List[tuple] = [
    # -----------------------------------------------------------------------
    # MISRA C:2012 — Directives
    # -----------------------------------------------------------------------
    ("D1.1",  "MISRA_C_2012", "Required",  "Any implementation-defined behaviour on which the output of the program depends shall be documented and understood.", "Portability.", "Major", None),
    ("D2.1",  "MISRA_C_2012", "Required",  "All source files shall compile without any compiler warnings.", "Compiler warnings often indicate real problems.", "Major", None),
    ("D3.1",  "MISRA_C_2012", "Required",  "All code shall be traceable to documented requirements.", "Traceability.", "Minor", None),
    ("D4.1",  "MISRA_C_2012", "Required",  "Run-time failures shall be minimised.", "Robust run-time behaviour.", "Critical", None),
    ("D4.3",  "MISRA_C_2012", "Required",  "Assembly language shall be encapsulated and isolated.", "Maintainability.", "Major", None),
    ("D4.6",  "MISRA_C_2012", "Advisory",  "typedefs that indicate size and signedness should be used in place of the basic numerical types.", "Portability.", "Minor", "Replace basic numeric type with sized typedef (e.g. uint8_t)"),
    ("D4.7",  "MISRA_C_2012", "Required",  "If a function returns error information, then that error information shall be tested.", "Reliability.", "Major", None),
    ("D4.8",  "MISRA_C_2012", "Advisory",  "If a pointer to a structure or union is never dereferenced within a translation unit, then the implementation of the object should be hidden.", "Information hiding.", "Minor", None),
    ("D4.9",  "MISRA_C_2012", "Advisory",  "A function should be used in preference to a function-like macro where they are interchangeable.", "Readability.", "Minor", None),
    ("D4.10", "MISRA_C_2012", "Required",  "Precautions shall be taken in order to prevent the contents of a header file being included more than once.", "Avoid duplicate declarations.", "Major", "Add include guard (#ifndef / #define / #endif)"),
    ("D4.11", "MISRA_C_2012", "Required",  "The validity of values passed to library functions shall be checked.", "Reliability.", "Major", None),
    ("D4.12", "MISRA_C_2012", "Required",  "Dynamic memory allocation shall not be used.", "Predictability.", "Critical", "Remove malloc/calloc/realloc/free and use static allocation"),
    ("D4.13", "MISRA_C_2012", "Advisory",  "Functions which are designed to provide operations on a resource should be called in an appropriate sequence.", "Resource management.", "Minor", None),
    ("D4.14", "MISRA_C_2012", "Required",  "The validity of values received from external sources shall be checked.", "Robustness.", "Major", None),

    # -----------------------------------------------------------------------
    # MISRA C:2012 — Rules Chapter 1 (Standard C environment)
    # -----------------------------------------------------------------------
    ("M1.1",  "MISRA_C_2012", "Required",  "The program shall contain no violations of the standard C syntax and constraints, and shall not exceed the implementation's translation limits.", "Correctness.", "Critical", None),
    ("M1.2",  "MISRA_C_2012", "Required",  "Language extensions should not be used.", "Portability.", "Major", None),
    ("M1.3",  "MISRA_C_2012", "Required",  "There shall be no occurrence of undefined or critical unspecified behaviour.", "Safety.", "Critical", None),
    ("M1.4",  "MISRA_C_2012", "Advisory",  "Emergent language features should not be used.", "Stability.", "Minor", None),

    # Chapter 2 — Unused code
    ("M2.1",  "MISRA_C_2012", "Required",  "A project shall not contain unreachable code.", "Dead code is a maintenance hazard.", "Major", "Remove unreachable code block"),
    ("M2.2",  "MISRA_C_2012", "Required",  "There shall be no dead code.", "Dead code is a maintenance hazard.", "Major", "Remove dead code"),
    ("M2.3",  "MISRA_C_2012", "Advisory",  "A project should not contain unused type declarations.", "Clean interfaces.", "Minor", "Remove unused type declaration"),
    ("M2.4",  "MISRA_C_2012", "Advisory",  "A project should not contain unused tag declarations.", "Clean interfaces.", "Minor", "Remove unused tag declaration"),
    ("M2.5",  "MISRA_C_2012", "Advisory",  "A project should not contain unused macro declarations.", "Clean interfaces.", "Minor", "Remove unused macro"),
    ("M2.6",  "MISRA_C_2012", "Advisory",  "A function should not contain unused label declarations.", "Clean interfaces.", "Minor", "Remove unused label"),
    ("M2.7",  "MISRA_C_2012", "Advisory",  "There should be no unused parameters in a function.", "Clean interfaces.", "Minor", "Mark parameter as (void) or remove it"),

    # Chapter 3 — Comments
    ("M3.1",  "MISRA_C_2012", "Required",  "The character sequences /* and // shall not be used within a comment.", "Avoid nested/unterminated comments.", "Major", "Remove nested comment markers"),
    ("M3.2",  "MISRA_C_2012", "Required",  "Line-splicing shall not be used in // comments.", "Portability.", "Major", None),

    # Chapter 4 — Character sets and lexical conventions
    ("M4.1",  "MISRA_C_2012", "Required",  "Octal and hexadecimal escape sequences shall be terminated.", "Avoid ambiguous escape sequences.", "Major", None),
    ("M4.2",  "MISRA_C_2012", "Advisory",  "Trigraphs should not be used.", "Readability.", "Minor", "Replace trigraph with equivalent character"),

    # Chapter 5 — Identifiers
    ("M5.1",  "MISRA_C_2012", "Required",  "External identifiers shall be distinct.", "Link-time correctness.", "Critical", None),
    ("M5.2",  "MISRA_C_2012", "Required",  "Identifiers declared in the same scope and name space shall be distinct.", "Correctness.", "Critical", None),
    ("M5.3",  "MISRA_C_2012", "Required",  "An identifier declared in an inner scope shall not hide an identifier declared in an outer scope.", "Avoid confusion.", "Major", "Rename inner identifier to avoid shadowing"),
    ("M5.4",  "MISRA_C_2012", "Required",  "Macro identifiers shall be distinct.", "Preprocessing correctness.", "Major", None),
    ("M5.5",  "MISRA_C_2012", "Required",  "Identifiers shall be distinct from macro names.", "Preprocessing correctness.", "Major", None),
    ("M5.6",  "MISRA_C_2012", "Required",  "A typedef name shall be a unique identifier.", "Type correctness.", "Major", None),
    ("M5.7",  "MISRA_C_2012", "Required",  "A tag name shall be a unique identifier.", "Type correctness.", "Major", None),
    ("M5.8",  "MISRA_C_2012", "Required",  "Identifiers that define objects or functions with external linkage shall be unique in the file scope.", "Link-time safety.", "Major", None),
    ("M5.9",  "MISRA_C_2012", "Advisory",  "Identifiers that define objects or functions with internal linkage should be unique.", "Readability.", "Minor", None),

    # Chapter 6 — Types
    ("M6.1",  "MISRA_C_2012", "Required",  "Bit-fields shall only be declared with an explicitly signed or unsigned integer type.", "Portability.", "Major", None),
    ("M6.2",  "MISRA_C_2012", "Required",  "Single-bit named bit fields shall not be of a signed integer type.", "Correctness.", "Major", None),

    # Chapter 7 — Literals and constants
    ("M7.1",  "MISRA_C_2012", "Required",  "Octal constants shall not be used.", "Readability.", "Major", "Replace octal literal with decimal or hex equivalent"),
    ("M7.2",  "MISRA_C_2012", "Required",  "A u or U suffix shall be applied to all integer constants that are represented in an unsigned type.", "Type correctness.", "Major", "Add U suffix to unsigned integer constant"),
    ("M7.3",  "MISRA_C_2012", "Required",  "The lowercase character l shall not be used as a suffix.", "Readability (l looks like 1).", "Major", "Replace l suffix with L"),
    ("M7.4",  "MISRA_C_2012", "Required",  "A string literal shall not be assigned to an object unless the object's type is pointer to const-qualified char.", "Correctness.", "Major", None),

    # Chapter 8 — Declarations and definitions
    ("M8.1",  "MISRA_C_2012", "Required",  "Types shall be explicitly specified.", "Explicit typing.", "Major", None),
    ("M8.2",  "MISRA_C_2012", "Required",  "Function types shall be in prototype form with named parameters.", "Correctness.", "Major", None),
    ("M8.3",  "MISRA_C_2012", "Required",  "All declarations of an object or function shall use the same names and type qualifiers.", "Consistency.", "Major", None),
    ("M8.4",  "MISRA_C_2012", "Required",  "A compatible declaration shall be visible when an object or function with external linkage is defined.", "Correctness.", "Major", None),
    ("M8.5",  "MISRA_C_2012", "Required",  "An external object or function shall be declared once in one and only one file.", "Correctness.", "Major", None),
    ("M8.6",  "MISRA_C_2012", "Required",  "An identifier with external linkage shall have exactly one external definition.", "ODR.", "Critical", None),
    ("M8.7",  "MISRA_C_2012", "Advisory",  "Functions and objects should not be defined with external linkage if they are referenced in only one translation unit.", "Encapsulation.", "Minor", "Add static keyword to limit linkage"),
    ("M8.8",  "MISRA_C_2012", "Required",  "The static storage class specifier shall be used in all declarations of objects and functions that have internal linkage.", "Explicit linkage.", "Major", "Add static keyword"),
    ("M8.9",  "MISRA_C_2012", "Advisory",  "An object should be defined at block scope if its identifier only appears in a single function.", "Minimise scope.", "Minor", "Move object definition to block scope"),
    ("M8.10", "MISRA_C_2012", "Required",  "An inline function shall be declared with the static storage class.", "Correctness.", "Major", "Add static keyword to inline function"),
    ("M8.11", "MISRA_C_2012", "Advisory",  "When an array with external linkage is declared, its size should be explicitly specified.", "Explicitness.", "Minor", None),
    ("M8.12", "MISRA_C_2012", "Required",  "Within an enumerator list, the value of an implicitly-specified enumeration constant shall be unique.", "Correctness.", "Major", None),
    ("M8.13", "MISRA_C_2012", "Advisory",  "A pointer should point to a const-qualified type whenever possible.", "Const-correctness.", "Minor", "Add const qualifier to pointed-to type"),
    ("M8.14", "MISRA_C_2012", "Required",  "The restrict type qualifier shall not be used.", "Portability.", "Major", "Remove restrict qualifier"),

    # Chapter 9 — Initialisation
    ("M9.1",  "MISRA_C_2012", "Mandatory", "The value of an object with automatic storage duration shall not be read before it has been set.", "Undefined behaviour.", "Critical", None),
    ("M9.2",  "MISRA_C_2012", "Required",  "The initializer for an aggregate or union shall be enclosed in braces.", "Explicitness.", "Major", "Enclose initializer in braces"),
    ("M9.3",  "MISRA_C_2012", "Required",  "Arrays shall not be partially initialised.", "Correctness.", "Major", None),
    ("M9.4",  "MISRA_C_2012", "Required",  "An element of an object shall not be initialised more than once.", "Correctness.", "Major", None),
    ("M9.5",  "MISRA_C_2012", "Required",  "Where designated initialisers are used to initialise an array object the size of the array shall be specified explicitly.", "Explicitness.", "Major", None),

    # Chapter 10 — Essential type model
    ("M10.1", "MISRA_C_2012", "Required",  "Operands shall not be of an inappropriate essential type.", "Type safety.", "Major", None),
    ("M10.2", "MISRA_C_2012", "Required",  "Expressions of essentially character type shall not be used inappropriately in addition and subtraction operations.", "Correctness.", "Major", None),
    ("M10.3", "MISRA_C_2012", "Required",  "The value of an expression shall not be assigned to an object with a narrower essential type.", "Type safety.", "Major", None),
    ("M10.4", "MISRA_C_2012", "Required",  "Both operands of an operator in which the usual arithmetic conversions are performed shall have the same essential type category.", "Type safety.", "Major", None),
    ("M10.5", "MISRA_C_2012", "Advisory",  "The value of an expression should not be cast to an inappropriate essential type.", "Type safety.", "Minor", None),
    ("M10.6", "MISRA_C_2012", "Required",  "The value of a composite expression shall not be assigned to an object with wider essential type.", "Type safety.", "Major", "Cast composite expression before assignment"),
    ("M10.7", "MISRA_C_2012", "Required",  "If a composite expression is used as one operand of an operator in which the usual arithmetic conversions are performed then the other operand shall not have wider essential type.", "Type safety.", "Major", None),
    ("M10.8", "MISRA_C_2012", "Required",  "The value of a composite expression shall not be cast to a different essential type category or a wider essential type.", "Type safety.", "Major", None),

    # Chapter 11 — Pointer type conversions
    ("M11.1", "MISRA_C_2012", "Required",  "Conversions shall not be performed between a pointer to a function and any other type.", "Safety.", "Critical", None),
    ("M11.2", "MISRA_C_2012", "Required",  "Conversions shall not be performed between a pointer to an incomplete type and any other type.", "Safety.", "Major", None),
    ("M11.3", "MISRA_C_2012", "Required",  "A cast shall not be performed between a pointer to object type and a pointer to a different object type.", "Aliasing.", "Major", None),
    ("M11.4", "MISRA_C_2012", "Advisory",  "A conversion should not be performed between a pointer to object and an integer type.", "Portability.", "Minor", None),
    ("M11.5", "MISRA_C_2012", "Advisory",  "A conversion should not be performed from pointer to void into pointer to object.", "Type safety.", "Minor", None),
    ("M11.6", "MISRA_C_2012", "Required",  "A cast shall not be performed between pointer to void and an arithmetic type.", "Safety.", "Major", None),
    ("M11.7", "MISRA_C_2012", "Required",  "A cast shall not be performed between pointer to object and a non-integer arithmetic type.", "Safety.", "Major", None),
    ("M11.8", "MISRA_C_2012", "Required",  "A cast shall not remove any const or volatile qualification from the type pointed to by a pointer.", "Const-correctness.", "Major", None),
    ("M11.9", "MISRA_C_2012", "Required",  "The macro NULL shall be the only permitted form of integer null pointer constant.", "Correctness.", "Major", "Replace 0 integer null pointer with NULL"),

    # Chapter 12 — Side effects
    ("M12.1", "MISRA_C_2012", "Advisory",  "The precedence of operators within expressions should be made explicit.", "Readability.", "Minor", "Add explicit parentheses"),
    ("M12.2", "MISRA_C_2012", "Required",  "The right-hand operand of a shift operator shall lie in the range zero to one less than the width in bits of the essential type of the left-hand operand.", "Undefined behaviour.", "Critical", None),
    ("M12.3", "MISRA_C_2012", "Advisory",  "The comma operator should not be used.", "Readability.", "Minor", None),
    ("M12.4", "MISRA_C_2012", "Required",  "Evaluation of constant expressions should not lead to unsigned integer wrap-around.", "Correctness.", "Major", None),
    ("M12.5", "MISRA_C_2012", "Mandatory", "The sizeof operator shall not have an operand which is a function parameter declared as 'array of type'.", "Correctness.", "Critical", None),

    # Chapter 13 — Side effects
    ("M13.1", "MISRA_C_2012", "Required",  "Initializer lists shall not contain persistent side effects.", "Correctness.", "Major", None),
    ("M13.2", "MISRA_C_2012", "Required",  "The value of an expression and its persistent side effects shall be the same under all permitted evaluation orders.", "Correctness.", "Critical", None),
    ("M13.3", "MISRA_C_2012", "Advisory",  "A full expression containing an increment (++) or decrement (--) operator should have no other potential side effects.", "Readability.", "Minor", None),
    ("M13.4", "MISRA_C_2012", "Advisory",  "The result of an assignment operator should not be used.", "Readability.", "Minor", None),
    ("M13.5", "MISRA_C_2012", "Required",  "The right hand operand of a logical && or || operator shall not contain persistent side effects.", "Correctness.", "Major", None),
    ("M13.6", "MISRA_C_2012", "Mandatory", "The operand of the sizeof operator shall not contain any expression which has potential side effects.", "Correctness.", "Critical", None),

    # Chapter 14 — Control statement expressions
    ("M14.1", "MISRA_C_2012", "Required",  "A loop counter shall not have essentially floating type.", "Reliability.", "Major", None),
    ("M14.2", "MISRA_C_2012", "Required",  "A for loop shall be well-formed.", "Correctness.", "Major", None),
    ("M14.3", "MISRA_C_2012", "Required",  "Controlling expressions shall not be invariant.", "Detect dead branches.", "Major", "Remove invariant branch"),
    ("M14.4", "MISRA_C_2012", "Required",  "The controlling expression of an if statement and the controlling expression of an iteration-statement shall have essentially Boolean type.", "Correctness.", "Major", "Cast controlling expression to _Bool"),

    # Chapter 15 — Control flow
    ("M15.1", "MISRA_C_2012", "Advisory",  "The goto statement should not be used.", "Structured programming.", "Minor", None),
    ("M15.2", "MISRA_C_2012", "Required",  "The goto statement shall jump to a label declared later in the same function.", "Structured programming.", "Major", None),
    ("M15.3", "MISRA_C_2012", "Required",  "Any label referenced by a goto statement shall be declared in the same block, or in any block enclosing the goto statement.", "Structured programming.", "Major", None),
    ("M15.4", "MISRA_C_2012", "Advisory",  "There should be no more than one break or goto statement used to terminate any iteration statement.", "Structured programming.", "Minor", None),
    ("M15.5", "MISRA_C_2012", "Advisory",  "A function should have a single point of exit at the end.", "Structured programming.", "Minor", None),
    ("M15.6", "MISRA_C_2012", "Required",  "The body of an iteration-statement or a selection-statement shall be a compound statement.", "Readability/safety.", "Major", "Add braces around single-statement body"),
    ("M15.7", "MISRA_C_2012", "Required",  "All if...else if constructs shall be terminated with an else statement.", "Completeness.", "Major", "Add trailing else clause"),

    # Chapter 16 — Switch statements
    ("M16.1", "MISRA_C_2012", "Required",  "All switch statements shall be well-formed.", "Correctness.", "Major", None),
    ("M16.2", "MISRA_C_2012", "Required",  "A switch label shall only be used when the most closely-enclosing compound statement is the body of a switch statement.", "Correctness.", "Major", None),
    ("M16.3", "MISRA_C_2012", "Required",  "An unconditional break statement shall terminate every switch-clause.", "Fall-through prevention.", "Major", "Add break statement at end of switch clause"),
    ("M16.4", "MISRA_C_2012", "Required",  "Every switch statement shall have a default label.", "Completeness.", "Major", "Add default: clause to switch"),
    ("M16.5", "MISRA_C_2012", "Required",  "A default label shall appear as either the first or the last switch label of a switch statement.", "Readability.", "Major", "Move default: to last position in switch"),
    ("M16.6", "MISRA_C_2012", "Required",  "Every switch statement shall have at least two switch-clauses.", "Correctness.", "Major", None),
    ("M16.7", "MISRA_C_2012", "Required",  "A switch-expression shall not have essentially Boolean type.", "Correctness.", "Major", None),

    # Chapter 17 — Functions
    ("M17.1", "MISRA_C_2012", "Required",  "The features of <stdarg.h> shall not be used.", "Safety.", "Major", None),
    ("M17.2", "MISRA_C_2012", "Required",  "Functions shall not call themselves, either directly or indirectly.", "Predictable stack usage.", "Critical", None),
    ("M17.3", "MISRA_C_2012", "Mandatory", "A function shall not be declared implicitly.", "Correctness.", "Critical", None),
    ("M17.4", "MISRA_C_2012", "Mandatory", "All exit paths from a function with non-void return type shall have an explicit return statement with an expression.", "Correctness.", "Critical", None),
    ("M17.5", "MISRA_C_2012", "Advisory",  "The function argument corresponding to a parameter declared to have an array type shall have an appropriate number of elements.", "Correctness.", "Minor", None),
    ("M17.6", "MISRA_C_2012", "Mandatory", "The declaration of an array parameter shall not contain the static keyword between the [ ].", "Portability.", "Major", None),
    ("M17.7", "MISRA_C_2012", "Required",  "The value returned by a function having non-void return type shall be used.", "Reliability.", "Major", "Cast return value to (void) if intentionally discarded"),
    ("M17.8", "MISRA_C_2012", "Advisory",  "A function parameter should not be modified.", "Clarity.", "Minor", None),

    # Chapter 18 — Pointers and arrays
    ("M18.1", "MISRA_C_2012", "Required",  "A pointer resulting from arithmetic on a pointer operand shall address an element of the same array as that pointer operand.", "Safety.", "Critical", None),
    ("M18.2", "MISRA_C_2012", "Required",  "Subtraction between pointers shall only be applied to pointers that address elements of the same array.", "Safety.", "Critical", None),
    ("M18.3", "MISRA_C_2012", "Required",  "The relational operators >, >=, < and <= shall not be applied to objects of pointer type except where they point into the same object.", "Safety.", "Critical", None),
    ("M18.4", "MISRA_C_2012", "Advisory",  "The +, -, += and -= operators should not be applied to an expression of pointer type.", "Safety.", "Minor", None),
    ("M18.5", "MISRA_C_2012", "Advisory",  "Declarations should contain no more than two levels of pointer nesting.", "Readability.", "Minor", None),
    ("M18.6", "MISRA_C_2012", "Required",  "The address of an object with automatic storage shall not be copied to another object that persists after the first object has ceased to exist.", "Dangling pointer.", "Critical", None),
    ("M18.7", "MISRA_C_2012", "Required",  "Flexible array members shall not be declared.", "Portability.", "Major", None),
    ("M18.8", "MISRA_C_2012", "Required",  "Variable-length array types shall not be used.", "Predictable stack usage.", "Major", "Replace VLA with fixed-size array"),

    # Chapter 19 — Overlapping storage
    ("M19.1", "MISRA_C_2012", "Mandatory", "An object shall not be assigned or copied to an overlapping object.", "Correctness.", "Critical", None),
    ("M19.2", "MISRA_C_2012", "Advisory",  "The union keyword should not be used.", "Portability.", "Minor", None),

    # Chapter 20 — Preprocessing directives
    ("M20.1", "MISRA_C_2012", "Advisory",  "#include directives should only be preceded by preprocessor directives or comments.", "Readability.", "Minor", None),
    ("M20.2", "MISRA_C_2012", "Required",  "The ', \" or \\ characters and the /* or // character sequences shall not occur in a header file name.", "Portability.", "Major", None),
    ("M20.3", "MISRA_C_2012", "Required",  "The #include directive shall be followed by either a <filename> or \"filename\" sequence.", "Correctness.", "Major", None),
    ("M20.4", "MISRA_C_2012", "Required",  "A macro shall not be defined with the same name as a keyword.", "Correctness.", "Critical", None),
    ("M20.5", "MISRA_C_2012", "Advisory",  "#undef should not be used.", "Maintainability.", "Minor", None),
    ("M20.6", "MISRA_C_2012", "Required",  "Tokens that look like a preprocessing directive shall not occur within a macro argument.", "Correctness.", "Major", None),
    ("M20.7", "MISRA_C_2012", "Required",  "Expressions resulting from the expansion of macro parameters shall be enclosed in parentheses.", "Correctness.", "Major", "Enclose macro parameter in parentheses"),
    ("M20.8", "MISRA_C_2012", "Required",  "The controlling expression of a #if or #elif preprocessing directive shall evaluate to 0 or 1.", "Correctness.", "Major", None),
    ("M20.9", "MISRA_C_2012", "Required",  "All identifiers used in the controlling expression of #if or #elif preprocessing directives shall be #define'd before evaluation.", "Correctness.", "Major", None),
    ("M20.10", "MISRA_C_2012", "Advisory", "The # and ## preprocessor operators should not be used.", "Readability.", "Minor", None),
    ("M20.11", "MISRA_C_2012", "Required",  "A macro parameter immediately following a # operator shall not immediately be followed by a ## operator.", "Correctness.", "Major", None),
    ("M20.12", "MISRA_C_2012", "Required",  "A macro parameter used as an operand to the # or ## operators, which is itself subject to further macro replacement, shall only be used as an operand to these operators.", "Correctness.", "Major", None),
    ("M20.13", "MISRA_C_2012", "Required",  "A line whose first token is # shall be a valid preprocessing directive.", "Correctness.", "Major", None),
    ("M20.14", "MISRA_C_2012", "Required",  "All #else, #elif and #endif preprocessor directives shall reside in the same file as the #if, #ifdef or #ifndef directive to which they are related.", "Correctness.", "Major", None),

    # Chapter 21 — Standard libraries
    ("M21.1", "MISRA_C_2012", "Required",  "#define and #undef shall not be used on a reserved identifier or reserved macro name.", "Correctness.", "Critical", None),
    ("M21.2", "MISRA_C_2012", "Required",  "A reserved identifier or macro name shall not be declared.", "Correctness.", "Critical", None),
    ("M21.3", "MISRA_C_2012", "Required",  "The memory allocation and deallocation functions of <stdlib.h> shall not be used.", "Safety.", "Critical", "Replace dynamic allocation with static allocation"),
    ("M21.4", "MISRA_C_2012", "Required",  "The standard header file <setjmp.h> shall not be used.", "Safety.", "Critical", None),
    ("M21.5", "MISRA_C_2012", "Required",  "The standard header file <signal.h> shall not be used.", "Safety.", "Critical", None),
    ("M21.6", "MISRA_C_2012", "Required",  "The Standard Library input/output functions shall not be used in production code.", "Safety.", "Major", "Remove printf/scanf usage from production code"),
    ("M21.7", "MISRA_C_2012", "Required",  "The atof, atoi, atol and atoll functions of <stdlib.h> shall not be used.", "Safety.", "Major", "Replace atoi/atol/atof with strtol/strtod equivalents"),
    ("M21.8", "MISRA_C_2012", "Required",  "The library functions abort, exit, getenv and system of <stdlib.h> shall not be used.", "Safety.", "Critical", None),
    ("M21.9", "MISRA_C_2012", "Required",  "The library functions bsearch and qsort of <stdlib.h> shall not be used.", "Safety.", "Major", None),
    ("M21.10", "MISRA_C_2012", "Required", "The Standard Library time and date functions shall not be used.", "Safety.", "Major", None),
    ("M21.11", "MISRA_C_2012", "Required", "The standard header file <tgmath.h> shall not be used.", "Safety.", "Major", None),
    ("M21.12", "MISRA_C_2012", "Advisory", "The exception handling features of <fenv.h> should not be used.", "Safety.", "Minor", None),

    # Chapter 22 — Resources
    ("M22.1", "MISRA_C_2012", "Required",  "All resources obtained dynamically by means of Standard Library functions shall be explicitly released.", "Resource leaks.", "Critical", "Add corresponding free/close for each dynamic acquisition"),
    ("M22.2", "MISRA_C_2012", "Mandatory", "A block of memory shall only be freed if it was allocated by means of a Standard Library function.", "Safety.", "Critical", None),
    ("M22.3", "MISRA_C_2012", "Required",  "The same file shall not be open for read and write access at the same time in different streams.", "Correctness.", "Major", None),
    ("M22.4", "MISRA_C_2012", "Mandatory", "There shall be no attempt to write to a stream which has been opened as read-only.", "Correctness.", "Critical", None),
    ("M22.5", "MISRA_C_2012", "Mandatory", "A pointer to a FILE object shall not be dereferenced.", "Safety.", "Critical", None),
    ("M22.6", "MISRA_C_2012", "Mandatory", "The value of a pointer to a FILE shall not be used after the associated stream has been closed.", "Dangling pointer.", "Critical", None),
    ("M22.7", "MISRA_C_2012", "Required",  "The macro EOF shall only be compared with the unmodified return value from fgetc, fputc, getc, getchar, putc, putchar, or ungetc.", "Correctness.", "Major", None),
    ("M22.8", "MISRA_C_2012", "Required",  "The value of errno shall be set to zero prior to a call to an errno-setting function.", "Reliability.", "Major", "Set errno=0 before errno-setting call"),
    ("M22.9", "MISRA_C_2012", "Required",  "The value of errno shall be tested against zero after calling an errno-setting function.", "Reliability.", "Major", "Check errno after errno-setting call"),
    ("M22.10", "MISRA_C_2012", "Required", "The value of errno shall only be tested when the last function to be called was an errno-setting function.", "Reliability.", "Major", None),

    # -----------------------------------------------------------------------
    # AUTOSAR C++14 Guidelines (representative set)
    # -----------------------------------------------------------------------
    # A0 — General
    ("A0-1-1",  "AUTOSAR_CPP14", "Required",  "A project shall not contain instances of non-volatile variables being given values that are never subsequently used.", "Dead assignments waste memory and confuse readers.", "Major", "Remove unused variable assignment"),
    ("A0-1-2",  "AUTOSAR_CPP14", "Required",  "The value returned by a function having a non-void return type that is not an overloaded operator shall be used.", "Unused return values may hide errors.", "Major", "Capture or cast return value to void"),
    ("A0-1-3",  "AUTOSAR_CPP14", "Advisory",  "Every function defined in an anonymous namespace, or static function with internal linkage, or private function shall be used.", "Dead code.", "Minor", None),
    ("A0-1-4",  "AUTOSAR_CPP14", "Required",  "There shall be no unused named parameters in the set of parameters for a non-virtual function.", "Clarity.", "Minor", "Mark unused parameter with (void) cast or remove it"),
    ("A0-1-6",  "AUTOSAR_CPP14", "Advisory",  "There should be no unused type declarations.", "Dead code.", "Minor", None),
    ("A0-4-2",  "AUTOSAR_CPP14", "Required",  "Type long double shall not be used.", "Portability.", "Major", "Replace long double with double"),
    ("A1-1-1",  "AUTOSAR_CPP14", "Required",  "All code shall conform to ISO/IEC 14882:2014 - Programming Language C++ and shall not use deprecated features.", "Portability.", "Major", None),
    ("A1-1-2",  "AUTOSAR_CPP14", "Advisory",  "A warning level of the compilation process shall be set in compliance with project policies.", "Quality.", "Minor", None),
    ("A1-1-3",  "AUTOSAR_CPP14", "Required",  "An optimization option that disregards strict standard-compliance shall not be used.", "Correctness.", "Major", None),
    ("A1-2-1",  "AUTOSAR_CPP14", "Required",  "When using a compiler toolchain, the compiler, linker and any other tools shall each be configured to generate warnings or errors for any unsafe construct.", "Quality.", "Minor", None),
    ("A2-3-1",  "AUTOSAR_CPP14", "Required",  "Only those characters specified in the C++ Language Standard basic source character set shall be used in the source code.", "Portability.", "Minor", None),
    ("A2-5-1",  "AUTOSAR_CPP14", "Required",  "Trigraphs shall not be used.", "Readability.", "Minor", "Remove trigraph"),
    ("A2-5-2",  "AUTOSAR_CPP14", "Required",  "Digraphs shall not be used.", "Readability.", "Minor", "Replace digraph with equivalent token"),
    ("A2-7-1",  "AUTOSAR_CPP14", "Required",  "The character \\ shall not occur as a last character of a C++ comment.", "Avoid line-splicing in comments.", "Minor", None),
    ("A2-7-2",  "AUTOSAR_CPP14", "Required",  "Sections of code shall not be 'commented out'.", "Maintainability.", "Minor", None),
    ("A2-7-3",  "AUTOSAR_CPP14", "Advisory",  "All declarations of 'user-defined' type, object or function shall be followed by a comment providing design intent.", "Documentation.", "Minor", None),
    ("A2-10-1", "AUTOSAR_CPP14", "Required",  "An identifier declared in an inner scope shall not hide an identifier declared in an outer scope.", "Avoid confusion.", "Major", "Rename inner identifier"),
    ("A2-10-4", "AUTOSAR_CPP14", "Required",  "The identifier name of a non-member object with static storage duration or static function shall not be reused within a namespace.", "Clarity.", "Major", None),
    ("A2-10-6", "AUTOSAR_CPP14", "Required",  "A class or enumeration name shall not be hidden by a variable, function or enumerator declaration in the same or an inner scope.", "Clarity.", "Major", None),
    ("A2-11-1", "AUTOSAR_CPP14", "Required",  "Volatile keyword shall not be used.", "Portability.", "Major", None),
    ("A2-13-1", "AUTOSAR_CPP14", "Required",  "Only those escape sequences that are defined in ISO/IEC 14882:2014 shall be used.", "Portability.", "Major", None),
    ("A2-13-2", "AUTOSAR_CPP14", "Required",  "String literals with different encoding prefixes shall not be concatenated.", "Correctness.", "Major", None),
    ("A2-13-3", "AUTOSAR_CPP14", "Required",  "Type wchar_t shall not be used.", "Portability.", "Major", "Replace wchar_t with char16_t or char32_t"),
    ("A2-13-4", "AUTOSAR_CPP14", "Required",  "String literals shall not be assigned to non-const pointers.", "Const-correctness.", "Major", "Add const to pointer declaration"),
    ("A3-1-1",  "AUTOSAR_CPP14", "Required",  "It shall be possible to include any header file in multiple translation units without violating the ODR.", "Correctness.", "Major", "Add include guard or #pragma once"),
    ("A3-1-2",  "AUTOSAR_CPP14", "Required",  "Header files, that are defined locally in the project, shall have a file name extension of one of: \".h\", \".hpp\" or \".hxx\".", "Convention.", "Minor", None),
    ("A3-1-3",  "AUTOSAR_CPP14", "Advisory",  "Implementation files, that are defined locally in the project, should have a file name extension of \".cpp\".", "Convention.", "Minor", None),
    ("A3-3-1",  "AUTOSAR_CPP14", "Required",  "Objects or functions with external linkage (including members of named namespaces) shall be declared in a header file.", "ODR.", "Major", None),
    ("A3-3-2",  "AUTOSAR_CPP14", "Required",  "Static and thread-local objects shall be constant-initialized.", "Safety.", "Major", None),
    ("A3-9-1",  "AUTOSAR_CPP14", "Required",  "Fixed width integer types from <cstdint> shall be used instead of the basic numerical types.", "Portability.", "Major", "Replace int/long/short with int8_t/int16_t/int32_t etc."),
    ("A4-5-1",  "AUTOSAR_CPP14", "Required",  "Expressions with type enum or enum class shall not be used as operands to built-in and overloaded operators other than the subscript operator [].", "Type safety.", "Major", None),
    ("A4-7-1",  "AUTOSAR_CPP14", "Required",  "An integer expression shall not lead to data loss.", "Overflow prevention.", "Major", None),
    ("A4-10-1", "AUTOSAR_CPP14", "Required",  "Only nullptr literal shall be used as the null-pointer-constant.", "Clarity.", "Major", "Replace NULL or 0 null pointer with nullptr"),
    ("A5-0-2",  "AUTOSAR_CPP14", "Required",  "The condition of an if-statement and the condition of an iteration statement shall have type bool.", "Type safety.", "Major", "Cast condition to bool explicitly"),
    ("A5-0-3",  "AUTOSAR_CPP14", "Required",  "The declaration of objects shall contain no more than two levels of pointer indirection.", "Readability.", "Minor", None),
    ("A5-1-1",  "AUTOSAR_CPP14", "Required",  "Literal values shall not be used apart from type initialization, otherwise symbolic names shall be used instead.", "Maintainability.", "Minor", "Replace magic number with named constant"),
    ("A5-1-2",  "AUTOSAR_CPP14", "Required",  "Variables shall not be implicitly captured in a lambda expression.", "Clarity.", "Major", "Use explicit capture list in lambda"),
    ("A5-1-3",  "AUTOSAR_CPP14", "Required",  "Parameter list (possibly empty) shall be included in every lambda expression.", "Clarity.", "Minor", "Add () to lambda expression"),
    ("A5-1-4",  "AUTOSAR_CPP14", "Required",  "A lambda expression object shall not outlive any of its reference-captured objects.", "Safety.", "Critical", None),
    ("A5-1-6",  "AUTOSAR_CPP14", "Advisory",  "Return type of a non-void return type lambda expression should be explicitly specified.", "Clarity.", "Minor", None),
    ("A5-1-7",  "AUTOSAR_CPP14", "Required",  "A lambda shall not be an operand to decltype or typeid.", "Correctness.", "Major", None),
    ("A5-1-8",  "AUTOSAR_CPP14", "Advisory",  "Lambda expressions should not be defined inside another lambda expression.", "Readability.", "Minor", None),
    ("A5-1-9",  "AUTOSAR_CPP14", "Advisory",  "Identical unnamed lambda expressions shall be replaced with a named function or a named lambda expression.", "Maintainability.", "Minor", None),
    ("A5-2-1",  "AUTOSAR_CPP14", "Advisory",  "dynamic_cast should not be used.", "Design.", "Minor", None),
    ("A5-2-2",  "AUTOSAR_CPP14", "Required",  "Traditional C-style casts shall not be used.", "Type safety.", "Major", "Replace C-style cast with static_cast/reinterpret_cast/const_cast"),
    ("A5-2-3",  "AUTOSAR_CPP14", "Advisory",  "A cast shall not remove any const or volatile qualification from the type of a pointer or reference.", "Const-correctness.", "Minor", None),
    ("A5-2-4",  "AUTOSAR_CPP14", "Required",  "reinterpret_cast shall not be used.", "Type safety.", "Major", None),
    ("A5-2-5",  "AUTOSAR_CPP14", "Required",  "An array or container shall not be accessed beyond its range.", "Safety.", "Critical", None),
    ("A5-2-6",  "AUTOSAR_CPP14", "Required",  "The operands of a logical && or || shall be parenthesized if the operands contain binary operators.", "Readability.", "Minor", "Add parentheses around operands"),
    ("A5-3-1",  "AUTOSAR_CPP14", "Required",  "Evaluation of the operand to the typeid operator shall not contain side-effects.", "Correctness.", "Major", None),
    ("A5-3-2",  "AUTOSAR_CPP14", "Required",  "Null pointers shall not be dereferenced.", "Safety.", "Critical", "Add null pointer check before dereference"),
    ("A5-3-3",  "AUTOSAR_CPP14", "Required",  "Pointers to completed type shall not be deleted without first being checked for a null pointer value.", "Safety.", "Major", "Add null check before delete"),
    ("A5-5-1",  "AUTOSAR_CPP14", "Required",  "A pointer to member shall not access non-existent class members.", "Safety.", "Critical", None),
    ("A5-6-1",  "AUTOSAR_CPP14", "Required",  "The right hand operand of the integer division or remainder operators shall not be equal to zero.", "Divide-by-zero prevention.", "Critical", "Add divisor-not-zero guard"),
    ("A5-8-1",  "AUTOSAR_CPP14", "Required",  "An object with potential non-volatile side effects shall not be used in an expression if it is not used.", "Correctness.", "Major", None),
    ("A5-10-1", "AUTOSAR_CPP14", "Required",  "A pointer to member virtual function shall only be called on a valid virtual member function.", "Safety.", "Critical", None),
    ("A6-2-1",  "AUTOSAR_CPP14", "Required",  "Move and copy assignment operators shall handle self-assignment.", "Correctness.", "Major", "Add self-assignment guard in operator="),
    ("A6-2-2",  "AUTOSAR_CPP14", "Required",  "Expression statements shall not be explicit calls to constructors of temporary objects.", "Clarity.", "Minor", None),
    ("A6-4-1",  "AUTOSAR_CPP14", "Required",  "A switch statement shall have at least two case labels, distinct from the default label.", "Correctness.", "Major", None),
    ("A6-5-1",  "AUTOSAR_CPP14", "Advisory",  "A for-loop that loops through all elements of the container and does not use its loop-counter shall be replaced by a range-based for-loop.", "Modern C++.", "Minor", "Convert to range-based for loop"),
    ("A6-5-2",  "AUTOSAR_CPP14", "Required",  "A for loop shall contain a single loop-counter which shall not have floating-point type.", "Correctness.", "Major", None),
    ("A6-5-3",  "AUTOSAR_CPP14", "Advisory",  "Do statements should not be used.", "Readability.", "Minor", None),
    ("A6-5-4",  "AUTOSAR_CPP14", "Advisory",  "For-init-statement and expression should not perform actions other than loop-counter initialization and modification.", "Readability.", "Minor", None),
    ("A6-6-1",  "AUTOSAR_CPP14", "Required",  "The goto statement shall not be used.", "Structured programming.", "Major", None),
    ("A7-1-1",  "AUTOSAR_CPP14", "Required",  "Constexpr specifier shall be used for values that can be determined at compile time.", "Performance.", "Minor", "Replace const with constexpr where applicable"),
    ("A7-1-2",  "AUTOSAR_CPP14", "Required",  "The constexpr specifier shall be used for named constants.", "Performance.", "Minor", "Add constexpr"),
    ("A7-1-3",  "AUTOSAR_CPP14", "Required",  "CV-qualifiers shall be placed on the right hand side of the type that is a typedef or a using name.", "Consistency.", "Minor", None),
    ("A7-1-4",  "AUTOSAR_CPP14", "Required",  "The register keyword shall not be used.", "Portability (deprecated in C++17).", "Major", "Remove register keyword"),
    ("A7-1-5",  "AUTOSAR_CPP14", "Required",  "The auto specifier shall not be used apart from following cases: (1) to declare that a variable has the same type as return type of a function call, (2) to declare that a variable has the same type as initializer of non-fundamental type, (3) to declare parameters of a generic lambda expression, (4) to declare a function template using trailing return type syntax.", "Clarity.", "Minor", None),
    ("A7-1-6",  "AUTOSAR_CPP14", "Required",  "The typedef specifier shall not be used.", "Modern C++ — use using instead.", "Minor", "Replace typedef with using alias"),
    ("A7-1-7",  "AUTOSAR_CPP14", "Required",  "Each expression statement and identifier declaration shall be placed on a separate line.", "Readability.", "Minor", None),
    ("A7-1-8",  "AUTOSAR_CPP14", "Required",  "A non-type specifier shall be placed before a type specifier in a declaration.", "Consistency.", "Minor", None),
    ("A7-2-1",  "AUTOSAR_CPP14", "Required",  "An expression with enum underlying type shall only have values corresponding to the enumerators of the enumeration.", "Type safety.", "Major", None),
    ("A7-2-2",  "AUTOSAR_CPP14", "Required",  "Enumeration underlying base type shall be explicitly defined.", "Portability.", "Major", "Add explicit underlying type to enum"),
    ("A7-2-3",  "AUTOSAR_CPP14", "Required",  "Enumerations shall be declared as scoped enum classes.", "Type safety.", "Major", "Replace enum with enum class"),
    ("A7-2-4",  "AUTOSAR_CPP14", "Required",  "In an enumeration, either (1) none, (2) the first, or (3) all enumerators shall be initialised.", "Correctness.", "Major", None),
    ("A7-3-1",  "AUTOSAR_CPP14", "Required",  "All overloads of a function shall be visible from the point of call.", "Correctness.", "Major", None),
    ("A7-4-1",  "AUTOSAR_CPP14", "Required",  "The asm declaration shall not be used.", "Portability.", "Major", None),
    ("A7-5-1",  "AUTOSAR_CPP14", "Required",  "A function shall not return a reference or a pointer to a local variable.", "Dangling reference/pointer.", "Critical", None),
    ("A7-5-2",  "AUTOSAR_CPP14", "Required",  "Functions shall not call themselves, either directly or indirectly.", "Stack overflow.", "Critical", None),
    ("A7-6-1",  "AUTOSAR_CPP14", "Required",  "Functions declared with the [[noreturn]] attribute shall not return.", "Correctness.", "Critical", None),
    ("A8-2-1",  "AUTOSAR_CPP14", "Required",  "When declaring function templates, the trailing return type syntax shall be used if the return type depends on the type of parameters.", "Clarity.", "Minor", None),
    ("A8-4-1",  "AUTOSAR_CPP14", "Required",  "Functions shall not be defined using the ellipsis notation.", "Safety.", "Major", "Replace variadic function with template or overload set"),
    ("A8-4-2",  "AUTOSAR_CPP14", "Required",  "All exit paths from a function with non-void return type shall have an explicit return statement with an expression.", "Correctness.", "Critical", "Add explicit return at all exit paths"),
    ("A8-4-4",  "AUTOSAR_CPP14", "Required",  "Multiple output values from a function shall be returned as a struct or tuple.", "Clarity.", "Minor", None),
    ("A8-4-5",  "AUTOSAR_CPP14", "Required",  "\"consume\" parameters declared as X && shall always be moved from.", "Correctness.", "Major", None),
    ("A8-4-6",  "AUTOSAR_CPP14", "Required",  "\"forward\" parameters declared as T && shall always be forwarded.", "Correctness.", "Major", None),
    ("A8-4-7",  "AUTOSAR_CPP14", "Required",  "\"in\" parameters for \"cheap to copy\" types shall be passed by value.", "Performance.", "Minor", None),
    ("A8-4-8",  "AUTOSAR_CPP14", "Required",  "Output parameters shall not be used.", "Clarity.", "Minor", None),
    ("A8-4-9",  "AUTOSAR_CPP14", "Required",  "\"in-out\" parameters declared as T & shall be labeled accordingly.", "Clarity.", "Minor", None),
    ("A8-4-10", "AUTOSAR_CPP14", "Advisory",  "Parameter over alignment should be avoided.", "Performance.", "Minor", None),
    ("A8-4-11", "AUTOSAR_CPP14", "Required",  "A smart pointer shall only be used to represent ownership.", "Clarity.", "Minor", None),
    ("A8-4-12", "AUTOSAR_CPP14", "Required",  "A std::unique_ptr shall be used to represent exclusive ownership.", "Clarity.", "Minor", None),
    ("A8-4-13", "AUTOSAR_CPP14", "Required",  "A std::shared_ptr shall be used to represent shared ownership.", "Clarity.", "Minor", None),
    ("A8-4-14", "AUTOSAR_CPP14", "Advisory",  "Interfaces shall be precisely and strongly typed.", "Type safety.", "Minor", None),
    ("A9-3-1",  "AUTOSAR_CPP14", "Required",  "Member functions shall not return non-const handles to class-data.", "Encapsulation.", "Major", None),
    ("A9-5-1",  "AUTOSAR_CPP14", "Required",  "Unions shall not be used.", "Portability.", "Major", None),
    ("A9-6-1",  "AUTOSAR_CPP14", "Required",  "Data types used for interfacing with hardware or conforming to communication protocols shall be trivial, standard-layout and only contain members of types with defined sizes.", "Safety.", "Major", None),
    ("A10-1-1", "AUTOSAR_CPP14", "Required",  "Class shall not be derived from more than one base class which is not an interface class.", "Design.", "Major", None),
    ("A10-2-1", "AUTOSAR_CPP14", "Required",  "Non-virtual public or protected member functions shall not be redefined in derived classes.", "LSP.", "Critical", None),
    ("A10-3-1", "AUTOSAR_CPP14", "Required",  "Virtual function declaration shall contain exactly one of the three specifiers: (1) virtual, (2) override, (3) final.", "Clarity.", "Major", "Add override or final to virtual function override"),
    ("A10-3-2", "AUTOSAR_CPP14", "Required",  "Each overriding virtual function shall be declared with the override or final specifier.", "Clarity.", "Major", "Add override specifier"),
    ("A10-3-3", "AUTOSAR_CPP14", "Required",  "Virtual functions shall not be introduced in a final class.", "Correctness.", "Major", None),
    ("A10-3-5", "AUTOSAR_CPP14", "Required",  "A user-defined assignment operator shall not be virtual.", "Design.", "Major", None),
    ("A10-4-1", "AUTOSAR_CPP14", "Required",  "Hierarchies shall be based on interface classes.", "Design.", "Minor", None),
    ("A11-0-1", "AUTOSAR_CPP14", "Required",  "A non-POD type should be defined as class.", "Consistency.", "Minor", "Change struct to class"),
    ("A11-0-2", "AUTOSAR_CPP14", "Advisory",  "A type defined as struct shall: (1) provide only public data members, (2) not provide any special member functions or methods, (3) not be a base of another struct or class, (4) not inherit from another struct or class.", "Consistency.", "Minor", None),
    ("A11-3-1", "AUTOSAR_CPP14", "Required",  "Friend declarations shall not be used.", "Encapsulation.", "Major", None),
    ("A12-0-1", "AUTOSAR_CPP14", "Required",  "If a class declares a copy or move operation, or a destructor, via =default, =delete, or via a user-provided declaration, then all others of the five special member functions shall be declared as well.", "Rule of Five.", "Major", "Implement all five special member functions"),
    ("A12-1-1", "AUTOSAR_CPP14", "Required",  "An object's dynamic type shall not be used from the body of its constructor or destructor.", "Undefined behaviour.", "Critical", None),
    ("A12-1-2", "AUTOSAR_CPP14", "Advisory",  "Both NSDMI and a non-static member initializer in a constructor shall not be used in the same type.", "Consistency.", "Minor", None),
    ("A12-1-3", "AUTOSAR_CPP14", "Required",  "If all user-defined constructors of a class initialize data members with constant values that are the same across all constructors, then data members shall be initialized using NSDMI instead.", "DRY.", "Minor", None),
    ("A12-1-4", "AUTOSAR_CPP14", "Required",  "All constructors that are callable with a single argument of fundamental type shall be declared explicit.", "Prevent implicit conversions.", "Major", "Add explicit keyword to constructor"),
    ("A12-1-5", "AUTOSAR_CPP14", "Required",  "Common class initialization for non-constant members shall be done by a delegating constructor.", "DRY.", "Minor", None),
    ("A12-1-6", "AUTOSAR_CPP14", "Required",  "Derived classes that do not need further explicit initialization and require all the constructors from a base class shall use inheriting constructors.", "DRY.", "Minor", None),
    ("A12-4-1", "AUTOSAR_CPP14", "Required",  "Destructor of a base class shall be public virtual, public override or protected non-virtual.", "Correct destruction.", "Critical", "Add virtual to base class destructor"),
    ("A12-6-1", "AUTOSAR_CPP14", "Required",  "All class data members that are initialized by the constructor shall be initialized using member initializers.", "Correctness.", "Major", None),
    ("A12-7-1", "AUTOSAR_CPP14", "Advisory",  "If the behavior of a user-defined special member function is identical to implicitly defined function, then it should be defined '=default' or be left undefined.", "Clarity.", "Minor", None),
    ("A12-8-1", "AUTOSAR_CPP14", "Required",  "Move and copy constructors shall move and respectively copy base classes and data members of a class, without any side effects.", "Correctness.", "Major", None),
    ("A12-8-3", "AUTOSAR_CPP14", "Required",  "Moved-from object shall not be read-accessed.", "Safety.", "Critical", None),
    ("A12-8-4", "AUTOSAR_CPP14", "Required",  "Move constructor shall not initialize its class members and base classes using copy semantics.", "Performance.", "Minor", None),
    ("A12-8-5", "AUTOSAR_CPP14", "Required",  "A copy assignment operator shall handle self-assignment.", "Correctness.", "Major", "Add self-assignment guard"),
    ("A12-8-6", "AUTOSAR_CPP14", "Advisory",  "Copy and move constructors and copy assignment and move assignment operators shall be declared protected or defined =delete in base class.", "Design.", "Minor", None),
    ("A12-8-7", "AUTOSAR_CPP14", "Advisory",  "Assignment operators should be declared with the ref-qualifier &.", "Clarity.", "Minor", None),
    ("A13-1-2", "AUTOSAR_CPP14", "Required",  "User defined suffixes of the user defined literal operators shall start with underscore followed by one or more letters.", "Convention.", "Minor", None),
    ("A13-1-3", "AUTOSAR_CPP14", "Required",  "User defined literals shall only be used if the literal operator is declared in the current or enclosing scope.", "Correctness.", "Major", None),
    ("A13-2-1", "AUTOSAR_CPP14", "Required",  "An assignment expression shall have the same value category as its left operand.", "Correctness.", "Major", None),
    ("A13-2-2", "AUTOSAR_CPP14", "Required",  "A binary arithmetic operator and a bitwise operator shall return a 'prvalue'.", "Correctness.", "Major", None),
    ("A13-2-3", "AUTOSAR_CPP14", "Required",  "A relational operator shall return a boolean value.", "Correctness.", "Major", None),
    ("A13-3-1", "AUTOSAR_CPP14", "Required",  "A function that contains \"forwarding reference\" as its argument shall not be overloaded.", "Correctness.", "Major", None),
    ("A13-5-1", "AUTOSAR_CPP14", "Required",  "If \"operator[]\" is to be overloaded with a non-const version, const version shall also be implemented.", "Correctness.", "Major", None),
    ("A13-5-2", "AUTOSAR_CPP14", "Required",  "All user-defined conversion operators shall be defined explicit.", "Safety.", "Major", "Add explicit to conversion operator"),
    ("A13-5-3", "AUTOSAR_CPP14", "Advisory",  "User-defined conversion operators should not be used.", "Clarity.", "Minor", None),
    ("A13-5-4", "AUTOSAR_CPP14", "Required",  "If two opposite operators are defined, one shall be defined in terms of the other.", "Consistency.", "Minor", None),
    ("A13-5-5", "AUTOSAR_CPP14", "Required",  "Comparison operators shall be non-member functions with identical parameter types and noexcept.", "Correctness.", "Major", None),
    ("A14-1-1", "AUTOSAR_CPP14", "Advisory",  "A template should check if a specific operator is needed.", "Correctness.", "Minor", None),
    ("A14-5-1", "AUTOSAR_CPP14", "Required",  "A template constructor shall not participate in overload resolution for a copy/move constructor.", "Correctness.", "Major", None),
    ("A14-5-2", "AUTOSAR_CPP14", "Advisory",  "Class members that are not dependent on template type parameters should be defined in a separate base class.", "Design.", "Minor", None),
    ("A14-5-3", "AUTOSAR_CPP14", "Required",  "A non-member generic operator shall only be declared in a namespace that does not contain class (struct) type declarations.", "Correctness.", "Major", None),
    ("A14-7-1", "AUTOSAR_CPP14", "Required",  "A type used as a template argument shall meet the requirements of the template.", "Correctness.", "Critical", None),
    ("A14-7-2", "AUTOSAR_CPP14", "Required",  "Template specialization shall be declared in the same file (1) as the primary template, (2) as a user-defined type, for which the specialization is created.", "Correctness.", "Major", None),
    ("A14-8-2", "AUTOSAR_CPP14", "Required",  "Explicit specializations of function templates shall not be used.", "Design.", "Major", None),
    ("A15-0-1", "AUTOSAR_CPP14", "Required",  "A function shall not exit with an exception if it is able to perform a valid return.", "Safety.", "Major", None),
    ("A15-0-2", "AUTOSAR_CPP14", "Advisory",  "Exception safety guarantee of a called function shall be considered.", "Robustness.", "Minor", None),
    ("A15-1-1", "AUTOSAR_CPP14", "Advisory",  "Only instances of types derived from std::exception should be thrown.", "Convention.", "Minor", None),
    ("A15-1-2", "AUTOSAR_CPP14", "Required",  "An exception object shall not be a pointer.", "Safety.", "Major", None),
    ("A15-1-3", "AUTOSAR_CPP14", "Advisory",  "All thrown exceptions should be unique.", "Clarity.", "Minor", None),
    ("A15-1-4", "AUTOSAR_CPP14", "Advisory",  "If a function is declared to be noexcept, noexcept(true) or noexcept(<true condition>), then all functions called within this function, its sub-functions and lambda expressions shall be non-throwing too.", "Safety.", "Minor", None),
    ("A15-2-1", "AUTOSAR_CPP14", "Required",  "Constructors that are not noexcept shall not be invoked before program startup.", "Safety.", "Critical", None),
    ("A15-2-2", "AUTOSAR_CPP14", "Required",  "If a constructor is not noexcept and the constructor cannot finish object initialization due to allocation failure, it shall indicate failure by throwing an exception.", "Reliability.", "Major", None),
    ("A15-3-3", "AUTOSAR_CPP14", "Required",  "Main function and a task main function shall catch at least: base class exceptions from all third-party libraries used, std::exception and all otherwise unhandled exceptions.", "Robustness.", "Major", None),
    ("A15-3-4", "AUTOSAR_CPP14", "Required",  "Catch-all (ellipsis and std::exception) handlers shall be used only in (a) main, (b) task main functions, (c) in functions that are supposed to isolate independent components and (d) when calling third-party code that uses exceptions not according to AUTOSAR C++14 guidelines.", "Robustness.", "Major", None),
    ("A15-3-5", "AUTOSAR_CPP14", "Required",  "A class type exception shall be caught by reference or const reference.", "Correctness.", "Major", "Change catch(ExType e) to catch(ExType const& e)"),
    ("A15-4-1", "AUTOSAR_CPP14", "Required",  "Dynamic exception-specification shall not be used.", "Deprecated.", "Major", "Replace throw(...) with noexcept or noexcept(false)"),
    ("A15-4-2", "AUTOSAR_CPP14", "Required",  "If a function is declared to be noexcept, noexcept(true), it shall not exit with an exception.", "Safety.", "Critical", None),
    ("A15-4-3", "AUTOSAR_CPP14", "Required",  "The noexcept specification of a function shall either be identical to, or stricter than, the noexcept specification of the overridden virtual function.", "Correctness.", "Major", None),
    ("A15-4-4", "AUTOSAR_CPP14", "Advisory",  "A declaration of non-throwing function shall contain noexcept specification.", "Clarity.", "Minor", "Add noexcept to non-throwing function"),
    ("A15-4-5", "AUTOSAR_CPP14", "Required",  "Checked exceptions that could be thrown from a function shall be specified together with the function declaration and they shall be identical in all function declarations and for all its overriders.", "Contract.", "Minor", None),
    ("A15-5-1", "AUTOSAR_CPP14", "Required",  "All user-provided class destructors, deallocation functions, move constructors, move assignment operators and swap functions shall not exit with an exception.", "Safety.", "Critical", "Add noexcept to destructor/move/swap"),
    ("A15-5-2", "AUTOSAR_CPP14", "Required",  "Program shall not be abruptly terminated. In particular, an implicit or explicit invocation of std::terminate(), std::abort(), std::exit() and std::quick_exit() shall not be done.", "Safety.", "Critical", None),
    ("A15-5-3", "AUTOSAR_CPP14", "Required",  "The std::terminate() function shall not be called implicitly.", "Safety.", "Critical", None),
    ("A16-0-1", "AUTOSAR_CPP14", "Required",  "The preprocessor shall only be used for unconditional and conditional file inclusion and include guards, and using the following directives: (1) #ifndef, #ifdef, (3) #if, (4) #if defined, (5) #elif, (6) #else, (7) #define, (8) #endif, (9) #include.", "Maintainability.", "Major", None),
    ("A16-2-1", "AUTOSAR_CPP14", "Required",  "The ', \" or \\ characters and the /* or // character sequences shall not occur in a header file name.", "Correctness.", "Major", None),
    ("A16-2-2", "AUTOSAR_CPP14", "Required",  "There shall be no unused include directives.", "Clarity.", "Minor", "Remove unused #include"),
    ("A16-6-1", "AUTOSAR_CPP14", "Required",  "#error directive shall not be used.", "Maintainability.", "Minor", None),
    ("A16-7-1", "AUTOSAR_CPP14", "Required",  "The #pragma directive shall not be used.", "Portability.", "Minor", "Replace #pragma once with include guard"),
    ("A17-0-1", "AUTOSAR_CPP14", "Required",  "Reserved identifiers, macros and functions in the C++ standard library shall not be defined, redefined or undefined.", "Correctness.", "Critical", None),
    ("A17-1-1", "AUTOSAR_CPP14", "Required",  "Use of the C Standard Library shall be encapsulated and isolated.", "Portability.", "Major", None),
    ("A18-0-1", "AUTOSAR_CPP14", "Required",  "The C library facilities shall only be accessed through C++ library headers.", "Portability.", "Major", None),
    ("A18-0-2", "AUTOSAR_CPP14", "Required",  "The error state of a conversion from string to a numeric value shall be checked.", "Reliability.", "Major", None),
    ("A18-0-3", "AUTOSAR_CPP14", "Required",  "The library <clocale> (locale.h) and the setlocale function shall not be used.", "Portability.", "Major", None),
    ("A18-1-1", "AUTOSAR_CPP14", "Required",  "C-style arrays shall not be used.", "Safety.", "Major", "Replace C array with std::array or std::vector"),
    ("A18-1-2", "AUTOSAR_CPP14", "Required",  "The std::vector<bool> specialization shall not be used.", "Correctness.", "Major", "Replace vector<bool> with vector<uint8_t> or bitset"),
    ("A18-1-3", "AUTOSAR_CPP14", "Required",  "The std::auto_ptr type shall not be used.", "Safety.", "Major", "Replace auto_ptr with unique_ptr"),
    ("A18-1-4", "AUTOSAR_CPP14", "Advisory",  "A pointer pointing to an element of an array of objects shall not be passed to a smart pointer of single object type.", "Safety.", "Minor", None),
    ("A18-1-6", "AUTOSAR_CPP14", "Required",  "All std::hash specializations for user-defined types shall have a noexcept function call operator.", "Correctness.", "Major", None),
    ("A18-5-1", "AUTOSAR_CPP14", "Required",  "Functions malloc, calloc, realloc and free shall not be used.", "Safety.", "Critical", "Replace with new/delete or smart pointers"),
    ("A18-5-2", "AUTOSAR_CPP14", "Required",  "Non-placement new or delete expressions shall not be used.", "Safety.", "Major", None),
    ("A18-5-3", "AUTOSAR_CPP14", "Required",  "The form of the delete expression shall match the form of the new expression used to allocate the memory.", "Safety.", "Critical", "Match delete[] with new[] and delete with new"),
    ("A18-5-4", "AUTOSAR_CPP14", "Advisory",  "If a project has a sized or unsized version of operator 'new' defined, both sized and unsized versions shall be defined.", "Completeness.", "Minor", None),
    ("A18-5-5", "AUTOSAR_CPP14", "Required",  "Memory management functions shall ensure the following: (a) deterministic behavior resulting with the existence of worst-case execution time, (b) avoiding memory fragmentation, (c) avoid running out of memory, (d) avoiding mismatched allocations or deallocations, (e) no dependence of non-deterministic calls to kernel.", "Safety.", "Critical", None),
    ("A18-5-6", "AUTOSAR_CPP14", "Advisory",  "An appropriate user-defined operator new shall be defined for any class that contains a member variable of pointer type.", "Safety.", "Minor", None),
    ("A18-5-7", "AUTOSAR_CPP14", "Advisory",  "If non-default memory management is needed for a type, then all allocating/deallocating functions for that type shall be specified.", "Safety.", "Minor", None),
    ("A18-5-8", "AUTOSAR_CPP14", "Advisory",  "Objects of non-standard-layout type shall not be allocated using C memory allocation functions.", "Safety.", "Minor", None),
    ("A18-5-9", "AUTOSAR_CPP14", "Required",  "Custom implementations of dynamic memory allocation and deallocation functions shall meet the semantic requirements specified in the corresponding 'Required behaviour' clause from the C++ Standard.", "Correctness.", "Major", None),
    ("A18-5-10", "AUTOSAR_CPP14", "Required", "Placement new shall be used only with properly aligned pointers to sufficient storage capacity.", "Safety.", "Critical", None),
    ("A18-5-11", "AUTOSAR_CPP14", "Required", "\"operator new\" and \"operator delete\" shall not be called explicitly.", "Safety.", "Major", None),
    ("A18-9-1", "AUTOSAR_CPP14", "Required",  "The std::bind shall not be used.", "Clarity.", "Minor", "Replace std::bind with lambda"),
    ("A18-9-2", "AUTOSAR_CPP14", "Required",  "Forwarding values to other functions shall be done via perfect forwarding.", "Performance.", "Minor", None),
    ("A18-9-3", "AUTOSAR_CPP14", "Required",  "The std::move shall only be used on rvalue references.", "Correctness.", "Major", None),
    ("A18-9-4", "AUTOSAR_CPP14", "Required",  "An argument to std::forward shall not be subsequently used.", "Correctness.", "Major", None),
    ("A20-8-1", "AUTOSAR_CPP14", "Required",  "An already-owned pointer value shall not be stored in an unrelated smart pointer.", "Safety.", "Critical", None),
    ("A20-8-2", "AUTOSAR_CPP14", "Required",  "A std::unique_ptr shall be used to represent exclusive ownership.", "Clarity.", "Minor", None),
    ("A20-8-3", "AUTOSAR_CPP14", "Required",  "A std::shared_ptr shall be used to represent shared ownership.", "Clarity.", "Minor", None),
    ("A20-8-4", "AUTOSAR_CPP14", "Required",  "A std::unique_ptr shall be used over std::shared_ptr if ownership sharing is not required.", "Performance.", "Minor", None),
    ("A20-8-5", "AUTOSAR_CPP14", "Required",  "std::make_unique shall be used to construct objects owned by std::unique_ptr.", "Safety.", "Minor", "Use std::make_unique<T>(...)"),
    ("A20-8-6", "AUTOSAR_CPP14", "Required",  "std::make_shared shall be used to construct objects owned by std::shared_ptr.", "Safety/Performance.", "Minor", "Use std::make_shared<T>(...)"),
    ("A20-8-7", "AUTOSAR_CPP14", "Required",  "A std::weak_ptr shall be used to represent temporary shared ownership.", "Safety.", "Minor", None),
    ("A21-8-1", "AUTOSAR_CPP14", "Required",  "Arguments to character-handling functions shall be representable as unsigned char.", "Correctness.", "Major", "Cast character argument to unsigned char"),
    ("A23-0-1", "AUTOSAR_CPP14", "Required",  "An iterator shall not be implicitly converted to const_iterator.", "Correctness.", "Major", None),
    ("A23-0-2", "AUTOSAR_CPP14", "Required",  "Elements of a container shall only be accessed via valid references, iterators, and pointers.", "Safety.", "Critical", None),
    ("A25-1-1", "AUTOSAR_CPP14", "Required",  "Non-static data members or captured values of predicate function objects that are state related to this object's identity shall not be copied.", "Correctness.", "Major", None),
    ("A26-5-1", "AUTOSAR_CPP14", "Required",  "Pseudorandom numbers shall not be generated using std::rand().", "Security.", "Major", "Replace std::rand() with a proper random engine from <random>"),
    ("A26-5-2", "AUTOSAR_CPP14", "Required",  "Random number engines shall not be default-initialized.", "Reliability.", "Major", "Seed random engine with std::random_device"),
    ("A27-0-1", "AUTOSAR_CPP14", "Required",  "Inputs from independent components shall be validated.", "Security.", "Major", None),
    ("A27-0-2", "AUTOSAR_CPP14", "Advisory",  "A C-style string shall guarantee sufficient space for data and the null terminator.", "Safety.", "Minor", None),
    ("A27-0-3", "AUTOSAR_CPP14", "Required",  "Alternate input and output operations on a file stream shall not be used without an intervening flush or positioning call.", "Correctness.", "Major", None),
    ("A27-0-4", "AUTOSAR_CPP14", "Advisory",  "C-style strings shall not be used.", "Safety.", "Minor", "Replace char* string with std::string"),
]


# ---------------------------------------------------------------------------
# Database helper
# ---------------------------------------------------------------------------
class RulesDatabase:
    """Thin wrapper around a SQLite connection that manages schema and data."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._ensure_schema()
        self._ensure_rules_populated()

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------
    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------
    def _ensure_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(DDL)

    def _ensure_rules_populated(self) -> None:
        with self._conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
            if count == 0:
                conn.executemany(
                    "INSERT OR IGNORE INTO rules "
                    "(rule_id, standard, category, description, rationale, severity, fix_template) "
                    "VALUES (?,?,?,?,?,?,?)",
                    RULES,
                )

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------
    def get_rule(self, rule_id: str) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM rules WHERE rule_id = ?", (rule_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_rules(
        self,
        standard: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict]:
        query = "SELECT * FROM rules WHERE 1=1"
        params: list = []
        if standard:
            query += " AND standard = ?"
            params.append(standard)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def add_violation(
        self,
        file_path: str,
        line_number: int,
        col_number: int,
        rule_id: str,
        snippet: str,
        status: str = "open",
        fixed_snippet: Optional[str] = None,
    ) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO violations "
                "(file_path, line_number, col_number, rule_id, snippet, status, fixed_snippet) "
                "VALUES (?,?,?,?,?,?,?)",
                (file_path, line_number, col_number, rule_id, snippet, status, fixed_snippet),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def update_violation_status(
        self, violation_id: int, status: str, fixed_snippet: Optional[str] = None
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE violations SET status = ?, fixed_snippet = ? WHERE id = ?",
                (status, fixed_snippet, violation_id),
            )

    def get_violations(
        self,
        file_path: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict]:
        query = """
            SELECT v.*, r.description, r.severity, r.standard, r.category, r.fix_template
            FROM violations v
            JOIN rules r ON v.rule_id = r.rule_id
            WHERE 1=1
        """
        params: list = []
        if file_path:
            query += " AND v.file_path = ?"
            params.append(file_path)
        if status:
            query += " AND v.status = ?"
            params.append(status)
        query += " ORDER BY v.file_path, v.line_number"
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def clear_violations(self) -> None:
        """Remove all violations (used at the start of a fresh scan)."""
        with self._conn() as conn:
            conn.execute("DELETE FROM violations")

    def violation_summary(self) -> Dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM violations").fetchone()[0]
            auto_fixed = conn.execute(
                "SELECT COUNT(*) FROM violations WHERE status = 'auto-fixed'"
            ).fetchone()[0]
            manual = conn.execute(
                "SELECT COUNT(*) FROM violations WHERE status = 'manual-review'"
            ).fetchone()[0]
            open_count = conn.execute(
                "SELECT COUNT(*) FROM violations WHERE status = 'open'"
            ).fetchone()[0]
        return {
            "total": total,
            "open": open_count,
            "auto_fixed": auto_fixed,
            "manual_review": manual,
        }
