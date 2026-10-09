"""
AST & Structural Syntax Validator and Patcher.
Provides AST-level validation and mutation for Python, YAML, TOML, and JSON files,
ensuring LLM-generated edits maintain syntactical and structural integrity without
brittle regex or broken indentation.
"""
from __future__ import annotations

import ast
import json
import logging
import os
import re
import shutil
import subprocess
from typing import Tuple, Optional, Any, List
import yaml

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

logger = logging.getLogger("automaintainer.ast_patcher")


class AstValidationError(Exception):
    """Raised when generated code fails AST or structural syntax validation."""
    pass


def _check_balanced_delimiters(content: str, lang: str) -> Tuple[bool, Optional[str]]:
    """
    Structural delimiter and quote balance scanner.
    Handles single/double/template strings and single/multi-line comments.
    """
    stack: List[Tuple[str, int, int]] = []  # (char, line, col)
    matching = {")": "(", "}": "{", "]": "["}
    
    i = 0
    line = 1
    col = 1
    n = len(content)

    in_single_quote = False
    in_double_quote = False
    in_backtick_quote = False
    in_line_comment = False
    in_block_comment = False
    in_rust_raw_string = False

    while i < n:
        ch = content[i]
        nxt = content[i + 1] if i + 1 < n else ""

        if ch == "\n":
            line += 1
            col = 1
            if in_line_comment:
                in_line_comment = False
            i += 1
            continue

        # Handle comments and strings
        if in_line_comment:
            i += 1
            col += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                col += 2
                continue
            i += 1
            col += 1
            continue

        if in_single_quote:
            if ch == "\\":
                i += 2
                col += 2
                continue
            if ch == "'":
                in_single_quote = False
            i += 1
            col += 1
            continue

        if in_double_quote:
            if ch == "\\":
                i += 2
                col += 2
                continue
            if ch == '"':
                in_double_quote = False
            i += 1
            col += 1
            continue

        if in_backtick_quote:
            if ch == "\\":
                i += 2
                col += 2
                continue
            if ch == "`":
                in_backtick_quote = False
            i += 1
            col += 1
            continue

        if in_rust_raw_string:
            if ch == '"' and nxt == "#":
                in_rust_raw_string = False
                i += 2
                col += 2
                continue
            i += 1
            col += 1
            continue

        # Check comment starts
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            col += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            col += 2
            continue

        # Check string starts
        if lang == "rust" and ch == "r" and nxt == "#":
            in_rust_raw_string = True
            i += 2
            col += 2
            continue
        if ch == "'":
            in_single_quote = True
            i += 1
            col += 1
            continue
        if ch == '"':
            in_double_quote = True
            i += 1
            col += 1
            continue
        if ch == "`" and lang in ("javascript", "typescript", "go"):
            in_backtick_quote = True
            i += 1
            col += 1
            continue

        # Delimiter tracking
        if ch in "({[":
            stack.append((ch, line, col))
        elif ch in ")}]":
            expected = matching[ch]
            if not stack:
                return False, f"SyntaxError: Unmatched closing '{ch}' at line {line}, col {col}"
            last_ch, last_line, last_col = stack.pop()
            if last_ch != expected:
                return False, f"SyntaxError: Mismatched delimiter '{ch}' at line {line}, col {col} (expected match for '{last_ch}' from line {last_line}, col {last_col})"

        i += 1
        col += 1

    if in_block_comment:
        return False, "SyntaxError: Unclosed block comment"
    if in_single_quote:
        return False, "SyntaxError: Unclosed single quote string literal"
    if in_double_quote:
        return False, "SyntaxError: Unclosed double quote string literal"
    if in_backtick_quote:
        return False, "SyntaxError: Unclosed template/raw string literal"
    if in_rust_raw_string:
        return False, "SyntaxError: Unclosed Rust raw string literal"
    if stack:
        unclosed, u_line, u_col = stack[-1]
        return False, f"SyntaxError: Unclosed delimiter '{unclosed}' opened at line {u_line}, col {u_col}"

    return True, None


_TS_PARSERS: Dict[str, Any] = {}

def _get_tree_sitter_parser(lang: str):
    """
    Returns a Tree-sitter Parser instance for the specified language
    if the corresponding grammar package is installed.
    """
    if lang in _TS_PARSERS:
        return _TS_PARSERS[lang]
    parser = None
    try:
        from tree_sitter import Language, Parser
        ts_lang = None
        if lang == "javascript":
            import tree_sitter_javascript as mod
            ts_lang = Language(mod.language())
        elif lang == "typescript":
            import tree_sitter_typescript as mod
            fn = getattr(mod, "language_typescript", None) or getattr(mod, "language", None)
            ts_lang = Language(fn()) if fn else None
        elif lang == "tsx":
            import tree_sitter_typescript as mod
            fn = getattr(mod, "language_tsx", None) or getattr(mod, "language", None)
            ts_lang = Language(fn()) if fn else None
        elif lang == "go":
            import tree_sitter_go as mod
            ts_lang = Language(mod.language())
        elif lang == "rust":
            import tree_sitter_rust as mod
            ts_lang = Language(mod.language())

        if ts_lang:
            try:
                parser = Parser(ts_lang)
            except TypeError:
                parser = Parser()
                if hasattr(parser, "language"):
                    parser.language = ts_lang
                elif hasattr(parser, "set_language"):
                    parser.set_language(ts_lang)
    except Exception as e:
        logger.debug(f"Tree-sitter parser init failed for '{lang}': {e}")
        parser = None

    _TS_PARSERS[lang] = parser
    return parser


def _try_tree_sitter(content: str, lang: str) -> Tuple[Optional[bool], Optional[str]]:
    """
    Parses content with Tree-sitter if grammar is installed.
    Returns:
      - (True, None) if AST parsed cleanly with no error nodes.
      - (False, error_msg) if AST contains syntax error nodes.
      - (None, None) if Tree-sitter or grammar is not available.
    """
    parser = _get_tree_sitter_parser(lang)
    if parser is None:
        return None, None
    try:
        tree = parser.parse(content.encode("utf-8"))
        if not tree or not tree.root_node:
            return True, None
        if tree.root_node.has_error:
            def find_error_node(node):
                is_err = getattr(node, "is_error", False) is True
                is_miss = getattr(node, "is_missing", False) is True
                node_type = str(getattr(node, "type", ""))
                if is_err or is_miss or node_type == "ERROR":
                    return node
                for child in getattr(node, "children", []):
                    c_err = (
                        getattr(child, "has_error", False) is True
                        or getattr(child, "is_error", False) is True
                        or str(getattr(child, "type", "")) == "ERROR"
                    )
                    if c_err:
                        found = find_error_node(child)
                        if found:
                            return found
                return None

            err_node = find_error_node(tree.root_node)
            if err_node and hasattr(err_node, "start_point"):
                row = err_node.start_point[0] + 1
                col = err_node.start_point[1] + 1
                return False, f"Tree-sitter {lang.capitalize()} AST SyntaxError at line {row}, col {col}"
            return False, f"Tree-sitter {lang.capitalize()} AST SyntaxError: syntax error detected in AST"
        return True, None
    except Exception as e:
        logger.debug(f"Tree-sitter parse exception for '{lang}': {e}")
        return None, None


class AstPatcher:
    """
    Validates and structurally transforms code and configuration files.
    Ensures that every LLM patch preserves valid AST before sandbox execution.
    Supports Python, YAML, TOML, JSON, JavaScript/TypeScript, Rust, and Go.
    """

    @classmethod
    def validate_content(cls, file_path: str, content: str) -> Tuple[bool, Optional[str]]:
        """
        Validates content according to file type:
          - *.py: Python ast.parse()
          - *.yml, *.yaml: YAML safe_load()
          - *.toml: TOML parser (pyproject.toml, Cargo.toml)
          - *.json: JSON parser (package.json, tsconfig.json)
          - *.js, *.mjs, *.cjs, *.jsx, *.ts, *.tsx: Node.js/Tree-sitter/structural syntax verification
          - *.rs: Rust structural and compiler/AST syntax verification
          - *.go: Go structural and package syntax verification
          - go.mod: Go module structural directive verification
        Returns (is_valid, error_message_if_invalid).
        """
        lower = file_path.lower()

        if lower.endswith(".py"):
            try:
                ast.parse(content, filename=file_path)
                return True, None
            except SyntaxError as se:
                msg = f"Python SyntaxError at line {se.lineno}, col {se.offset}: {se.msg}"
                return False, msg
            except Exception as e:
                return False, f"Python AST validation failed: {str(e)}"

        elif lower.endswith((".yml", ".yaml")):
            try:
                yaml.safe_load(content)
                return True, None
            except yaml.YAMLError as ye:
                return False, f"YAML SyntaxError: {str(ye)}"
            except Exception as e:
                return False, f"YAML validation failed: {str(e)}"

        elif lower.endswith(".toml"):
            if tomllib:
                try:
                    tomllib.loads(content)
                    return True, None
                except Exception as e:
                    return False, f"TOML SyntaxError: {str(e)}"
            return True, None

        elif lower.endswith(".json"):
            try:
                json.loads(content)
                return True, None
            except json.JSONDecodeError as jde:
                return False, f"JSON SyntaxError at line {jde.lineno}, col {jde.colno}: {jde.msg}"
            except Exception as e:
                return False, f"JSON validation failed: {str(e)}"

        elif lower.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")):
            valid, err = _check_balanced_delimiters(content, "javascript")
            if not valid:
                return False, f"JavaScript/TypeScript {err}"

            # Native Tree-sitter AST validation
            ts_lang = "tsx" if lower.endswith(".tsx") else ("typescript" if lower.endswith((".ts", ".tsx")) else "javascript")
            ts_valid, ts_err = _try_tree_sitter(content, ts_lang)
            if ts_valid is not None:
                if not ts_valid:
                    return False, ts_err
                return True, None

            # If node is available, execute VM syntax validation for JS
            node_path = shutil.which("node")
            if node_path and lower.endswith((".js", ".cjs")):
                try:
                    js_code = (
                        "const vm = require('vm'); const fs = require('fs'); "
                        "try { new vm.Script(fs.readFileSync(0, 'utf-8')); } "
                        "catch(e) { console.error(e.message); process.exit(1); }"
                    )
                    res = subprocess.run(
                        [node_path, "-e", js_code],
                        input=content,
                        capture_output=True,
                        text=True,
                        timeout=3.0
                    )
                    if res.returncode != 0:
                        err_msg = res.stderr.strip() or res.stdout.strip() or "Invalid JavaScript syntax"
                        return False, f"JavaScript SyntaxError: {err_msg}"
                except Exception:
                    pass

            return True, None

        elif lower.endswith(".rs"):
            valid, err = _check_balanced_delimiters(content, "rust")
            if not valid:
                return False, f"Rust {err}"

            # Native Tree-sitter AST validation
            ts_valid, ts_err = _try_tree_sitter(content, "rust")
            if ts_valid is not None:
                if not ts_valid:
                    return False, ts_err
                return True, None

            # Basic Rust syntactic sanity check
            if content.strip() and not any(kw in content for kw in ("fn", "struct", "enum", "impl", "use", "mod", "pub", "const", "static", "trait", "type", "let", "macro")):
                if not content.strip().startswith("//") and not content.strip().startswith("/*"):
                    return False, "Rust SyntaxError: No valid Rust declarations or statements found"

            return True, None

        elif os.path.basename(lower) == "go.mod":
            lines = content.splitlines()
            has_module = False
            in_paren_block = False
            for idx, raw_line in enumerate(lines, 1):
                line_str = raw_line.split("//")[0].strip()
                if not line_str:
                    continue
                if "(" in line_str and ")" not in line_str:
                    in_paren_block = True
                    continue
                if ")" in line_str:
                    in_paren_block = False
                    continue
                if in_paren_block:
                    continue
                if line_str.startswith("module "):
                    has_module = True
                elif not any(line_str.startswith(k) for k in ("module", "go", "require", "replace", "exclude", "retract")):
                    return False, f"Go.mod SyntaxError at line {idx}: Unrecognized directive '{line_str}'"
            if not has_module and content.strip():
                return False, "Go.mod SyntaxError: Missing required 'module <name>' directive"

            valid, err = _check_balanced_delimiters(content, "go")
            if not valid:
                return False, f"Go.mod {err}"
            return True, None

        elif lower.endswith(".go"):
            valid, err = _check_balanced_delimiters(content, "go")
            if not valid:
                return False, f"Go {err}"

            # Native Tree-sitter AST validation
            ts_valid, ts_err = _try_tree_sitter(content, "go")
            if ts_valid is not None:
                if not ts_valid:
                    return False, ts_err
                return True, None

            # Go must have package declaration
            clean_lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("//")]
            if clean_lines:
                first_code = clean_lines[0]
                if not first_code.startswith("package "):
                    return False, "Go SyntaxError: Missing required 'package <name>' statement at top of file"

            return True, None

        # Default for plain text, Markdown, etc.
        return True, None

    @classmethod
    def assert_valid(cls, file_path: str, content: str) -> None:
        """Raises AstValidationError if content is invalid."""
        valid, err = cls.validate_content(file_path, content)
        if not valid:
            raise AstValidationError(err or f"Syntax validation failed for '{file_path}'")
