"""
Tests for Issue 5:
- AST & structural syntax verification in AstPatcher for JavaScript/TypeScript, Rust, and Go.
- MinimalPatcher syntax verification before and after patching.
"""
import pytest

from automaintainer.agents.ast_patcher import AstPatcher, AstValidationError
from automaintainer.agents.patcher import MinimalPatcher
from automaintainer.inference.schemas import PlannerOutput, ProposedEdit, ValidationStep
from automaintainer.core.models import RiskTier



def test_ast_patcher_valid_javascript():
    code = """
    function add(a, b) {
        const result = a + b;
        return result;
    }
    module.exports = { add };
    """
    valid, err = AstPatcher.validate_content("index.js", code)
    assert valid is True
    assert err is None


def test_ast_patcher_invalid_javascript_unclosed_brace():
    code = """
    function calculate(x) {
        if (x > 0) {
            return x * 2;
        // Missing closing braces
    """
    valid, err = AstPatcher.validate_content("src/calc.js", code)
    assert valid is False
    assert "JavaScript/TypeScript" in err or "SyntaxError" in err


def test_ast_patcher_invalid_javascript_mismatched_delimiter():
    code = "const items = [1, 2, 3);"
    valid, err = AstPatcher.validate_content("app.js", code)
    assert valid is False
    assert "Mismatched delimiter" in err or "SyntaxError" in err


def test_ast_patcher_valid_rust():
    code = """
    pub fn greet(name: &str) -> String {
        format!("Hello, {}!", name)
    }

    mod tests {
        use super::*;
        fn test_greet() {
            assert_eq!(greet("world"), "Hello, world!");
        }
    }
    """
    valid, err = AstPatcher.validate_content("src/lib.rs", code)
    assert valid is True
    assert err is None


def test_ast_patcher_invalid_rust_unclosed_delimiter():
    code = """
    pub fn compute() -> i32 {
        let x = (1 + 2;
        x
    }
    """
    valid, err = AstPatcher.validate_content("src/compute.rs", code)
    assert valid is False
    assert "Rust" in err and "SyntaxError" in err


def test_ast_patcher_valid_go_code():
    code = """package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
"""
    valid, err = AstPatcher.validate_content("main.go", code)
    assert valid is True
    assert err is None


def test_ast_patcher_invalid_go_missing_package():
    code = """
import "fmt"

func main() {
    fmt.Println("No package!")
}
"""
    valid, err = AstPatcher.validate_content("main.go", code)
    assert valid is False
    assert "Missing required 'package <name>'" in err


def test_ast_patcher_valid_go_mod():
    code = """module github.com/example/myproject

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
)
"""
    valid, err = AstPatcher.validate_content("go.mod", code)
    assert valid is True
    assert err is None


def test_ast_patcher_invalid_go_mod_unrecognized_directive():
    code = """module github.com/example/myproject

go 1.21

invalid_directive something
"""
    valid, err = AstPatcher.validate_content("go.mod", code)
    assert valid is False
    assert "Unrecognized directive" in err



def test_minimal_patcher_catches_js_syntax_error():
    """Verify MinimalPatcher catches syntax errors in JavaScript files and records them in errors."""
    patcher = MinimalPatcher()

    plan = PlannerOutput(
        objective="Update JS module",
        task_type="package_metadata",
        confidence=0.9,
        target_paths=["src/utils.js"],
        proposed_edits=[
            ProposedEdit(
                path="src/utils.js",
                operation="full_replace",
                rationale="Broken patch with unclosed bracket",
                new_content="export function broken() { return [1, 2, 3; }",
            )
        ],
        explicitly_unchanged=[],
        validation_steps=[],
        risk_tier=RiskTier.R1,
        requires_human_approval=False,
    )

    original_contents = {"src/utils.js": "export function ok() { return [1, 2, 3]; }"}
    result = patcher.apply(plan, original_contents)

    assert not result.success
    assert any("AST validation error in 'src/utils.js'" in e for e in result.errors)


def test_minimal_patcher_catches_rust_syntax_error():
    """Verify MinimalPatcher catches syntax errors in Rust files."""
    patcher = MinimalPatcher()

    plan = PlannerOutput(
        objective="Update Rust lib",
        task_type="package_metadata",
        confidence=0.9,
        target_paths=["src/lib.rs"],
        proposed_edits=[
            ProposedEdit(
                path="src/lib.rs",
                operation="full_replace",
                rationale="Broken Rust function",
                new_content="pub fn broken() { let a = (1 + 2; }",
            )
        ],
        explicitly_unchanged=[],
        validation_steps=[],
        risk_tier=RiskTier.R1,
        requires_human_approval=False,
    )

    original_contents = {"src/lib.rs": "pub fn ok() { let a = (1 + 2); }"}
    result = patcher.apply(plan, original_contents)

    assert not result.success
    assert any("AST validation error in 'src/lib.rs'" in e for e in result.errors)
