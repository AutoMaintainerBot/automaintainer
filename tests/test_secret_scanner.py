"""Tests for SecretPatternScanner — credential detection in diff content."""
import pytest

from automaintainer.validation.secret_scanner import SecretPatternScanner

scanner = SecretPatternScanner()


def test_detects_github_pat():
    text = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    result = scanner.scan(text)
    assert result.has_secrets
    assert any("GitHub personal access token" in f for f in result.findings)


def test_detects_aws_access_key():
    text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    result = scanner.scan(text)
    assert result.has_secrets
    assert any("AWS" in f for f in result.findings)


def test_detects_groq_api_key():
    text = "GROQ_API_KEY=gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234567890"
    result = scanner.scan(text)
    assert result.has_secrets
    assert any("Groq" in f for f in result.findings)


def test_detects_pem_header():
    text = "-----BEGIN RSA PRIVATE KEY-----\nABCDE...\n-----END RSA PRIVATE KEY-----"
    result = scanner.scan(text)
    assert result.has_secrets
    assert any("private key" in f.lower() for f in result.findings)


def test_detects_database_url_with_credentials():
    text = "DATABASE_URL=postgresql://admin:supersecret@localhost:5432/mydb"
    result = scanner.scan(text)
    assert result.has_secrets


def test_detects_password_assignment():
    text = "password = MySuper$ecretP@ssword123"
    result = scanner.scan(text)
    assert result.has_secrets
    assert any("Password" in f for f in result.findings)


def test_clean_source_code_is_safe():
    text = """
def update_dependency(package_name: str, new_version: str) -> None:
    \"\"\"Updates a dependency to a newer version.\"\"\"
    print(f"Updating {package_name} to {new_version}")
"""
    result = scanner.scan(text)
    assert not result.has_secrets
    assert result.findings == []


def test_scan_diff_files_aggregates_across_multiple_files():
    files = [
        "# Normal Python file\ndef hello():\n    pass",
        "API_KEY=gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234567890",
    ]
    result = scanner.scan_diff_files(files)
    assert result.has_secrets


def test_clean_yaml_action_bump_is_safe():
    text = """
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
    """
    result = scanner.scan(text)
    assert not result.has_secrets
