"""Tests for the GitHub URL parser and file filter logic."""

import pytest
from src.fetcher import parse_github_url, _should_include


class TestParseGithubUrl:
    def test_owner_repo_shorthand(self):
        assert parse_github_url("fastapi/fastapi") == ("fastapi", "fastapi")

    def test_full_https_url(self):
        assert parse_github_url("https://github.com/tiangolo/fastapi") == ("tiangolo", "fastapi")

    def test_trailing_slash(self):
        assert parse_github_url("https://github.com/tiangolo/fastapi/") == ("tiangolo", "fastapi")

    def test_dot_git_suffix(self):
        assert parse_github_url("https://github.com/django/django.git") == ("django", "django")

    def test_invalid_url(self):
        with pytest.raises(ValueError):
            parse_github_url("not-a-url")


class TestShouldInclude:
    def test_python_file(self):
        assert _should_include("src/main.py", 1000) is True

    def test_typescript_file(self):
        assert _should_include("app/index.ts", 2000) is True

    def test_node_modules_skip(self):
        assert _should_include("node_modules/express/index.js", 500) is False

    def test_dist_skip(self):
        assert _should_include("dist/bundle.js", 500) is False

    def test_large_file_skip(self):
        assert _should_include("src/big.py", 200_000) is False

    def test_readme(self):
        assert _should_include("README.md", 5000) is True

    def test_dockerfile(self):
        assert _should_include("Dockerfile", 800) is True

    def test_binary_extension(self):
        assert _should_include("assets/logo.png", 5000) is False
