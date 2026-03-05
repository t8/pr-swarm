from pr_swarm.tools.ast_parser import (
    BoundaryViolation,
    check_boundary_violations,
    parse_js_imports,
    parse_python_module,
)
from pr_swarm.tools.coverage import CoverageReport, compute_coverage_delta, find_untested_new_functions


class TestPythonParser:
    def test_parse_imports(self):
        source = """
import os
from pathlib import Path
import json

class MyClass:
    pass

def my_function():
    pass
"""
        info = parse_python_module("test.py", source)
        assert "os" in info.imports
        assert "pathlib" in info.imports
        assert "json" in info.imports
        assert "MyClass" in info.classes
        assert "my_function" in info.functions

    def test_parse_syntax_error(self):
        info = parse_python_module("bad.py", "def foo(:\n    pass")
        assert info.path == "bad.py"
        assert info.imports == []


class TestJsImports:
    def test_es6_imports(self):
        source = """
import React from 'react';
import { useState } from 'react';
import type { FC } from 'react';
"""
        imports = parse_js_imports(source)
        assert "react" in imports

    def test_require(self):
        source = "const express = require('express');"
        imports = parse_js_imports(source)
        assert "express" in imports


class TestBoundaryViolations:
    def test_no_violations(self):
        from pr_swarm.tools.ast_parser import ModuleInfo

        modules = [
            ModuleInfo(path="api/routes.py", dependencies=["api.models", "shared.utils"]),
        ]
        allowed = {"api/": ["api/", "shared/"], "db/": ["db/", "shared/"]}
        violations = check_boundary_violations(modules, allowed)
        assert len(violations) == 0

    def test_violation_detected(self):
        from pr_swarm.tools.ast_parser import ModuleInfo

        modules = [
            ModuleInfo(path="ui/component.py", dependencies=["db.models"]),
        ]
        allowed = {"ui/": ["ui/", "shared/"], "db/": ["db/"]}
        violations = check_boundary_violations(modules, allowed)
        assert len(violations) == 1
        assert "ui/" in violations[0].description


class TestCoverage:
    def test_compute_delta(self):
        before = CoverageReport(total_coverage_pct=80.0)
        after = CoverageReport(total_coverage_pct=78.5)
        assert compute_coverage_delta(before, after) == -1.5

    def test_delta_with_none(self):
        assert compute_coverage_delta(None, CoverageReport(total_coverage_pct=80.0)) == 0.0

    def test_find_untested(self):
        cov = CoverageReport(
            total_coverage_pct=75.0,
            uncovered_lines={"api/users.py": [10, 15, 20]},
        )
        result = find_untested_new_functions(["api/users.py", "api/auth.py"], cov)
        assert "api/users.py" in result
        assert "api/auth.py" not in result
