from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field


@dataclass
class ModuleInfo:
    path: str
    imports: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)  # imported module paths


@dataclass
class BoundaryViolation:
    source_file: str
    target_module: str
    import_line: int
    description: str


def parse_python_module(file_path: str, source: str) -> ModuleInfo:
    """Parse a Python file and extract structural information."""
    info = ModuleInfo(path=file_path)

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return info

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                info.imports.append(alias.name)
                info.dependencies.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            info.imports.append(module)
            info.dependencies.append(module)
        elif isinstance(node, ast.ClassDef):
            info.classes.append(node.name)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if not isinstance(getattr(node, "_parent", None), ast.ClassDef):
                info.functions.append(node.name)

    return info


def parse_js_imports(source: str) -> list[str]:
    """Extract imports from JavaScript/TypeScript source (regex-based)."""
    imports = []
    patterns = [
        r'import\s+.*?\s+from\s+["\']([^"\']+)["\']',
        r'require\s*\(\s*["\']([^"\']+)["\']\s*\)',
        r'import\s*\(\s*["\']([^"\']+)["\']\s*\)',
    ]
    for pattern in patterns:
        imports.extend(re.findall(pattern, source))
    return imports


def check_boundary_violations(
    modules: list[ModuleInfo],
    allowed_deps: dict[str, list[str]],
) -> list[BoundaryViolation]:
    """Check if any module imports from a disallowed layer.

    allowed_deps maps module prefixes to lists of allowed import prefixes.
    e.g. {"ui/": ["ui/", "shared/"], "api/": ["api/", "db/", "shared/"]}
    """
    violations = []
    for module in modules:
        source_layer = _get_layer(module.path, allowed_deps)
        if source_layer is None:
            continue
        allowed = allowed_deps.get(source_layer, [])
        for dep in module.dependencies:
            dep_layer = _get_layer(dep, allowed_deps)
            if dep_layer is not None and dep_layer not in allowed:
                violations.append(
                    BoundaryViolation(
                        source_file=module.path,
                        target_module=dep,
                        import_line=0,
                        description=f"Layer violation: {source_layer} imports from {dep_layer} (not allowed)",
                    )
                )
    return violations


def _get_layer(path: str, layers: dict[str, list[str]]) -> str | None:
    normalized = path.replace(".", "/")
    for prefix in layers:
        if path.startswith(prefix) or normalized.startswith(prefix):
            return prefix
    return None
