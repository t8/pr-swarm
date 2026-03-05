from pr_swarm.config import is_path_ignored, is_sensitive_path, load_config


class TestLoadConfig:
    def test_defaults(self):
        config = load_config()
        assert config["sensitivity"] == "high"
        assert config["max_pr_lines"] == 2000
        assert config["agent_timeout_seconds"] == 30

    def test_yaml_override(self):
        yaml_str = """
sensitivity: paranoid
sensitive_paths:
  - auth/
  - payments/
max_pr_lines: 1000
"""
        config = load_config(config_yaml=yaml_str)
        assert config["sensitivity"] == "paranoid"
        assert "auth/" in config["sensitive_paths"]
        assert config["max_pr_lines"] == 1000

    def test_empty_yaml(self):
        config = load_config(config_yaml="")
        assert config["sensitivity"] == "high"


class TestPathIgnore:
    def test_vendor(self):
        config = {"ignore_paths": ["vendor/*"]}
        assert is_path_ignored("vendor/lib.js", config)
        assert not is_path_ignored("src/app.js", config)

    def test_generated(self):
        config = {"ignore_paths": ["**/*.generated.*"]}
        assert is_path_ignored("src/types.generated.ts", config)

    def test_minified(self):
        config = {"ignore_paths": ["**/*.min.js"]}
        assert is_path_ignored("dist/app.min.js", config)
        assert not is_path_ignored("src/app.js", config)


class TestSensitivePath:
    def test_sensitive(self):
        config = {"sensitive_paths": ["auth/", "payments/"]}
        assert is_sensitive_path("auth/login.py", config)
        assert is_sensitive_path("payments/stripe.py", config)
        assert not is_sensitive_path("api/users.py", config)
