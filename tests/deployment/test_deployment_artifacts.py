from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ReleaseMetadataTest(unittest.TestCase):
    def test_release_metadata_and_ci_image_tags_are_aligned(self) -> None:
        version = "0.8.1"
        backend_version = (ROOT / "backend" / "app" / "version.py").read_text(encoding="utf-8")
        frontend_package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        production_env = (ROOT / ".env.production.example").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

        self.assertIn(f'APPLICATION_VERSION = "{version}"', backend_version)
        self.assertEqual(frontend_package["version"], version)
        for image in ("backend", "web"):
            tag = f"cyberqalqon/{image}:{version}"
            self.assertIn(tag, compose)
            self.assertIn(tag, production_env)
            self.assertIn(tag, workflow)
            self.assertNotIn(f"cyberqalqon/{image}:0.8.0", workflow)


class DeploymentArtifactsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("docker") is None:
            raise unittest.SkipTest("Docker CLI is not available")
        result = subprocess.run(
            [
                "docker",
                "compose",
                "--profile",
                "ollama",
                "--env-file",
                ".env.production.example",
                "config",
                "--format",
                "json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        cls.config = json.loads(result.stdout)

    def test_only_reverse_proxy_publishes_ports(self) -> None:
        services = self.config["services"]
        self.assertNotIn("ports", services["backend"])
        self.assertNotIn("ports", services["ollama"])
        targets = {int(port["target"]) for port in services["web"]["ports"]}
        self.assertEqual(targets, {8080, 8443})
        self.assertTrue(self.config["networks"]["private"]["internal"])
        self.assertEqual(set(services["backend"]["networks"]), {"private"})
        self.assertEqual(set(services["ollama"]["networks"]), {"private"})
        self.assertEqual(set(services["web"]["networks"]), {"edge", "private"})

    def test_backend_production_security_contract(self) -> None:
        backend = self.config["services"]["backend"]
        environment = backend["environment"]
        self.assertEqual(environment["APP_ENV"], "production")
        self.assertEqual(environment["SESSION_COOKIE_SECURE"], "true")
        self.assertNotEqual(environment["CORS_ORIGINS"], "*")
        self.assertEqual(environment["WAZUH_INGEST_API_KEY_FILE"], "/run/secrets/wazuh_ingest_api_key")
        self.assertTrue(backend["read_only"])
        self.assertIn("ALL", backend["cap_drop"])
        self.assertEqual(backend["restart"], "unless-stopped")

    def test_proxy_has_tls_headers_limits_and_no_api_cache(self) -> None:
        nginx = (ROOT / "frontend" / "docker" / "nginx.conf").read_text(encoding="utf-8")
        for required in (
            "ssl_protocols TLSv1.2 TLSv1.3",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "frame-ancestors 'none'",
            "Permissions-Policy",
            "client_max_body_size 1m",
            'Cache-Control "no-store"',
            'Cache-Control "public, max-age=31536000, immutable"',
            "proxy_read_timeout 100s",
        ):
            self.assertIn(required, nginx)
        self.assertNotIn("unsafe-inline", nginx)
        self.assertNotIn("proxy_cache", nginx)

    def test_images_and_contexts_are_explicitly_hardened(self) -> None:
        backend = (ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
        frontend = (ROOT / "frontend" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("python:3.11.14-slim-bookworm", backend)
        self.assertIn("USER 10001:10001", backend)
        self.assertIn('"--workers", "1"', backend)
        self.assertIn("node:24.11.1-bookworm-slim AS build", frontend)
        self.assertIn("nginxinc/nginx-unprivileged:1.28.0-alpine", frontend)
        self.assertIn("USER 101:101", frontend)
        for directory in ("backend", "frontend"):
            ignored = (ROOT / directory / ".dockerignore").read_text(encoding="utf-8")
            for pattern in (".env", "*.db", "*-wal", "*-shm", "*.key"):
                self.assertIn(pattern, ignored)


if __name__ == "__main__":
    unittest.main()
