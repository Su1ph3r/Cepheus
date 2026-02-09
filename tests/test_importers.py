"""Tests for external tool importers."""

import json
from pathlib import Path

import pytest

from cepheus.importers.nubicustos import build_cloud_context, load_nubicustos_containers


@pytest.fixture
def nubicustos_export(tmp_path: Path) -> Path:
    """Create a sample Nubicustos container export."""
    data = {
        "export_source": "nubicustos",
        "export_timestamp": "2025-01-15T10:30:00Z",
        "total_containers": 2,
        "containers": [
            {
                "resource_id": "arn:aws:ecs:us-east-1:123456789:task/abc",
                "resource_name": "web-app",
                "resource_type": "ecs-container",
                "cloud_provider": "aws",
                "region": "us-east-1",
                "account_id": "123456789",
                "container_image": "nginx:latest",
                "runtime": "containerd",
                "privileged": False,
                "namespace": "default",
            },
            {
                "resource_id": "arn:aws:ecs:us-east-1:123456789:task/def",
                "resource_name": "api-server",
                "resource_type": "ecs-container",
                "cloud_provider": "aws",
                "region": "us-east-1",
                "account_id": "123456789",
                "container_image": "api:v2.1",
                "runtime": "containerd",
                "privileged": True,
                "namespace": "production",
            },
        ],
    }
    path = tmp_path / "nubicustos-containers.json"
    path.write_text(json.dumps(data))
    return path


@pytest.fixture
def invalid_export(tmp_path: Path) -> Path:
    """Create an export with wrong source."""
    data = {"export_source": "wrong", "containers": []}
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(data))
    return path


class TestLoadNubicustosContainers:
    def test_load_valid(self, nubicustos_export: Path) -> None:
        containers = load_nubicustos_containers(nubicustos_export)
        assert len(containers) == 2
        assert containers[0]["resource_name"] == "web-app"
        assert containers[1]["privileged"] is True

    def test_load_invalid_source(self, invalid_export: Path) -> None:
        with pytest.raises(ValueError, match="Expected export_source 'nubicustos'"):
            load_nubicustos_containers(invalid_export)

    def test_load_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_nubicustos_containers(tmp_path / "nonexistent.json")


class TestBuildCloudContext:
    def test_build_context(self) -> None:
        containers = [
            {
                "cloud_provider": "aws",
                "region": "us-east-1",
                "privileged": False,
                "container_image": "nginx:latest",
            },
            {
                "cloud_provider": "aws",
                "region": "us-west-2",
                "privileged": True,
                "container_image": "api:v2",
            },
        ]
        ctx = build_cloud_context(containers)

        assert ctx["source"] == "nubicustos"
        assert ctx["cloud_providers"] == ["aws"]
        assert sorted(ctx["regions"]) == ["us-east-1", "us-west-2"]
        assert ctx["has_privileged"] is True
        assert ctx["total_containers"] == 2
        assert len(ctx["container_images"]) == 2

    def test_build_context_empty(self) -> None:
        ctx = build_cloud_context([])
        assert ctx == {}
