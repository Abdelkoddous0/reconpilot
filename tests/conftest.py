import copy

import pytest

from reconpilot.config import DEFAULT_CONFIG
from reconpilot.scope import Scope
from reconpilot.store import Store


@pytest.fixture
def config(tmp_path):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["data_dir"] = str(tmp_path)
    return cfg


@pytest.fixture
def store(tmp_path):
    scope = Scope.from_entries(["example.com", "10.0.0.0/24"], exclude=["dev.example.com"])
    s = Store.create_project(tmp_path, "demo", client="Lab", auth_ref="home-lab", scope=scope)
    yield s
    s.close()
