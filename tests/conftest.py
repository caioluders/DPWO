import importlib.util
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(PROJECT_ROOT, "plugins")


def load_plugin(name):
    path = os.path.join(PLUGIN_DIR, name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def net_plugin():
    return load_plugin("NET_")


@pytest.fixture
def vivo_plugin():
    return load_plugin("VIVO")


@pytest.fixture
def vivofibra_plugin():
    return load_plugin("VIVOFIBRA")


@pytest.fixture
def claro_plugin():
    return load_plugin("CLARO")


@pytest.fixture
def brute_plugin():
    return load_plugin("brute")
