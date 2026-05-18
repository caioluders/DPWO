import sys
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_wifi():
    """Mock the wifi module so dpwo can be imported without it installed."""
    wifi_mock = MagicMock()
    with patch.dict(sys.modules, {"wifi": wifi_mock}):
        yield wifi_mock


@pytest.fixture
def dpwo_module(mock_wifi):
    """Import dpwo with wifi mocked out."""
    if "dpwo" in sys.modules:
        del sys.modules["dpwo"]
    import dpwo
    return dpwo


class TestParseArgs:
    def test_defaults(self, dpwo_module):
        with patch("sys.argv", ["dpwo"]):
            args = dpwo_module.parse_args()
        assert args.interface == "wlp3s0"
        assert args.brute is False
        assert args.disable is True
        assert args.verbosity is None

    def test_custom_interface(self, dpwo_module):
        with patch("sys.argv", ["dpwo", "-i", "wlan0"]):
            args = dpwo_module.parse_args()
        assert args.interface == "wlan0"

    def test_brute_flag(self, dpwo_module):
        with patch("sys.argv", ["dpwo", "-b"]):
            args = dpwo_module.parse_args()
        assert args.brute is True

    def test_disable_autoconnect(self, dpwo_module):
        with patch("sys.argv", ["dpwo", "-d"]):
            args = dpwo_module.parse_args()
        assert args.disable is False

    def test_verbosity_stacking(self, dpwo_module):
        with patch("sys.argv", ["dpwo", "-vv"]):
            args = dpwo_module.parse_args()
        assert args.verbosity == 2


class TestNETOwnerLoadPlugins:
    def test_loads_all_plugins(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        plugin_names = [p.__name__ for p in owner.plugins]
        assert "NET_" in plugin_names
        assert "VIVO" in plugin_names
        assert "VIVOFIBRA" in plugin_names
        assert "CLARO" in plugin_names
        assert "brute" in plugin_names

    def test_plugins_have_required_interface(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        for p in owner.plugins:
            assert hasattr(p, "is_vuln"), f"{p.__name__} missing is_vuln"
            assert hasattr(p, "own"), f"{p.__name__} missing own"
            assert hasattr(p, "brute"), f"{p.__name__} missing brute flag"


class TestNETOwnerScanNetwork:
    def test_scan_finds_vulnerable_network(self, dpwo_module, mock_wifi):
        fake_cell = MagicMock()
        fake_cell.ssid = "CLARO_1234"
        fake_cell.address = "AA:BB:CC:DD:EE:FF"
        fake_cell.signal = -50
        fake_cell.channel = 6
        mock_wifi.Cell.all.return_value = [fake_cell]

        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "linux"
        results = owner.scan_network()

        assert len(results) >= 1
        match = [r for r in results if r["ssid"] == "CLARO_1234"]
        assert len(match) == 1
        assert match[0]["wifi_password"] == "CCDDEEFF"

    def test_scan_ignores_non_vulnerable(self, dpwo_module, mock_wifi):
        fake_cell = MagicMock()
        fake_cell.ssid = "MyHomeWiFi"
        fake_cell.address = "AA:BB:CC:DD:EE:FF"
        fake_cell.signal = -50
        fake_cell.channel = 6
        mock_wifi.Cell.all.return_value = [fake_cell]

        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "linux"
        results = owner.scan_network()
        assert results == []

    def test_scan_unsupported_platform(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "win32"
        results = owner.scan_network()
        assert results == []

    def test_scan_handles_interface_error(self, dpwo_module, mock_wifi):
        mock_wifi.Cell.all.side_effect = Exception("Interface not found")

        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "linux"
        results = owner.scan_network()
        assert results == []


class TestNETOwnerConnect:
    def test_connect_unsupported_platform(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "win32"
        result = owner.connect_net({"ssid": "test", "wifi_password": "pass"})
        assert result is False

    def test_connect_handles_subprocess_error(self, dpwo_module):
        import subprocess
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "darwin"
        with patch("subprocess.check_output", side_effect=subprocess.CalledProcessError(1, "cmd")):
            result = owner.connect_net({"ssid": "test", "wifi_password": "pass"})
        assert result is False
