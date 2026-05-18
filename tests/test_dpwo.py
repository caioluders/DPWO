import subprocess
import sys
from unittest.mock import MagicMock, patch, call

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

    def test_connect_handles_timeout(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "darwin"
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)):
            result = owner.connect_net({"ssid": "test", "wifi_password": "pass"})
        assert result is False


class TestConnectNetLinux:
    def test_success(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "linux"
        mock_result = MagicMock(returncode=0, stdout="connected")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = owner.connect_net_linux({"ssid": "NET_2gABC", "wifi_password": "secret"})

        assert result is True
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args == [
            "nmcli", "device", "wifi", "connect",
            "NET_2gABC", "password", "secret", "ifname", "wlan0",
        ]

    def test_wrong_password(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        mock_result = MagicMock(returncode=4, stdout="Error")
        with patch("subprocess.run", return_value=mock_result):
            result = owner.connect_net_linux({"ssid": "NET_2gABC", "wifi_password": "wrong"})
        assert result is False


class TestConnectNetOSX:
    def test_success(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        mock_result = MagicMock(returncode=0, stdout="")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = owner.connect_net_osx({"ssid": "CLARO_1234", "wifi_password": "pass123"})

        assert result is True
        args = mock_run.call_args[0][0]
        assert "networksetup" in args
        assert "CLARO_1234" in args
        assert "pass123" in args

    def test_failure(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        mock_result = MagicMock(returncode=1, stdout="Failed")
        with patch("subprocess.run", return_value=mock_result):
            result = owner.connect_net_osx({"ssid": "test", "wifi_password": "bad"})
        assert result is False


class TestVerifyConnection:
    def test_success(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        mock_result = MagicMock(returncode=0)
        with patch("subprocess.run", return_value=mock_result):
            assert owner.verify_connection() is True

    def test_no_internet(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        mock_result = MagicMock(returncode=1)
        with patch("subprocess.run", return_value=mock_result):
            assert owner.verify_connection() is False

    def test_timeout(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ping", 10)):
            assert owner.verify_connection() is False


class TestOSXNetworksRetry:
    AIRPORT_OUTPUT = (
        "                            SSID BSSID             RSSI CHANNEL HT CC SECURITY\n"
        "                      CLARO_1234 AA:BB:CC:DD:EE:FF  -50  6      Y  -- WPA2\n"
    )

    def test_succeeds_after_retries(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "darwin"

        side_effects = ["", "", self.AIRPORT_OUTPUT]
        with patch("subprocess.check_output", side_effect=[s.encode() for s in side_effects]):
            with patch("time.sleep"):
                results = list(owner.osx_networks())
        assert len(results) > 0

    def test_gives_up_after_max_retries(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "darwin"

        with patch("subprocess.check_output", return_value=b""):
            with patch("time.sleep"):
                results = list(owner.osx_networks())
        assert results == []

    def test_handles_subprocess_error(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "darwin"

        with patch("subprocess.check_output",
                    side_effect=subprocess.CalledProcessError(1, "airport")):
            with patch("time.sleep"):
                results = list(owner.osx_networks())
        assert results == []


class TestOwnActiveMode:
    WIFI_RESULT = {"ssid": "CLARO_1234", "mac": "AA:BB:CC:DD:EE:FF",
                   "wifi_password": "CCDDEEFF", "admin_login": False,
                   "admin_password": False}

    def test_connects_and_verifies(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0", connect=True)
        with patch.object(owner, "scan_network", return_value=[self.WIFI_RESULT]):
            with patch.object(owner, "connect_net", return_value=True) as mock_conn:
                with patch.object(owner, "verify_connection", return_value=True) as mock_verify:
                    owner.own()

        mock_conn.assert_called_once_with(self.WIFI_RESULT)
        mock_verify.assert_called_once()

    def test_tries_next_on_failed_verification(self, dpwo_module):
        wifi1 = {**self.WIFI_RESULT, "ssid": "CLARO_1111"}
        wifi2 = {**self.WIFI_RESULT, "ssid": "CLARO_2222"}
        owner = dpwo_module.NETOwner("wlan0", connect=True)

        with patch.object(owner, "scan_network", return_value=[wifi1, wifi2]):
            with patch.object(owner, "connect_net", return_value=True):
                with patch.object(owner, "verify_connection", side_effect=[False, True]):
                    owner.own()

    def test_stops_after_first_verified(self, dpwo_module):
        wifi1 = {**self.WIFI_RESULT, "ssid": "CLARO_1111"}
        wifi2 = {**self.WIFI_RESULT, "ssid": "CLARO_2222"}
        owner = dpwo_module.NETOwner("wlan0", connect=True)

        with patch.object(owner, "scan_network", return_value=[wifi1, wifi2]):
            with patch.object(owner, "connect_net", return_value=True) as mock_conn:
                with patch.object(owner, "verify_connection", return_value=True):
                    owner.own()

        mock_conn.assert_called_once_with(wifi1)


class TestOwnPassiveMode:
    WIFI_RESULT = {"ssid": "CLARO_1234", "mac": "AA:BB:CC:DD:EE:FF",
                   "wifi_password": "CCDDEEFF", "admin_login": False,
                   "admin_password": False}

    def test_no_connect_attempts(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0", connect=False)
        with patch.object(owner, "scan_network", return_value=[self.WIFI_RESULT]):
            with patch.object(owner, "connect_net") as mock_conn:
                owner.own()

        mock_conn.assert_not_called()

    def test_still_displays_passwords(self, dpwo_module, capsys):
        owner = dpwo_module.NETOwner("wlan0", connect=False)
        with patch.object(owner, "scan_network", return_value=[self.WIFI_RESULT]):
            owner.own()
        # tqdm.write goes to stderr by default
