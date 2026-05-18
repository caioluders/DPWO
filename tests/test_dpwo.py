import os
import subprocess
import sys
import tempfile
from unittest.mock import MagicMock, patch, call

import pytest


@pytest.fixture
def dpwo_module():
    """Import dpwo module (reimport to avoid stale state)."""
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
    NMCLI_OUTPUT = "CLARO_1234:AA\\:BB\\:CC\\:DD\\:EE\\:FF:80:6\n"

    def test_scan_finds_vulnerable_network(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "linux"
        with patch("subprocess.check_output",
                    return_value="CLARO_1234:AA\\:BB\\:CC\\:DD\\:EE\\:FF:80:6\n"):
            results = owner.scan_network()

        assert len(results) >= 1
        match = [r for r in results if r["ssid"] == "CLARO_1234"]
        assert len(match) == 1
        assert match[0]["wifi_password"] == "CCDDEEFF"

    def test_scan_ignores_non_vulnerable(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "linux"
        with patch("subprocess.check_output",
                    return_value="MyHomeWiFi:AA\\:BB\\:CC\\:DD\\:EE\\:FF:80:6\n"):
            results = owner.scan_network()
        assert results == []

    def test_scan_unsupported_platform(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "freebsd"
        results = owner.scan_network()
        assert results == []

    def test_scan_handles_interface_error(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "linux"
        with patch("subprocess.check_output",
                    side_effect=subprocess.CalledProcessError(1, "nmcli")):
            results = owner.scan_network()
        assert results == []


class TestNETOwnerConnect:
    def test_connect_unsupported_platform(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "freebsd"
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


class TestWindowsNetworks:
    NETSH_OUTPUT = (
        "Interface name : Wi-Fi\n"
        "There are 2 networks currently visible.\n"
        "\n"
        "SSID 1 : CLARO_1234\n"
        "    Network type            : Infrastructure\n"
        "    Authentication          : WPA2-Personal\n"
        "    Encryption              : CCMP\n"
        "    BSSID 1                 : aa:bb:cc:dd:ee:ff\n"
        "         Signal             : 80%\n"
        "\n"
        "SSID 2 : VIVO-5678\n"
        "    Network type            : Infrastructure\n"
        "    Authentication          : WPA2-Personal\n"
        "    Encryption              : CCMP\n"
        "    BSSID 1                 : 11:22:33:44:55:66\n"
        "         Signal             : 60%\n"
    )

    def test_parses_networks(self, dpwo_module):
        owner = dpwo_module.NETOwner("Wi-Fi")
        owner.os = "win32"
        with patch("subprocess.check_output", return_value=self.NETSH_OUTPUT):
            results = list(owner.windows_networks())
        assert len(results) == 2
        assert results[0] == ["CLARO_1234", "aa:bb:cc:dd:ee:ff"]
        assert results[1] == ["VIVO-5678", "11:22:33:44:55:66"]

    def test_scan_error(self, dpwo_module):
        owner = dpwo_module.NETOwner("Wi-Fi")
        owner.os = "win32"
        with patch("subprocess.check_output",
                    side_effect=subprocess.CalledProcessError(1, "netsh")):
            results = list(owner.windows_networks())
        assert results == []

    def test_scan_integration_with_scan_network(self, dpwo_module):
        owner = dpwo_module.NETOwner("Wi-Fi")
        owner.os = "win32"
        with patch("subprocess.check_output", return_value=self.NETSH_OUTPUT):
            results = owner.scan_network()
        claro = [r for r in results if r["ssid"] == "CLARO_1234"]
        assert len(claro) == 1
        assert claro[0]["wifi_password"] == "CCDDEEFF"


class TestConnectNetWindows:
    def test_success(self, dpwo_module):
        owner = dpwo_module.NETOwner("Wi-Fi")
        owner.os = "win32"
        add_result = MagicMock(returncode=0, stdout="", stderr="")
        connect_result = MagicMock(returncode=0, stdout="connected")
        with patch("subprocess.run", side_effect=[add_result, connect_result]) as mock_run:
            with patch("tempfile.NamedTemporaryFile", wraps=tempfile.NamedTemporaryFile):
                result = owner.connect_net_windows(
                    {"ssid": "CLARO_1234", "wifi_password": "CCDDEEFF"}
                )
        assert result is True

    def test_profile_add_failure(self, dpwo_module):
        owner = dpwo_module.NETOwner("Wi-Fi")
        owner.os = "win32"
        add_result = MagicMock(returncode=1, stdout="", stderr="Error")
        with patch("subprocess.run", return_value=add_result):
            result = owner.connect_net_windows(
                {"ssid": "CLARO_1234", "wifi_password": "wrong"}
            )
        assert result is False

    def test_connect_failure(self, dpwo_module):
        owner = dpwo_module.NETOwner("Wi-Fi")
        owner.os = "win32"
        add_result = MagicMock(returncode=0, stdout="", stderr="")
        connect_result = MagicMock(returncode=1, stdout="failed")
        with patch("subprocess.run", side_effect=[add_result, connect_result]):
            result = owner.connect_net_windows(
                {"ssid": "CLARO_1234", "wifi_password": "bad"}
            )
        assert result is False

    def test_via_connect_net_dispatcher(self, dpwo_module):
        owner = dpwo_module.NETOwner("Wi-Fi")
        owner.os = "win32"
        with patch.object(owner, "connect_net_windows", return_value=True) as mock_win:
            result = owner.connect_net({"ssid": "test", "wifi_password": "pass"})
        assert result is True
        mock_win.assert_called_once()


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

    def test_windows_ping_flags(self, dpwo_module):
        owner = dpwo_module.NETOwner("Wi-Fi")
        owner.os = "win32"
        mock_result = MagicMock(returncode=0)
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            owner.verify_connection()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["ping", "-n", "1", "-w", "3000", "8.8.8.8"]


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


class TestScanNetworkWithCallback:
    WIFI_RESULT = {"ssid": "CLARO_1234", "mac": "AA:BB:CC:DD:EE:FF",
                   "wifi_password": "CCDDEEFF", "admin_login": False,
                   "admin_password": False}

    def test_calls_on_result_per_network(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "linux"

        results_received = []
        with patch("subprocess.check_output",
                    return_value="CLARO_1234:AA\\:BB\\:CC\\:DD\\:EE\\:FF:80:6\n"):
            owner.scan_network_with_callback(
                on_result=lambda r: results_received.append(r),
            )
        assert len(results_received) >= 1
        assert results_received[0]["ssid"] == "CLARO_1234"

    def test_calls_on_done_with_all_results(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "linux"

        done_results = []
        with patch("subprocess.check_output",
                    return_value="CLARO_1234:AA\\:BB\\:CC\\:DD\\:EE\\:FF:80:6\n"):
            owner.scan_network_with_callback(
                on_done=lambda r: done_results.extend(r),
            )
        assert len(done_results) >= 1

    def test_calls_on_error_for_unsupported_platform(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "freebsd"

        errors = []
        owner.scan_network_with_callback(on_error=lambda e: errors.append(e))
        assert len(errors) == 1
        assert "freebsd" in errors[0]

    def test_empty_scan_calls_on_done(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "linux"

        done_called = []
        with patch("subprocess.check_output", return_value=""):
            owner.scan_network_with_callback(on_done=lambda r: done_called.append(r))
        assert len(done_called) == 1
        assert done_called[0] == []


class TestConnectAndVerify:
    def test_returns_connected(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        with patch.object(owner, "connect_net", return_value=True):
            with patch.object(owner, "verify_connection", return_value=True):
                assert owner.connect_and_verify({"ssid": "X"}) == "connected"

    def test_returns_no_internet(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        with patch.object(owner, "connect_net", return_value=True):
            with patch.object(owner, "verify_connection", return_value=False):
                assert owner.connect_and_verify({"ssid": "X"}) == "no_internet"

    def test_returns_failed(self, dpwo_module):
        owner = dpwo_module.NETOwner("wlan0")
        with patch.object(owner, "connect_net", return_value=False):
            assert owner.connect_and_verify({"ssid": "X"}) == "failed"


class TestLogCallback:
    def test_log_callback_is_used(self, dpwo_module):
        logs = []
        owner = dpwo_module.NETOwner("wlan0", log_callback=lambda m: logs.append(m))
        owner.os = "freebsd"
        owner.scan_network()
        assert any("freebsd" in msg for msg in logs)

    def test_default_uses_print(self, dpwo_module, capsys):
        owner = dpwo_module.NETOwner("wlan0")
        owner.os = "freebsd"
        owner.scan_network()
        captured = capsys.readouterr()
        assert "freebsd" in captured.out


class TestGetBasePath:
    def test_returns_script_dir(self, dpwo_module):
        result = dpwo_module._get_base_path()
        assert os.path.isdir(result)
        assert os.path.exists(os.path.join(result, "plugins"))

    def test_returns_meipass_when_frozen(self, dpwo_module):
        with patch.object(sys, "frozen", True, create=True):
            with patch.object(sys, "_MEIPASS", "/tmp/fake_meipass", create=True):
                assert dpwo_module._get_base_path() == "/tmp/fake_meipass"
