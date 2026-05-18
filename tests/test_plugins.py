MAC = "AA:BB:CC:DD:EE:FF"


class TestNETPlugin:
    def test_is_vuln_lowercase_g(self, net_plugin):
        assert net_plugin.is_vuln("NET_2gXYZ", MAC) is True

    def test_is_vuln_uppercase_g(self, net_plugin):
        assert net_plugin.is_vuln("NET_2GABC", MAC) is True

    def test_is_vuln_rejects_other_ssid(self, net_plugin):
        assert net_plugin.is_vuln("VIVO-1234", MAC) is False
        assert net_plugin.is_vuln("CLARO_5678", MAC) is False
        assert net_plugin.is_vuln("MyHomeWiFi", MAC) is False

    def test_own_password_derivation(self, net_plugin):
        result = net_plugin.own("NET_2gABCD", "AA:BB:CC:DD:EE:FF")
        # mac.upper().split(":")[2:3] = ["CC"], ssid.split("_")[1][2:] = "ABCD"
        assert result["wifi_password"] == "CCABCD"
        assert result["ssid"] == "NET_2gABCD"
        assert result["mac"] == "AA:BB:CC:DD:EE:FF"
        assert result["admin_login"] == "NET_2gABCD"
        assert result["admin_password"] == "NET_AABBCCDDEEFF"

    def test_brute_flag(self, net_plugin):
        assert net_plugin.brute is False


class TestVIVOPlugin:
    def test_is_vuln_matches(self, vivo_plugin):
        assert vivo_plugin.is_vuln("VIVO-1234", MAC) is True
        assert vivo_plugin.is_vuln("VIVO-ABCD", MAC) is True

    def test_is_vuln_rejects(self, vivo_plugin):
        assert vivo_plugin.is_vuln("VIVOFIBRA-1234", MAC) is False
        assert vivo_plugin.is_vuln("NET_2gABC", MAC) is False

    def test_own_password_derivation(self, vivo_plugin):
        result = vivo_plugin.own("VIVO-1234", "aa:bb:cc:dd:ee:ff")
        # mac.replace(":","").upper()[2:] = "BBCCDDEEFF"
        assert result["wifi_password"] == "BBCCDDEEFF"
        assert result["admin_login"] is False
        assert result["admin_password"] is False

    def test_brute_flag(self, vivo_plugin):
        assert vivo_plugin.brute is False


class TestVIVOFIBRAPlugin:
    def test_is_vuln_matches(self, vivofibra_plugin):
        assert vivofibra_plugin.is_vuln("VIVOFIBRA-ABC", MAC) is True

    def test_is_vuln_rejects(self, vivofibra_plugin):
        assert vivofibra_plugin.is_vuln("VIVO-1234", MAC) is False
        assert vivofibra_plugin.is_vuln("VIVOFIBRA1234", MAC) is False

    def test_own_password_derivation(self, vivofibra_plugin):
        result = vivofibra_plugin.own("VIVOFIBRA-ABC", "aa:bb:cc:dd:ee:ff")
        # mac no-colon lower [2:8] = "bbccdd" + ssid.split("-")[1].lower() = "abc"
        assert result["wifi_password"] == "bbccddabc"

    def test_brute_flag(self, vivofibra_plugin):
        assert vivofibra_plugin.brute is False


class TestCLAROPlugin:
    def test_is_vuln_matches(self, claro_plugin):
        assert claro_plugin.is_vuln("CLARO_5678", MAC) is True
        assert claro_plugin.is_vuln("CLARO_ABCD", MAC) is True

    def test_is_vuln_rejects(self, claro_plugin):
        assert claro_plugin.is_vuln("NET_2gABC", MAC) is False
        assert claro_plugin.is_vuln("VIVO-1234", MAC) is False

    def test_own_password_derivation(self, claro_plugin):
        result = claro_plugin.own("CLARO_5678", "aa:bb:cc:dd:ee:ff")
        # mac.replace(":","").upper()[4:] = "CCDDEEFF"
        assert result["wifi_password"] == "CCDDEEFF"
        assert result["admin_login"] is False
        assert result["admin_password"] is False

    def test_brute_flag(self, claro_plugin):
        assert claro_plugin.brute is False


class TestBrutePlugin:
    def test_is_vuln_always_false(self, brute_plugin):
        assert brute_plugin.is_vuln("ANYTHING", MAC) is False
        assert brute_plugin.is_vuln("NET_2gABC", MAC) is False

    def test_own_returns_multiple_candidates(self, brute_plugin):
        results = brute_plugin.own("TestSSID", "aa:bb:cc:dd:ee:ff")
        assert isinstance(results, list)
        assert len(results) == 4
        for r in results:
            assert "wifi_password" in r
            assert r["ssid"] == "TestSSID"
            assert r["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_own_password_variants(self, brute_plugin):
        results = brute_plugin.own("X", "aa:bb:cc:dd:ee:ff")
        passwords = [r["wifi_password"] for r in results]
        assert "CCDDEEFF" in passwords    # upper [4:]
        assert "BBCCDDEEFF" in passwords  # upper [2:]
        assert "bbccddeeff" in passwords  # lower [2:]
        assert "ccddeeff" in passwords    # lower [4:]

    def test_brute_flag(self, brute_plugin):
        assert brute_plugin.brute is False
