from abc import ABC, abstractmethod

class PluginInterface(ABC):

    @abstractmethod
    def is_vuln(ssid: str) -> bool:
        pass

    @abstractmethod
    def own(ssid: str, mac: str) -> dict:
        pass