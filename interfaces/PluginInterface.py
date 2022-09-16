from abc import ABC, abstractmethod

class PluginInterface(ABC):
    '''The purpose of this interface is to ensure that all plugins will have the at least
    the "is_vuln" and "own" methods.
    '''

    @abstractmethod
    def is_vuln(ssid: str) -> bool:
        pass

    @abstractmethod
    def own(ssid: str, mac: str) -> dict:
        pass