from abc import ABC, abstractmethod, abstractproperty
from dojo.models import Finding

class Parser(ABC):

    @property
    @abstractproperty
    def scan_types(self) -> list[str]:
        """List of the scan types"""
        raise NotImplementedError
    
    @abstractmethod
    def get_label_for_scan_types(self, scan_type:str) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_description_for_scan_types(self, scan_type:str) -> str:
        raise NotImplementedError
    
    @abstractmethod
    def get_findings(self, scan, test) -> list[Finding]:
        """Parse the scan input to generate a Finding list"""
        raise NotImplementedError
    
    def requires_file(self, scan_type:str) -> bool:
        """Return True if the scan need a file. Default value is True since most of scans need one"""
        return True
