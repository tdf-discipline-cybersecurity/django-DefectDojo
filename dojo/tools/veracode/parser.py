from dojo.tools.veracode.json_parser import VeracodeJSONParser
from dojo.tools.veracode.xml_parser import VeracodeXMLParser
from dojo.tools.parser import Parser


class VeracodeParser(Parser):
    scan_types = ["Veracode Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Veracode Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Reports can be imported as JSON or XML report formats."
        )

    def get_findings(self, filename, test):
        if filename.name.lower().endswith(".xml"):
            return VeracodeXMLParser().get_findings(filename, test)
        elif filename.name.lower().endswith(".json"):
            return VeracodeJSONParser().get_findings(filename, test)
        else:
            raise ValueError(
                "Filename extension not recognized. Use .xml or .json"
            )
