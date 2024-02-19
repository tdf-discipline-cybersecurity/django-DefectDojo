import logging
import json, re
from dojo.models import Finding, Endpoint
from dojo.tools.parser import Parser

logger = logging.getLogger(__name__)

class FuffParser(Parser):
    scan_types = ["Ffuf Scan"]

    def get_label_for_scan_types(self, scan_type: str) -> str:
        return "FFUF Scan"
    
    def get_description_for_scan_types(self, scan_type: str) -> str:
        return "Import JSON output for FUFF scan report."
    
    def requires_file(self, scan_type: str) -> bool:
        return True

    def get_findings(self, file, test) -> list[Finding]:
        filecontent = file.read()
        if not filecontent:
            return []
        if isinstance(filecontent, bytes):
            filecontent = filecontent.decode("utf-8")
        try:
            data = json.loads(filecontent)["results"]
        except json.JSONDecodeError:
            try:
                data = [json.loads(line) for line in filecontent.split('\n') if line]
            except BaseException as e:
                logger.error(f"Failed to decode json: {e}")
                raise e
        except BaseException as e:
                logger.error(f"Failed to decode json: {e}")
                raise e
        else:
            res = []
            for item in data:
                logger.debug(f"Item {item}")
                url = item.get("url", "")
                fuzz = item.get("input", {}).get("FUZZ", "")
                r = r"(?:.*\/)?([^\/\?]*)(\?.*)?"
                match = re.match(r, fuzz)
                title = "ffuf-"+match.group(1)
                description = f"Input: {fuzz}\nContent Type: {item['content-type']}\nURL: {url}"
                #description = json.dumps(item, indent=2)
                finding = Finding(
                    title=title,
                    test=test,
                    severity="Info",
                    description=description
                )
                finding.unsaved_endpoints.append(Endpoint.from_uri(url))
                res.append(finding)
            return res

