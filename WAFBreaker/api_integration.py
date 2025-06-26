import requests

class BurpSuiteAPI:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url.rstrip('/')
    
    def send_to_repeater(self, payload):
        """Send payload to Burp Repeater"""
        # This is a simplified example - real implementation would use Burp's REST API
        # Requires Burp Suite Professional with REST API enabled
        try:
            response = requests.post(
                f"{self.base_url}/burp/repeater",
                json={"payload": payload},
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return True
        except Exception:
            return False

class ZapAPI:
    def __init__(self, base_url="http://localhost:8090"):
        self.base_url = base_url.rstrip('/')
        self.api_key = "your-zap-api-key"  # Should be configured in ZAP
    
    def send_to_active_scanner(self, payload):
        """Send payload to ZAP Active Scanner"""
        try:
            response = requests.get(
                f"{self.base_url}/JSON/ascan/action/scan/",
                params={
                    "url": f"http://example.com/vuln?input={payload}",
                    "apikey": self.api_key
                }
            )
            response.raise_for_status()
            return True
        except Exception:
            return False
