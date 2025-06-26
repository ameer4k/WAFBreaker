import base64
import random
import string

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
