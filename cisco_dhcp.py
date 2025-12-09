# cisco_dhcp_automation.py - Enhanced logging with debug mode
from netmiko import ConnectHandler
import json
import sys
import os
import time
from datetime import datetime
import socket
from urllib.parse import quote

class CiscoDHCPAutomation:
    def __init__(self):
        # --- REDACTED: Device Credentials ---
        self.credentials = [
            {
                'username': '[REDACTED_USER_1]',
                'password': '[REDACTED_PASS_1]',
                'secret': '[REDACTED_SECRET_1]',
                'description': 'ISE AAA'
            },
            {
                'username': '[REDACTED_USER_2]',
                'password': '[REDACTED_PASS_2]',
                'secret': '[REDACTED_SECRET_2]',
                'description': 'Wannoc'
            }
        ]
        
    def log_connection_attempt(self, router_ip, credential, attempt_number, encoded_password, encoded_secret, debug_passwords):
        """Log detailed connection attempt information, hiding sensitive data if not in debug mode."""
        print("\n" + "=" * 60)
        print("CONNECTION ATTEMPT DETAILS")
        print("=" * 60)
        # ... (logging details)
        
        # Check environment variable for password visibility
        if debug_passwords:
            print(f"Original Password: {credential['password']}")
            # ... (show other credentials)
        else:
            print(f"Password: [HIDDEN - Enable DEBUG_PASSWORDS in .env to view]")
            # ... (hide other credentials)
            
        print("=" * 60)
        
    def test_network_connectivity(self, router_ip):
        """Test basic network connectivity (TCP Port 22) before attempting SSH."""
        print(f"\nTesting network connectivity to {router_ip}...")
        try:
            # Short timeout for socket connection
            socket.setdefaulttimeout(5)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            start_time = time.time()
            result = sock.connect_ex((router_ip, 22))
            connect_time = round((time.time() - start_time) * 1000, 2)
            sock.close()
            
            if result == 0:
                print(f"[SUCCESS] Network connectivity - Port 22 is open (Response time: {connect_time}ms)")
                return True, connect_time
            else:
                print(f"[FAILED] Network connectivity - Port 22 is closed or unreachable")
                return False, connect_time
        except Exception as e:
            print(f"[ERROR] Network connectivity: {str(e)}")
            return False, 0
    
    def execute_store_commands(self, router_ip, store_commands):
        """
        Attempts to connect to the router using all configured credentials until success.
        Executes a pre-clearance command, then configures all store-specific commands.
        """
        print("=== Starting Cisco DHCP Automation ===")
        print(f"Target Router: {router_ip}")
        # ... (debug mode logging)
        
        # 1. Test Network Connectivity
        network_ok, response_time = self.test_network_connectivity(router_ip)
        if not network_ok:
            # Return failure immediately if network test fails
            return {
                'success': False,
                # ... (failure result details)
            }
        
        start_time = time.time()
        results = {
            # ... (initial results dict)
        }
        
        attempt_number = 1
        # 2. Iterate through credentials for connection
        for cred in self.credentials:
            
            # Smart URL Encoding for specific credentials (e.g., WAN NOC)
            if cred['description'] == 'Wannoc':
                encoded_password = quote(cred['password'], safe='')
                encoded_secret = quote(cred['secret'], safe='') if cred['secret'] else ''
            else:
                encoded_password = cred['password']
                encoded_secret = cred['secret'] if cred['secret'] else ''
            
            self.log_connection_attempt(router_ip, cred, attempt_number, encoded_password, encoded_secret, debug_passwords)
            attempt_number += 1
            
            connection_attempt = {
                # ... (connection attempt tracking)
            }
            
            try:
                # 3. Connect using Netmiko
                device = {
                    'device_type': 'cisco_ios',
                    'host': router_ip,
                    'username': cred['username'],
                    'password': encoded_password,  
                    'secret': encoded_secret,      
                    'timeout': 120,
                    'session_timeout': 300,
                    'global_delay_factor': 3,
                }
                
                net_connect = ConnectHandler(**device)
                
                # 4. Enter enable mode
                net_connect.enable()
                
                # 5. EXECUTE DHCP BINDING CLEARANCE (EXEC MODE)
                print("\n   Executing DHCP binding clearance...")
                clearance_output = net_connect.send_command(
                    'clear ip dhcp binding *', 
                    expect_string=r'#',
                    delay_factor=2
                )
                
                # 6. Execute commands for each store
                store_results = []
                for store_data in store_commands:
                    # ... (command execution loop)
                    commands = store_data.get('commands', [])
                    
                    try:
                        for i, cmd in enumerate(commands, 1):
                            if not cmd.strip() or cmd.startswith('!'):
                                continue
                            
                            # Send command and wait for prompt (r'#|\(config\)|\(config-line\)|\(config-if\)')
                            output = net_connect.send_command(
                                cmd, 
                                expect_string=r'#|\(config\)|\(config-line\)|\(config-if\)',
                                delay_factor=2
                            )
                            # ... (tracking and logging command execution)
                            
                            time.sleep(0.3) # Small delay for stability
                        
                        # ... (success logging)
                        
                    except Exception as store_error:
                        # ... (store failure logging)
                        pass
                
                # 7. Save configuration
                if results['stores_processed'] > 0:
                    net_connect.save_config()
                
                # 8. Disconnect and update results
                net_connect.disconnect()
                results['success'] = results['stores_processed'] > 0
                results['used_credentials'] = cred['description']
                # ... (break to exit credential loop)
                break
                
            except Exception as e:
                # Connection or execution failure for this credential set
                error_msg = str(e)
                results['errors'].append(f"{cred['description']}: {error_msg}")
                # ... (continue to the next credential)
                continue
        
        # 9. Return final results
        results['execution_time'] = round(time.time() - start_time, 2)
        # ... (Print detailed summary)
        return results

def main():
    # ... (main function logic for handling input/output files)
    pass

if __name__ == "__main__":
    main()