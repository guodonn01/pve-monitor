import requests
import sys
import os
import json
import datetime # Import datetime

# Disable warnings for self-signed certificates (common in Proxmox)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ProxmoxMonitor:
    """
    A class to connect to the Proxmox VE API, authenticate,
    and monitor VM/container statuses.
    """
    def __init__(self, base_url, username, password):
        """
        Initializes the monitor with connection details.

        Args:
            base_url (str): The base URL of the Proxmox API 
                            (e.g., "https://proxmox.example.com:8006")
            username (str): The Proxmox username (e.g., "root@pam")
            password (str): The user's password.
        """
        self.base_url = base_url.rstrip('/')  # Remove trailing slash
        self.api_url = f"{self.base_url}/api2/json"
        self.username = username
        self.password = password
        
        # We use a session to persist cookies (like the auth ticket)
        self.session = requests.Session()
        
        # Proxmox often uses self-signed certs, so we disable SSL verification.
        # WARNING: This is insecure for production environments talking to the internet.
        # For internal networks, it's a common practice.
        self.session.verify = False 
        
        self.auth_ticket = None
        self.csrf_token = None
        self.nodes = []
        self.rules = [] # Add rules list

    def login(self):
        """
        Authenticates with the Proxmox API as per the user's request.
        Stores the auth ticket and CSRF token for future requests.
        """
        login_url = f"{self.api_url}/access/ticket"
        payload = {
            "username": self.username,
            "password": self.password
        }
        
        print(f"Attempting login to {self.base_url} as {self.username}...")
        
        try:
            response = self.session.post(login_url, data=payload)
            
            # Check for HTTP errors (like 401 Unauthorized)
            response.raise_for_status() 
            
            data = response.json()
            
            # Extract credentials from the successful response
            self.auth_ticket = data['data']['ticket']
            self.csrf_token = data['data']['CSRFPreventionToken']
            
            # Set the credentials for all future requests in this session
            self.session.cookies['PVEAuthCookie'] = self.auth_ticket
            self.session.headers['CSRFPreventionToken'] = self.csrf_token
            
            print("Login SUCCESSFUL.")
            return True
            
        except requests.exceptions.HTTPError as e:
            print(f"Login FAILED. HTTP Error: {e.response.status_code} {e.response.reason}")
            if e.response.status_code == 401:
                print("Please check your username and password.")
        except requests.exceptions.ConnectionError as e:
            print(f"Login FAILED. Connection Error: Could not connect to {self.base_url}")
            print(f"Details: {e}")
        except KeyError:
            print("Login FAILED. Received unexpected response from server.")
            print(f"Response: {response.text}")
        except Exception as e:
            print(f"An unexpected error occurred during login: {e}")
            
        return False

    def _api_get(self, endpoint, params=None):
        """Helper method to make authenticated GET requests."""
        if not self.auth_ticket:
            print("Not authenticated. Please call login() first.")
            return None
            
        url = f"{self.api_url}{endpoint}"
        try:
            response = self.session.get(url, params=params) # Add params
            response.raise_for_status()
            # The 'data' key holds the actual list or object
            return response.json().get('data') 
        except requests.exceptions.HTTPError as e:
            print(f"API Error on GET {endpoint}: {e.response.status_code} {e.response.reason}")
            # Add more detail for 404
            if e.response.status_code == 404:
                print(f"  -> Endpoint not found. Check node, vm_type, and vmid.")
        except Exception as e:
            print(f"An unexpected error occurred during API request: {e}")
        return None

    def get_nodes(self):
        """Fetches a list of all nodes in the cluster."""
        print("\nFetching nodes...")
        self.nodes = self._api_get("/nodes")
        if self.nodes:
            print(f"Found {len(self.nodes)} nodes:")
            for node in self.nodes:
                print(f"  - {node['node']} (Status: {node['status']})")
        return self.nodes

    def get_all_vms_by_node(self, node_name):
        """Fetches all QEMU (KVM) and LXC (Container) VMs for a specific node."""
        qemu_vms = self._api_get(f"/nodes/{node_name}/qemu")
        lxc_vms = self._api_get(f"/nodes/{node_name}/lxc")
        return {
            "qemu": qemu_vms if qemu_vms else [],
            "lxc": lxc_vms if lxc_vms else []
        }

    def get_vm_status(self, node_name, vmid, vm_type="qemu"):
        """
        Fetches the current status of a specific VM or Container.
        
        Args:
            node_name (str): The node the VM is on (e.g., "pve")
            vmid (int): The ID of the VM (e.g., 100)
            vm_type (str): "qemu" for KVM or "lxc" for container.
        """
        status = self._api_get(f"/nodes/{node_name}/{vm_type}/{vmid}/status/current")
        return status

    def load_rules(self, config_file="rules.json"):
        """Loads monitoring rules from a JSON config file."""
        print(f"\nLoading monitoring rules from {config_file}...")
        try:
            with open(config_file, 'r') as f:
                self.rules = json.load(f)
            if not isinstance(self.rules, list):
                print(f"Error: {config_file} must contain a JSON list of rules.")
                return False
            print(f"Successfully loaded {len(self.rules)} rules.")
            return True
        except FileNotFoundError:
            print(f"Error: Rules file not found at {config_file}")
            return False
        except json.JSONDecodeError:
            print(f"Error: Could not decode JSON from {config_file}")
            return False
        except Exception as e:
            print(f"An unexpected error occurred loading rules: {e}")
            return False

    def get_vm_rrd_data(self, node, vmid, vm_type, timeframe):
        """
        Fetches RRD (Round-Robin Database) performance data for a VM.
        """
        endpoint = f"/nodes/{node}/{vm_type}/{vmid}/rrddata"
        params = {
            "timeframe": timeframe,
            "cf": "AVERAGE" # As per user example
        }
        return self._api_get(endpoint, params=params)

    def check_vm_rules(self, node, vmid, vm_type, vm_name):
        """
        Analyzes a VM's performance data against all loaded rules.
        Returns a list of unique actions to be taken.
        """
        triggered_actions = []
        
        # Check all rules for this VM
        for rule in self.rules:
            try:
                # 1. Get RRD data for the rule's timeframe
                rrd_data = self.get_vm_rrd_data(node, vmid, vm_type, rule['timeframe'])

                if not rrd_data or len(rrd_data) < 2:
                    # Not enough data to analyze
                    continue
                
                # 2. Calculate average interval between data points
                time_span = rrd_data[-1]['time'] - rrd_data[0]['time']
                avg_interval = time_span / (len(rrd_data) - 1)
                
                if avg_interval <= 0:
                    continue # Avoid division by zero, data is invalid

                # 3. Determine window size (in number of data points)
                rule_interval_sec = rule['interval']
                num_points_in_window = max(1, int(rule_interval_sec / avg_interval))

                if len(rrd_data) < num_points_in_window:
                    # Not enough data for even one window
                    continue

                # 4. Get rule parameters
                resource_key = rule['resource'].strip() # "cpu", "mem"
                max_resource_key = f"max{resource_key}" # "maxcpu", "maxmem"
                threshold = rule['threshold']           # 0.8
                ratio_threshold = rule['ratio']         # 0.9

                # 5. Slide the window over the data
                rule_broken = False
                for i in range(len(rrd_data) - num_points_in_window + 1):
                    window = rrd_data[i : i + num_points_in_window]
                    violating_points = 0
                    
                    # 6. Analyze points within the window
                    for point in window:
                        current_value = point.get(resource_key)
                        max_value = point.get(max_resource_key)

                        if current_value is None:
                            continue

                        # Calculate the usage ratio
                        if resource_key == "mem":
                            # Skip point if data is missing or invalid
                            if current_value is None or max_value is None or max_value == 0:
                                continue
                            else:
                                current_ratio = current_value / max_value
                        else:
                            current_ratio = current_value
                        
                        if current_ratio > threshold:
                            violating_points += 1
                    
                    # 7. Check if this window breaks the rule
                    window_violation_ratio = violating_points / num_points_in_window
                    
                    if window_violation_ratio >= ratio_threshold:
                        # Rule is broken.
                        # Get time window
                        start_time_ts = window[0]['time']
                        end_time_ts = window[-1]['time']
                        
                        # Format timestamps
                        start_time_str = datetime.datetime.fromtimestamp(start_time_ts).strftime('%Y-%m-%d %H:%M:%S')
                        end_time_str = datetime.datetime.fromtimestamp(end_time_ts).strftime('%Y-%m-%d %H:%M:%S')

                        print(f"  -> ALERT: VM {vmid} ({vm_name}) broke rule '{rule['name']}'")
                        print(f"     Resource: {resource_key}, Window Ratio: {window_violation_ratio:.2f} >= {ratio_threshold}")
                        print(f"     Time Window: {start_time_str} to {end_time_str}")
                        triggered_actions.append(rule['action'])
                        rule_broken = True
                        break # Stop checking this rule, move to the next rule
                
                if rule_broken:
                    continue # Move to the next rule

            except Exception as e:
                print(f"  -> Error checking rule '{rule.get('name', 'Unnamed')}' for VM {vmid}: {e}")

        # Return unique list of actions
        return list(set(triggered_actions))

    def run_monitor(self):
        """
        Runs a full monitoring pass:
        1. Logs in.
        2. Gets all nodes.
        3. For each node, gets all VMs.
        4. For each VM, prints its name and status.
        5. For each VM, checks monitoring rules and prints actions.
        """
        if not self.login():
            sys.exit(1) # Exit script if login fails
            
        # Load monitoring rules
        if not self.load_rules():
             print("Monitoring rules failed to load. Halting monitoring task.")
             sys.exit(1)
            
        if not self.get_nodes():
            print("No nodes found or API error.")
            sys.exit(1)
            
        print("\n--- VM/Container Status Report ---")
        
        for node in self.nodes:
            node_name = node['node']
            if node['status'] != 'online':
                print(f"\nSkipping node '{node_name}' (Status: {node['status']})")
                continue

            print(f"\nNode: '{node_name}'")
            all_vms = self.get_all_vms_by_node(node_name)
            
            # Process KVM VMs
            if not all_vms['qemu'] and not all_vms['lxc']:
                print("  No VMs or Containers found on this node.")
                continue

            for vm in all_vms['qemu']:
                vmid = vm['vmid']
                name = vm['name']
                status = vm['status']
                print(f"  [KVM {vmid: >4}] {name: <25} -> {status.upper()}")
                
                # Check rules for this VM
                actions = self.check_vm_rules(node_name, vmid, "qemu", name)
                if actions:
                    print(f"    -> ACTIONS: {', '.join(actions)}")

            # Process LXC Containers
            for lxc in all_vms['lxc']:
                vmid = lxc['vmid']
                name = lxc.get('name', 'N/A') # Name might not exist
                status = lxc['status']
                print(f"  [LXC {vmid: >4}] {name: <25} -> {status.upper()}")
                
                # Check rules for this VM
                actions = self.check_vm_rules(node_name, vmid, "lxc", name)
                if actions:
                    print(f"    -> ACTIONS: {', '.join(actions)}")

        print("\n--- Monitoring complete ---")


if __name__ == "__main__":
    # --- Configuration ---
    # Read configuration from environment variables
    PROXMOX_URL = os.environ.get("PROXMOX_URL")
    PROXMOX_USER = os.environ.get("PROXMOX_USER")
    PROXMOX_PASS = os.environ.get("PROXMOX_PASS")
    # --- End Configuration ---
    
    # Validate that all required environment variables are set
    if not all([PROXMOX_URL, PROXMOX_USER, PROXMOX_PASS]):
        print("Error: Missing one or more environment variables.")
        print("Please set PROXMOX_URL, PROXMOX_USER, and PROXMOX_PASS.")
        print("Example (Linux/macOS):")
        print("  export PROXMOX_URL=\"https://proxmox.example.com:8006\"")
        print("  export PROXMOX_USER=\"root@pam\"")
        print("  export PROXMOX_PASS=\"your_secret_password\"")
        print("Example (Windows CMD):")
        print("  set PROXMOX_URL=\"https://proxmox.example.com:8006\"")
        print("  set PROXMOX_USER=\"root@pam\"")
        print("  set PROXMOX_PASS=\"your_secret_password\"")
        sys.exit(1)

    print("--- Proxmox Monitor Script ---")
    print(f"Target URL: {PROXMOX_URL}")
    print(f"Target User: {PROXMOX_USER}")
    
    # Create the monitor instance and run it
    monitor = ProxmoxMonitor(PROXMOX_URL, PROXMOX_USER, PROXMOX_PASS)
    monitor.run_monitor()
