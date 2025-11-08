# Proxmox VM Monitor Script

This Python script connects to a Proxmox VE (Virtual Environment) API to perform two functions:

1. **List Status**: It prints a report of all nodes and the current status of their KVMs (QEMU) and Containers (LXC).
2. **Rule-Based Monitoring**: It fetches performance data for each VM and checks it against a set of rules defined in `rules.json`. If a rule is broken, it prints the configured action.

It reads its API configuration (`PROXMOX_URL`, `PROXMOX_USER`, `PROXMOX_PASS`) from environment variables.

## Features

- Securely reads API credentials from environment variables.
- Authenticates and maintains an API session.
- Handles self-signed SSL certificates.
- Lists all nodes and their online status.
- Lists all VMs and Containers and their running status.
- Loads monitoring rules from an external `rules.json` file.
- Fetches RRD performance data (CPU, memory, etc.) for each VM.
- Analyzes performance data using a sliding window based on rule parameters (`interval`, `threshold`, `ratio`).
- Prints alerts and actions when a rule is broken.

## Requirements

The script requires the `requests` library.

```
pip install requests
```

## How to Use

1. **Save the Files**:

   - Save the main script as `proxmox_monitor.py`.
   - Save the rule configuration as `rules.json` in the same directory.

2. **Configure `rules.json`**: Edit `rules.json` to define your monitoring rules. Each rule is an object with the following keys:

   - `name`: A descriptive name for the rule.
   - `timeframe`: The time period to fetch data for (e.g., `hour`, `day`, `week`). Must be a valid Proxmox RRD timeframe.
   - `resource`: The resource to check (e.g., `cpu`, `mem`, `disk`). This must match the key in the RRD data response.
   - `threshold`: The usage ratio (0.0 to 1.0) that is considered a violation. (e.g., `0.8` for 80%).
   - `interval`: The continuous duration (in seconds) to check for a violation (e.g., `3600` for 1 hour).
   - `ratio`: The percentage of data points (0.0 to 1.0) within the `interval` that must exceed the `threshold` to trigger the rule (e.g., `0.9` for 90%).
   - `action`: A string describing what to do (e.g., `"send email"`, `"restart vm"`). The script currently just prints this.

3. **Set Environment Variables**: Before running the script, you must set the API credentials.

   **On Linux/macOS:**

   ```
   export PROXMOX_URL="https://your-proxmox-ip-or-domain:8006"
   export PROXMOX_USER="root@pam"
   export PROXMOX_PASS="your_secret_password"
   ```

   **On Windows (Command Prompt):**

   ```
   set PROXMOX_URL="https://your-proxmox-ip-or-domain:8006"
   set PROXMOX_USER="root@pam"
   set PROXMOX_PASS="your_secret_password"
   ```

4. **Run the Script**: Execute the script from your terminal:

   ```
   python monitor.py
   ```

5. **View Output**: The script will log in, list all VMs, and then print any alerts that are triggered.

   ```
   --- Proxmox Monitor Script ---
   Target URL: https://**.fossvps.org
   Target User: USERNAME
   Attempting login to https://**.fossvps.org as USERNAME...
   Login SUCCESSFUL.
   
   Loading monitoring rules from rules.json...
   Successfully loaded 2 rules.
   
   Fetching nodes...
   Found 1 nodes:
   
     - uk1 (Status: online)
   
   --- VM/Container Status Report ---
   
   Node: 'uk1'
     [KVM  204] 2a06-7e00-0000-1a00-0008  -> RUNNING
     [KVM  211] 2a06-7e00-0000-1a00-000e  -> RUNNING
     [KVM  100] ubuntu-24.04.3-template   -> STOPPED
     [KVM  101] debian-13.1.0-template    -> STOPPED
     [KVM  210] foss-uk-pbs               -> RUNNING
     [KVM  206] 2a06-7e00-0000-1a00-000a  -> RUNNING
     [KVM  102] alpine-3.22.2-template    -> STOPPED
     [KVM  208] inception                 -> RUNNING
     [KVM  212] 2a06-7e00-0000-1a00-000f  -> RUNNING
     -> ALERT: VM 212 (2a06-7e00-0000-1a00-000f) broke rule 'High CPU Usage (Day)'
        Resource: cpu, Window Ratio: 1.00 >= 0.9
        Time Window: 2025-11-08 05:07:00 to 2025-11-08 05:11:00
     -> ALERT: VM 212 (2a06-7e00-0000-1a00-000f) broke rule 'High network in Usage (Day)'
        Resource: netin, Window Ratio: 1.00 >= 0.9
        Time Window: 2025-11-08 05:03:00 to 2025-11-08 05:07:00
     -> ALERT: VM 212 (2a06-7e00-0000-1a00-000f) broke rule 'High network out Usage (Day)'
        Resource: netout, Window Ratio: 1.00 >= 0.9
        Time Window: 2025-11-08 05:03:00 to 2025-11-08 05:07:00
       -> ACTIONS: send email
     [KVM  205] 2a06-7e00-0000-1a00-0003  -> RUNNING
     [KVM  209] foss-webserver            -> RUNNING
   
   --- Monitoring complete ---


   ```
