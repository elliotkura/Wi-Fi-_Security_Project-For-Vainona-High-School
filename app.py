import streamlit as st
import pandas as pd
import time
import psutil
import socket
import subprocess
import nmap
import matplotlib.pyplot as plt
from datetime import datetime
import pytz
import sqlite3
from scapy.all import ARP, Ether, srp
import speedtest
import logging
import hashlib
import secrets
import string
import os
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(filename='wifi_system.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Database setup
def init_db():
    conn = sqlite3.connect('wifi_management.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password_hash TEXT,
                  salt TEXT,
                  user_type TEXT,
                  full_name TEXT,
                  email TEXT,
                  date_created TEXT,
                  last_login TEXT)''')
    
    # Devices table
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  mac_address TEXT UNIQUE,
                  ip_address TEXT,
                  hostname TEXT,
                  first_seen TEXT,
                  last_seen TEXT,
                  user_id INTEGER,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    # Network logs table
    c.execute('''CREATE TABLE IF NOT EXISTS network_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  event_type TEXT,
                  description TEXT,
                  severity TEXT,
                  device_id INTEGER,
                  FOREIGN KEY(device_id) REFERENCES devices(id))''')
    
    # Performance metrics table
    c.execute('''CREATE TABLE IF NOT EXISTS performance_metrics
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  download_speed REAL,
                  upload_speed REAL,
                  latency REAL,
                  packet_loss REAL,
                  bandwidth_usage REAL)''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Security functions
def generate_salt():
    return secrets.token_hex(16)

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()

def generate_fernet_key():
    return Fernet.generate_key()

def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

# Network scanning functions
def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

def get_local_ip(interface):
    try:
        addrs = psutil.net_if_addrs()[interface]
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address
        return None
    except KeyError:
        return None

def scan_network(interface, ip_range=None):
    devices = []
    try:
        # Get local IP and subnet
        local_ip = get_local_ip(interface)
        if not local_ip:
            st.error(f"Could not get IP address for interface {interface}")
            return devices
        
        if not ip_range:
            # Create IP range from local IP (assuming /24 subnet)
            ip_parts = local_ip.split('.')
            ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1/24"
        
        # Use ARP to find devices
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        result = srp(packet, timeout=3, verbose=0, iface=interface)[0]
        
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            
    except Exception as e:
        st.error(f"Error scanning network: {e}")
        logging.error(f"Network scan error: {e}")
    
    return devices

def get_connected_devices(interface):
    devices = []
    try:
        # Get ARP cache
        arp_cache = subprocess.check_output(['arp', '-a']).decode('ascii')
        
        # Parse ARP cache
        for line in arp_cache.splitlines():
            if interface in line:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[1].strip('()')
                    mac = parts[3]
                    if mac.count(':') == 5:  # Basic MAC address validation
                        devices.append({'ip': ip, 'mac': mac})
                        
    except Exception as e:
        st.error(f"Error getting connected devices: {e}")
        logging.error(f"Connected devices error: {e}")
    
    return devices

def perform_speed_test():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        ping = st.results.ping
        
        return download_speed, upload_speed, ping
    except Exception as e:
        st.error(f"Speed test failed: {e}")
        logging.error(f"Speed test error: {e}")
        return None, None, None

def check_open_ports(ip, ports='22,80,443,3389'):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, ports=ports)
        
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)
        
        return open_ports
    except Exception as e:
        st.error(f"Port scan failed: {e}")
        logging.error(f"Port scan error: {e}")
        return []

# User management functions
def create_user(username, password, user_type, full_name, email):
    conn = sqlite3.connect('wifi_management.db')
    c = conn.cursor()
    
    try:
        salt = generate_salt()
        password_hash = hash_password(password, salt)
        date_created = datetime.now(pytz.timezone('Africa/Harare')).strftime('%Y-%m-%d %H:%M:%S')
        
        c.execute("INSERT INTO users (username, password_hash, salt, user_type, full_name, email, date_created) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (username, password_hash, salt, user_type, full_name, email, date_created))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        st.error("Username already exists")
        return False
    except Exception as e:
        st.error(f"Error creating user: {e}")
        logging.error(f"User creation error: {e}")
        return False
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('wifi_management.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
        result = c.fetchone()
        
        if result:
            stored_hash, salt = result
            input_hash = hash_password(password, salt)
            
            if stored_hash == input_hash:
                # Update last login
                last_login = datetime.now(pytz.timezone('Africa/Harare')).strftime('%Y-%m-%d %H:%M:%S')
                c.execute("UPDATE users SET last_login=? WHERE username=?", (last_login, username))
                conn.commit()
                return True
        return False
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        return False
    finally:
        conn.close()

def get_user_type(username):
    conn = sqlite3.connect('wifi_management.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT user_type FROM users WHERE username=?", (username,))
        result = c.fetchone()
        return result[0] if result else None
    except Exception as e:
        logging.error(f"Get user type error: {e}")
        return None
    finally:
        conn.close()

# Device management functions
def register_device(mac_address, ip_address, hostname, user_id=None):
    conn = sqlite3.connect('wifi_management.db')
    c = conn.cursor()
    
    try:
        now = datetime.now(pytz.timezone('Africa/Harare')).strftime('%Y-%m-%d %H:%M:%S')
        
        # Check if device exists
        c.execute("SELECT id FROM devices WHERE mac_address=?", (mac_address,))
        device = c.fetchone()
        
        if device:
            # Update existing device
            c.execute("UPDATE devices SET ip_address=?, hostname=?, last_seen=?, user_id=? WHERE mac_address=?",
                      (ip_address, hostname, now, user_id, mac_address))
        else:
            # Insert new device
            c.execute("INSERT INTO devices (mac_address, ip_address, hostname, first_seen, last_seen, user_id) VALUES (?, ?, ?, ?, ?, ?)",
                      (mac_address, ip_address, hostname, now, now, user_id))
        
        conn.commit()
        return True
    except Exception as e:
        st.error(f"Error registering device: {e}")
        logging.error(f"Device registration error: {e}")
        return False
    finally:
        conn.close()

def get_all_devices():
    conn = sqlite3.connect('wifi_management.db')
    c = conn.cursor()
    
    try:
        c.execute("SELECT d.id, d.mac_address, d.ip_address, d.hostname, d.first_seen, d.last_seen, u.full_name FROM devices d LEFT JOIN users u ON d.user_id = u.id")
        devices = c.fetchall()
        
        device_list = []
        for device in devices:
            device_list.append({
                'id': device[0],
                'mac_address': device[1],
                'ip_address': device[2],
                'hostname': device[3],
                'first_seen': device[4],
                'last_seen': device[5],
                'user': device[6] if device[6] else 'Unassigned'
            })
        
        return device_list
    except Exception as e:
        logging.error(f"Get all devices error: {e}")
        return []
    finally:
        conn.close()

# Reporting functions
def get_network_metrics():
    conn = sqlite3.connect('wifi_management.db')
    c = conn.cursor()
    
    try:
        # Get metrics for the last 7 days
        c.execute("SELECT timestamp, download_speed, upload_speed, latency, packet_loss, bandwidth_usage FROM performance_metrics WHERE date(timestamp) >= date('now', '-7 days') ORDER BY timestamp")
        metrics = c.fetchall()
        
        metric_list = []
        for metric in metrics:
            metric_list.append({
                'timestamp': metric[0],
                'download_speed': metric[1],
                'upload_speed': metric[2],
                'latency': metric[3],
                'packet_loss': metric[4],
                'bandwidth_usage': metric[5]
            })
        
        return metric_list
    except Exception as e:
        logging.error(f"Get network metrics error: {e}")
        return []
    finally:
        conn.close()

def log_network_event(event_type, description, severity='INFO', device_id=None):
    conn = sqlite3.connect('wifi_management.db')
    c = conn.cursor()
    
    try:
        timestamp = datetime.now(pytz.timezone('Africa/Harare')).strftime('%Y-%m-%d %H:%M:%S')
        
        c.execute("INSERT INTO network_logs (timestamp, event_type, description, severity, device_id) VALUES (?, ?, ?, ?, ?)",
                  (timestamp, event_type, description, severity, device_id))
        conn.commit()
    except Exception as e:
        logging.error(f"Network event logging error: {e}")
    finally:
        conn.close()

# Streamlit UI
def main():
    st.set_page_config(page_title="Vainona High School Wi-Fi Management", layout="wide")
    
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'current_user' not in st.session_state:
        st.session_state.current_user = None
    if 'user_type' not in st.session_state:
        st.session_state.user_type = None
    
    # Login page
    if not st.session_state.authenticated:
        login_page()
        return
    
    # Main application
    st.sidebar.title(f"Welcome, {st.session_state.current_user}")
    st.sidebar.subheader(f"Role: {st.session_state.user_type}")
    
    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.session_state.user_type = None
        st.rerun()
    
    menu_options = ["Dashboard", "User Management", "Device Management", "Network Monitoring", "Reports", "Security Settings"]
    if st.session_state.user_type != "admin":
        menu_options = [opt for opt in menu_options if opt not in ["User Management", "Security Settings"]]
    
    selected_page = st.sidebar.selectbox("Navigation", menu_options)
    
    if selected_page == "Dashboard":
        dashboard_page()
    elif selected_page == "User Management":
        user_management_page()
    elif selected_page == "Device Management":
        device_management_page()
    elif selected_page == "Network Monitoring":
        network_monitoring_page()
    elif selected_page == "Reports":
        reports_page()
    elif selected_page == "Security Settings":
        security_settings_page()

def login_page():
    st.title("Vainona High School Wi-Fi Management System")
    st.markdown("---")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")
        
        if submit_button:
            if authenticate_user(username, password):
                st.session_state.authenticated = True
                st.session_state.current_user = username
                st.session_state.user_type = get_user_type(username)
                st.rerun()
            else:
                st.error("Invalid username or password")

def dashboard_page():
    st.title("Network Dashboard")
    st.markdown("---")
    
    # Network summary
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Connected Devices", len(get_all_devices()))
    
    with col2:
        download, upload, ping = perform_speed_test()
        if download:
            st.metric("Download Speed", f"{download:.2f} Mbps")
    
    with col3:
        if upload:
            st.metric("Upload Speed", f"{upload:.2f} Mbps")
    
    # Recent activity
    st.subheader("Recent Network Activity")
    
    # Get recent logs
    conn = sqlite3.connect('wifi_management.db')
    c = conn.cursor()
    c.execute("SELECT timestamp, event_type, description FROM network_logs ORDER BY timestamp DESC LIMIT 10")
    recent_logs = c.fetchall()
    conn.close()
    
    if recent_logs:
        log_data = []
        for log in recent_logs:
            log_data.append({
                "Timestamp": log[0],
                "Event Type": log[1],
                "Description": log[2]
            })
        
        st.table(pd.DataFrame(log_data))
    else:
        st.info("No recent network activity logged")
    
    # Network health chart
    st.subheader("Network Performance (Last 7 Days)")
    metrics = get_network_metrics()
    
    if metrics:
        df = pd.DataFrame(metrics)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.plot(df['timestamp'], df['download_speed'], label='Download Speed (Mbps)')
        ax.plot(df['timestamp'], df['upload_speed'], label='Upload Speed (Mbps)')
        ax.set_xlabel("Time")
        ax.set_ylabel("Speed (Mbps)")
        ax.legend()
        ax.grid(True)
        
        st.pyplot(fig)
    else:
        st.info("No performance metrics available")

def user_management_page():
    st.title("User Management")
    st.markdown("---")
    
    tab1, tab2 = st.tabs(["Create User", "View Users"])
    
    with tab1:
        with st.form("create_user_form"):
            st.subheader("Create New User")
            
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            user_type = st.selectbox("User Type", ["admin", "teacher", "student", "staff"])
            full_name = st.text_input("Full Name")
            email = st.text_input("Email")
            
            submit_button = st.form_submit_button("Create User")
            
            if submit_button:
                if create_user(username, password, user_type, full_name, email):
                    st.success(f"User {username} created successfully")
                    log_network_event("USER_CREATE", f"Created new user: {username}")
    
    with tab2:
        st.subheader("Registered Users")
        
        conn = sqlite3.connect('wifi_management.db')
        c = conn.cursor()
        c.execute("SELECT username, user_type, full_name, email, date_created, last_login FROM users")
        users = c.fetchall()
        conn.close()
        
        if users:
            user_data = []
            for user in users:
                user_data.append({
                    "Username": user[0],
                    "Type": user[1],
                    "Full Name": user[2],
                    "Email": user[3],
                    "Date Created": user[4],
                    "Last Login": user[5] if user[5] else "Never"
                })
            
            st.dataframe(pd.DataFrame(user_data))
        else:
            st.info("No users registered")

def device_management_page():
    st.title("Device Management")
    st.markdown("---")
    
    tab1, tab2 = st.tabs(["Scan Network", "Registered Devices"])
    
    with tab1:
        st.subheader("Network Scan")
        
        interfaces = get_network_interfaces()
        selected_interface = st.selectbox("Select Network Interface", interfaces)
        
        if st.button("Scan Network"):
            with st.spinner("Scanning network..."):
                devices = scan_network(selected_interface)
                
                if devices:
                    st.success(f"Found {len(devices)} devices")
                    
                    device_data = []
                    for device in devices:
                        device_data.append({
                            "IP Address": device['ip'],
                            "MAC Address": device['mac'],
                            "Hostname": socket.getfqdn(device['ip']) if device['ip'] else "Unknown"
                        })
                    
                    df = pd.DataFrame(device_data)
                    st.dataframe(df)
                    
                    # Register found devices
                    for device in devices:
                        register_device(device['mac'], device['ip'], socket.getfqdn(device['ip']))
                    
                    log_network_event("NETWORK_SCAN", f"Scanned network interface {selected_interface}, found {len(devices)} devices")
                else:
                    st.warning("No devices found on the network")
    
    with tab2:
        st.subheader("Registered Devices")
        
        devices = get_all_devices()
        
        if devices:
            df = pd.DataFrame(devices)
            st.dataframe(df)
        else:
            st.info("No devices registered")

def network_monitoring_page():
    st.title("Network Monitoring")
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Current Connections")
        
        interfaces = get_network_interfaces()
        selected_interface = st.selectbox("Select Interface", interfaces, key="monitor_interface")
        
        if st.button("Refresh Connections"):
            with st.spinner("Checking connections..."):
                devices = get_connected_devices(selected_interface)
                
                if devices:
                    device_data = []
                    for device in devices:
                        device_data.append({
                            "IP Address": device['ip'],
                            "MAC Address": device['mac'],
                            "Hostname": socket.getfqdn(device['ip']) if device['ip'] else "Unknown"
                        })
                    
                    st.dataframe(pd.DataFrame(device_data))
                else:
                    st.info("No active connections found")
    
    with col2:
        st.subheader("Port Scanner")
        
        ip_to_scan = st.text_input("Enter IP to scan", "192.168.1.1")
        ports_to_scan = st.text_input("Ports to scan (comma separated)", "22,80,443,3389")
        
        if st.button("Scan Ports"):
            with st.spinner("Scanning ports..."):
                open_ports = check_open_ports(ip_to_scan, ports_to_scan)
                
                if open_ports:
                    st.warning(f"Open ports found: {', '.join(map(str, open_ports))}")
                    log_network_event("PORT_SCAN", f"Found open ports {open_ports} on {ip_to_scan}", "WARNING")
                else:
                    st.success("No open ports found on the specified IP")

def reports_page():
    st.title("Network Reports")
    st.markdown("---")
    
    tab1, tab2, tab3 = st.tabs(["Performance Metrics", "Security Events", "Usage Statistics"])
    
    with tab1:
        st.subheader("Network Performance Metrics")
        
        metrics = get_network_metrics()
        
        if metrics:
            df = pd.DataFrame(metrics)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Show raw data
            st.dataframe(df)
            
            # Show charts
            st.subheader("Performance Trends")
            
            fig, ax = plt.subplots(2, 1, figsize=(10, 8))
            
            # Speed metrics
            ax[0].plot(df['timestamp'], df['download_speed'], label='Download Speed')
            ax[0].plot(df['timestamp'], df['upload_speed'], label='Upload Speed')
            ax[0].set_ylabel("Speed (Mbps)")
            ax[0].legend()
            ax[0].grid(True)
            
            # Latency and packet loss
            ax[1].plot(df['timestamp'], df['latency'], label='Latency (ms)', color='green')
            ax[1].set_ylabel("Latency (ms)")
            ax[1].legend(loc='upper left')
            
            ax2 = ax[1].twinx()
            ax2.plot(df['timestamp'], df['packet_loss'], label='Packet Loss (%)', color='red')
            ax2.set_ylabel("Packet Loss (%)")
            ax2.legend(loc='upper right')
            
            ax[1].grid(True)
            
            st.pyplot(fig)
        else:
            st.info("No performance metrics available")
    
    with tab2:
        st.subheader("Security Events")
        
        conn = sqlite3.connect('wifi_management.db')
        c = conn.cursor()
        c.execute("SELECT timestamp, event_type, description, severity FROM network_logs WHERE severity IN ('WARNING', 'ERROR') ORDER BY timestamp DESC")
        security_events = c.fetchall()
        conn.close()
        
        if security_events:
            event_data = []
            for event in security_events:
                event_data.append({
                    "Timestamp": event[0],
                    "Event Type": event[1],
                    "Description": event[2],
                    "Severity": event[3]
                })
            
            st.dataframe(pd.DataFrame(event_data))
        else:
            st.info("No security events logged")
    
    with tab3:
        st.subheader("Bandwidth Usage")
        
        metrics = get_network_metrics()
        
        if metrics:
            df = pd.DataFrame(metrics)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            fig, ax = plt.subplots(figsize=(10, 4))
            ax.plot(df['timestamp'], df['bandwidth_usage'], label='Bandwidth Usage (Mbps)')
            ax.set_xlabel("Time")
            ax.set_ylabel("Bandwidth Usage (Mbps)")
            ax.legend()
            ax.grid(True)
            
            st.pyplot(fig)
        else:
            st.info("No bandwidth usage data available")

def security_settings_page():
    st.title("Security Settings")
    st.markdown("---")
    
    st.subheader("Network Security Configuration")
    
    with st.form("security_form"):
        st.write("Configure security settings for the network")
        
        # Simulated security options
        encryption = st.selectbox("Encryption Protocol", ["WPA3", "WPA2", "WPA"])
        password_policy = st.selectbox("Password Policy", ["Strong (12+ chars, complex)", "Medium (8+ chars)", "Weak (6+ chars)"])
        auto_updates = st.checkbox("Enable Automatic Security Updates", True)
        intrusion_detection = st.checkbox("Enable Intrusion Detection System", True)
        
        if st.form_submit_button("Save Settings"):
            st.success("Security settings updated successfully")
            log_network_event("SECURITY_UPDATE", "Updated network security settings")

# Run the main function
if __name__ == "__main__":
    # Initialize with a default admin user if none exists
    conn = sqlite3.connect('wifi_management.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        salt = generate_salt()
        password_hash = hash_password("admin123", salt)
        date_created = datetime.now(pytz.timezone('Africa/Harare')).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("INSERT INTO users (username, password_hash, salt, user_type, full_name, email, date_created) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  ("admin", password_hash, salt, "admin", "System Administrator", "admin@vainona.edu.zw", date_created))
        conn.commit()
    conn.close()
    
    # Periodically log network metrics (simulated)
    if 'metrics_logged' not in st.session_state:
        download, upload, ping = perform_speed_test()
        if download:
            conn = sqlite3.connect('wifi_management.db')
            c = conn.cursor()
            timestamp = datetime.now(pytz.timezone('Africa/Harare')).strftime('%Y-%m-%d %H:%M:%S')
            c.execute("INSERT INTO performance_metrics (timestamp, download_speed, upload_speed, latency, packet_loss, bandwidth_usage) VALUES (?, ?, ?, ?, ?, ?)",
                      (timestamp, download, upload, ping, 0.5, (download + upload) / 2))
            conn.commit()
            conn.close()
            st.session_state.metrics_logged = True
    
    main()