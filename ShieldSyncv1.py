import ipaddress
import socket
import getpass
import json
import logging
import os

#Configure Logging 
logging.basicConfig(filename='logs/ShieldSync.log', level=logging.INFO, format='%(asctime)s-%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def logs(action):
    logging.info(action)

def load_generated_ids():
    generated_ids = set()
    if os.path.exists('rules/policy_ids.txt'):
        with open('rules/policy_ids.txt', 'r') as file:
            for line in file:
                generated_ids.add(line.strip())
    return generated_ids

def save_generated_ids(generated_ids):
    with open('rules/policy_ids.txt', 'w') as file:
        for id in generated_ids:
            file.write(id + '\n')

def gen_policy_id():
    generated_ids = load_generated_ids()
    for id in range(100, 200):
        id_str = str(id)
        if id_str not in generated_ids:
            generated_ids.add(id_str)
            save_generated_ids(generated_ids)
            yield str(id)

def fqdn_to_ip(fqdn):
    try:
        ip_address = socket.gethostbyname(fqdn)
        return ip_address
    except (socket.gaierror, socket.herror):
        return None

def find_firewall_for_ip(input_ip, network_layout):
    if not input_ip:
        return None, []

    try:
        input_ip = ipaddress.IPv4Address(input_ip)
    except ipaddress.AddressValueError:
        return None, []

    firewall_ip = None
    connected_ports = []

    # Find the firewall ip for input ip
    for network, firewall_info in network_layout["networks"].items():
        network_ip = ipaddress.IPv4Network(network, strict=False)
        if input_ip in network_ip:
            firewall_ip = firewall_info.get("firewall")
            break

    if firewall_ip is None:
        return None, []

    for fw_ip, fw_info in network_layout["firewalls"].items():
        if fw_ip == firewall_ip:
            connected_ports = network_layout["Ports"].get(network, {}).get("Connected_ports", [])
            break

    return firewall_ip, connected_ports

def get_user_inputs():
    while True:
        user_name = input("Enter the Username: ")
        logs(f"User {user_name} logged in")
        user_passwd = getpass.getpass("Password for " + user_name + ": ")
        user_input1 = input("Enter the Destination IP address or FQDN: ")
        logs(f"First Node {user_input1}")
        user_input2 = input("Enter the Source IP address or FQDN: ")
        logs(f"Second Node {user_input2}")

        # Check if the inputs are FQDNs and convert them to IP addresses
        ip1 = fqdn_to_ip(user_input1) or user_input1
        ip2 = fqdn_to_ip(user_input2) or user_input2
        logs(f"Selecting the Firewall address for {ip1}")
        logs(f"Selecting the Firewall address for {ip2}")

        if ip1 and ip2:
            return user_name, user_passwd, ip1, ip2
        else:
            print("Invalid IP address or FQDN. Please enter valid ones.")

def determine_port(network_layout, firewall_ip, connected_network):
    # Get the connected ports for the given connected network
    connected_ports = network_layout["Ports"].get(connected_network, {}).get("Connected_ports", [])
    # Check if the firewall IP is directly connected to the network
    if firewall_ip in network_layout["firewalls"]:
        connected_networks = network_layout["firewalls"][firewall_ip].get("directly_connected_networks", [])
        if connected_network in connected_networks:
            return connected_ports[0] if connected_ports else "default_port"  # Return the first port or a default port if no ports are specified
    # If not directly connected, check if indirectly connected and retrieve the port
    for fw_ip, fw_info in network_layout["firewalls"].items():
        indirectly_connected_networks = fw_info.get("indirectly_connected_networks", {})
        for indirectly_connected, connected_via in indirectly_connected_networks.items():
            if firewall_ip == connected_via and connected_network in connected_via:
                return connected_ports[0] if connected_ports else "default_port"  # Return the first port or a default port if no ports are specified
    return "default_port"  # Return a default port if no matches are found

def select_indirectly_connected_network(ip2, routing_info):
    for firewall, firewall_data in routing_info["firewalls"].items():
        indirectly_connected_networks = firewall_data.get("indirectly_connected_networks", {})
        for network, indirectly_connected_ips in indirectly_connected_networks.items():
            for indirectly_connected_ip in indirectly_connected_ips:
                network_ip = ipaddress.ip_network(indirectly_connected_ip)
                if ipaddress.ip_address(ip2) in network_ip:
                    return network

    return None

def determine_associated_port(selected_network, network_layout):
    if selected_network in network_layout["Ports"]:
        return network_layout["Ports"][selected_network]["Connected_ports"][0]
    else:
        return None

def execute_scripts(user_name, user_passwd, user_ip, firewall_result, routing_info):
    firewall_ip, connected_ports = firewall_result
    selected_network = select_indirectly_connected_network(ip2, routing_info)
    # Set environment variables for firewall policy configuration and get the user inputs
    os.environ['new_policy_id'] = next(gen_policy_id())
    logs(f"Editing Policy ID number {os.environ['new_policy_id']}")
    os.environ['new_policy_name'] = input("Enter The Policy name (Example Rule): ") or 'Example Rule'
    logs(f"Adding Rule Name {os.environ['new_policy_name']}")
    if firewall_result1[0] == firewall_result2[0]:
        os.environ['new_src_interface'] = firewall_result2[1][0] or 'port1' 
    else:
        os.environ['new_src_interface'] = determine_associated_port(selected_network, network_layout)
    logs(f"Firewall Source Interface Selecting {os.environ['new_src_interface']}")
    os.environ['new_dst_interface'] = connected_ports[0] or 'port1'
    logs(f"Firewall Destination Interface {os.environ['new_dst_interface']}")
    os.environ['new_action'] = input("Enter The Firewall Action ACCEPT or DENY (default accept): ") or 'accept'
    logs(f"{os.environ['new_action']} Firewall Rule")
    os.environ['new_src_address'] = input("Enter The Firewall Source Add (default all): ") or 'all'
    os.environ['new_dst_address'] = input("Enter The Firewall Destination Add (default all): ") or 'all'
    os.environ['new_schedule'] = 'always'
    os.environ['new_service'] = input("Enter The Firewall Service (default all): ") or 'ALL'
    logs(f"Enabling firewall Service {os.environ['new_service']}")

    # Generate dynamic Ansible hosts file
    with open('extras/hosts', 'w') as hosts_file:
        hosts_file.write('[fortigates]\n')
       # for firewall_ip, connected_ports in firewall_result:
        firewall_ip = firewall_ip.split(':')[0]
        hosts_file.write(f'{firewall_ip} ansible_user="{user_name}" ansible_password="{user_passwd}"\n\n')
        hosts_file.write('[fortigates:vars]\nansible_network_os=fortinet.fortios.fortios\n')

    # Run Ansible playbook for firewall policy configuration
    os.system('ansible-playbook -i extras/hosts rules/Firewall-Rule-v1.yml')

# Get the Network layout from the network_layout file
with open('extras/network_layout.json', 'r') as file:
    network_layout = json.load(file)

# Load the Routing information
with open('extras/routing.json', 'r') as file:
    routing_info = json.load(file)

# User inputs
user_name, user_passwd, ip1, ip2 = get_user_inputs()

# Find the associated firewall using the network layout for the first IP
firewall_result1 = find_firewall_for_ip(ip1, network_layout)
firewall_result2 = find_firewall_for_ip(ip2, network_layout)
print(f"Firewall IP for {ip1}: {firewall_result1[0]} Firewall IP for {ip2}: {firewall_result2[0]}")

# Execute the scripts for the first IP
execute_scripts(user_name, user_passwd, ip1, firewall_result1, routing_info)

# Delete the host file acter creating 
host_path = "extras/hosts"

os.remove(host_path)

# Find the associated firewall using the network layout for the second IP
#firewall_result2 = find_firewall_for_ip(ip2, network_layout)
#print(f"Firewall IP for {ip2}: {firewall_result2[0]}")

# Execute the scripts for the second IP
# execute_scripts(user_name, user_passwd, ip2, firewall_result2)

