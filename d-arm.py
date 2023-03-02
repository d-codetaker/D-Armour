import time
import sqlite3
from collections import Counter
import re
import subprocess
import os 

# Connect to the SQLite database
conn = sqlite3.connect('ips.db')
cursor = conn.cursor()

# Create the table to store the blocked IPs
cursor.execute('''
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        time INTEGER NOT NULL
    )
''')
conn.commit()

# A dictionary to store the IP addresses and their request count
ips = Counter()

# Keep track of the last read line
last_read_line = 0

# Compile the regex pattern to extract the IP address from the log line
ip_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

# Define the function to block an IP using iptables
def ban_ip(ip):
    # Check if the IP is already banned in iptables
    process = subprocess.Popen(['sudo', 'iptables', '-L', '-n'], stdout=subprocess.PIPE)
    output, error = process.communicate()
    if ip.encode() in output:
        return

    # Check if the IP already exists in the table
    cursor.execute('SELECT time FROM blocked_ips WHERE ip=?', (ip,))
    result = cursor.fetchone()
    if result:
        # Update the time for the existing IP
        cursor.execute('UPDATE blocked_ips SET time=? WHERE ip=?', (int(time.time()), ip))
    else:
        # Insert the IP and the current time into the database
        cursor.execute('INSERT INTO blocked_ips VALUES (?,?)', (ip, int(time.time())))
    conn.commit()

    # Ban the IP using iptables
    subprocess.call(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])

def ban_unbanned_ips():
    cursor.execute('SELECT ip FROM blocked_ips')
    rows = cursor.fetchall()
    for row in rows:
        ip = row[0]
        process = subprocess.Popen(['sudo', 'iptables', '-L', '-n'], stdout=subprocess.PIPE)
        output, error = process.communicate()
        if ip.encode() not in output:
            ban_ip(ip)

def add_unbanned_ips_to_db():
    process = subprocess.Popen(['sudo', 'iptables', '-L', '-n'], stdout=subprocess.PIPE)
    output, error = process.communicate()
    for line in output.decode().split('\n'):
        if 'DROP' in line:
            ip = line.split()[3]
            cursor.execute('SELECT time FROM blocked_ips WHERE ip=?', (ip,))
            result = cursor.fetchone()
            if not result:
                current_time = int(time.time())
                cursor.execute('INSERT INTO blocked_ips VALUES (?,?)', (ip, current_time))
                conn.commit()


# Define the function to unblock an IP using iptables
def unblock_ip(ip):
    # Unblock the IP using iptables
    subprocess.call(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
    
    # Remove the IP from the blocked_ips table
    cursor.execute('DELETE FROM blocked_ips WHERE ip=?', (ip,))
    conn.commit()

# Define the function to unblock IPs that were blocked more than 30 minutes ago
def unblock_old_ips():
    current_time = int(time.time())
    cursor.execute('SELECT ip, time FROM blocked_ips')
    rows = cursor.fetchall()
    for row in rows:
        ip, blocked_time = row
        if current_time - blocked_time > 1800:
            # Unban the IP in iptables
            subprocess.call(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            print(f'Unbanned IP address {ip}')
            # Delete the IP from the blocked_ips table
            cursor.execute('DELETE FROM blocked_ips WHERE ip=?', (ip,))
            conn.commit()


# Define the function to check if an IP is whitelisted
def is_whitelisted(ip):
    # You can customize this function to check your own whitelist rules
    whitelist = ['103.102.58.110']
    return ip in whitelist

while True:
    # Check and unblock old IPs
    unblock_old_ips()

    # Read the log file line by line
    with open('/var/log/nginx/access.log', 'r') as f:
        for i, line in enumerate(f):
            # Only process new lines in the log file
            if i < last_read_line:
                continue

            # Extract the IP address from the log line using regex
            match = ip_pattern.match(line)
            if match:
                ip = match.group(1)
            else:
                continue

            # Check if the IP is whitelisted
            if is_whitelisted(ip):
                continue

            # # Check if the IP is already banned in iptables
            # if unblock_ip(ip):
            #     continue

            # Increment the request count for the IP
            ips[ip] += 1

            # Check if the IP has made more than 3 requests in 1 second
            if ips[ip] >= 3:
                # Block the IP in iptables and in the blocked_ips table
                ban_ip(ip)
                print(f'Blocked IP address {ip}')

            # Update the last read line
            last_read_line = i + 1

    # Reset the IP request counts
    ips.clear()

    # Wait for 1 second before reading the log file again
    time.sleep(1)