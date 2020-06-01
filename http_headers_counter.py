#!/usr/bin/env python3
# 
# Prerequisite
# sudo apt-get install -y python3-pip
# pip3 install --pre scapy[basic]
#
# Run
# ./http_headers_counter.py
#

from scapy.all import *
from scapy.layers import http
from collections import Counter
from pathlib import Path
import os
import glob

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
PCAPS_DIR = Path(f'{SCRIPT_DIR}/pcaps')

# https://en.wikipedia.org/wiki/List_of_HTTP_header_fields

KNOWN_HEADERS = [
    "Cache-Control",
    "Connection",
    "Permanent",
    "Content-Length",
    "Content-MD5",
    "Content-Type",
    "Date",
    "Keep-Alive",
    "Pragma",
    "Upgrade",
    "Via",
    "Warning",
    "X-Request-ID",
    "X-Correlation-ID",
    "A-IM",
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Datetime",
    "Access-Control-Request-Method",
    "Access-Control-Request-Headers",
    "Authorization",
    "Cookie",
    "Expect",
    "Forwarded",
    "From",
    "Host",
    "HTTP2-Settings",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Max-Forwards",
    "Origin",
    "Proxy-Authorization",
    "Range",
    "Referer",
    "TE",
    "User-Agent",
    "Upgrade-Insecure-Requests",
    "Upgrade-Insecure-Requests",
    "X-Requested-With",
    "DNT",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "Front-End-Https",
    "X-Http-Method-Override",
    "X-ATT-DeviceId",
    "X-Wap-Profile",
    "Proxy-Connection",
    "X-UIDH",
    "X-Csrf-Token",
    "Save-Data",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Accept-Patch",
    "Accept-Ranges",
    "Age",
    "Allow",
    "Alt-Svc",
    "Content-Disposition",
    "Content-Encoding",
    "Content-Language",
    "Content-Location",
    "Content-Range",
    "Delta-Base",
    "ETag",
    "Expires",
    "IM",
    "Last-Modified",
    "Link",
    "Location",
    "Permanent",
    "P3P",
    "Proxy-Authenticate",
    "Public-Key-Pins",
    "Retry-After",
    "Server",
    "Set-Cookie",
    "Strict-Transport-Security",
    "Trailer",
    "Transfer-Encoding",
    "Tk",
    "Vary",
    "WWW-Authenticate",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Security-Policy",
    "X-WebKit-CSP",
    "Refresh",
    "Status",
    "Timing-Allow-Origin",
    "X-Content-Duration",
    "X-Content-Type-Options",
    "X-Powered-By",
    "X-UA-Compatible",
    "X-XSS-Protection"
]


##############################################################################################################
# MAIN 

# Create a Header Counter
headers_counts = Counter()

# Create a list of pcap file names from PCAPS_DIR
os.chdir(f'{PCAPS_DIR}')
files_list = glob.glob('*.pcap')

if not len(files_list):
    print(f"Error: no pcap files was found")
    exit()

load_layer("http")
num_of_http_pkts = 0

# Iterate the files
for pcap_file in files_list:

    print(f'Reading file {pcap_file}')

    pkts = rdpcap(pcap_file) # Read packets from pcap_file 
    
    
    # Iterate the packets 
    for packet in pkts:
        
        if packet.haslayer('HTTP'):
            http_packet = str(packet[HTTP]) # Convert to string
            headers_packet_dict = {}
            try:
                # Remove the request or response line and the payload of http packet
                http_packet = http_packet[http_packet.index("\\r\\n")+4:http_packet.index("\\r\\n\\r\\n")+4]

                # Create a dictionary { <header name> : <value> } 
                headers_packet_dict = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\\r\\n", http_packet))
                num_of_http_pkts = num_of_http_pkts + 1
            except: 
                continue

            # Update every header in the Header Counter
            headers_counts.update(header for header in headers_packet_dict.keys())
            # print(headers_counts.most_common())


# Final print
print('\n\n\033[1m{:40}{:20}{}\033[0m'.format('HEADER', 'COUNTS', 'KNOWN'))

total_headers_known = 0
for key,value in headers_counts.most_common():

    headerIsKnown = False

    if key in KNOWN_HEADERS:
        headerIsKnown = True
        total_headers_known = total_headers_known + 1

    print ('{:34}{:10}{knwon:>20}'.format(key, value, knwon = 'yes' if headerIsKnown else 'no'))

total_headers_found = len(headers_counts)
print(f'\nTotal HTTP packets analized: {num_of_http_pkts}')
print('Total HTTP headers = {} ({} knowns | {} unknowns)'.format(total_headers_found, total_headers_known, (total_headers_found - total_headers_known)))

##############################################################################################################

