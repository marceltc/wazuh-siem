#!/usr/bin/env python

import os
import time
import sys
import json
import requests

# Global params
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)

# Read configuration parameters
alert_file = open(sys.argv[1])
username = sys.argv[2].split(':')[0]
password = sys.argv[2].split(':')[1]
hook_url = sys.argv[3]

def debug(msg):
    if debug_enabled:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"{now}: {msg}"
        print(formatted)
        with open(log_file, "a") as f:
            f.write(formatted + "\n")

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Send the alert
headers = {'content-type': 'application/json'}
response = requests.post(hook_url, json=(alert_json), headers=headers, auth=(username,password))
debug(f"Sent n8n webhook to {hook_url}: {response}")

sys.exit(0)
