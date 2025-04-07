#!/usr/bin/env python3
import os
import time                                                                     
import hmac                                                                     
import codecs
import json  
import sys                                                              
from hashlib import sha256 
import requests
from requests.adapters import HTTPAdapter                                       
from urllib.parse import urlparse

#Setup variables according to environment

#GitLab:
api_id = os.getenv("VERACODE_ID")
api_secret = os.getenv("VERACODE_KEY")
dynamic_job = os.getenv("VERACODE_APPNAME")   #Dynamic Job name
#dynamic_job = "AutoBuild Verademo"    #os.getenv("CI_PROJECT_NAME") #Dynamic Job name will be same as GitLab project name

def veracode_hmac(host, url, method):
    signing_data = 'id={api_id}&host={host}&url={url}&method={method}'.format(
                    api_id=api_id.lower(),
                    host=host.lower(),
                    url=url, method=method.upper())

    timestamp = int(round(time.time() * 1000))
    nonce = os.urandom(16).hex()

    key_nonce = hmac.new(
        codecs.decode(api_secret, 'hex_codec'),
        codecs.decode(nonce, 'hex_codec'), sha256).digest()

    key_date = hmac.new(key_nonce, str(timestamp).encode(), sha256).digest()
    signature_key = hmac.new(
            key_date, 'vcode_request_version_1'.encode(), sha256).digest()
    signature = hmac.new(
            signature_key, signing_data.encode(), sha256).hexdigest()

    return '{auth} id={id},ts={ts},nonce={nonce},sig={sig}'.format(
            auth='VERACODE-HMAC-SHA-256',
            id=api_id,
            ts=timestamp,
            nonce=nonce,
            sig=signature)

def prepared_request(method, end_point, json=None, query=None, file=None):
    session = requests.Session()
    session.mount(end_point, HTTPAdapter(max_retries=3))
    request = requests.Request(method, end_point, json=json, params=query, files=file)
    prepared_request = request.prepare()
    prepared_request.headers['Authorization'] = veracode_hmac(
        urlparse(end_point).hostname, prepared_request.path_url, method)
    res = session.send(prepared_request)

    return res

# code above this line is reusable for all/most API calls

print("Looking for Dynamic Analysis Job: " + dynamic_job )
#Retrieve DA Job ID by project name
res = prepared_request('GET', 'https://api.veracode.com/was/configservice/v1/analyses', query=("name=" + dynamic_job))
response = res.json()
try:
    job_id = response['_embedded']['analyses'][0]['analysis_id']
except: 
    print("Could not find Dynamic Analysis")
    sys.exit(1)

#Update Schedule of existing DA Job
print("Found and job_id is: " + job_id)

res = prepared_request('GET', 'https://api.veracode.com/was/configservice/v1/analyses/'+ job_id)
#print(res.json())
#print(res.status_code)
response = res.json()
if res.status_code == 200:
    if (response['schedule']['schedule_status']=="COMPLETED"):
        if (response['latest_occurrence_status']['status_type']=="FINISHED_RESULTS_AVAILABLE"):
            print("DA Status code is: " + response['schedule']['schedule_status'])
            print("DA Status type is: " + response['latest_occurrence_status']['status_type'])
            print("Scan completed and results available")
            sys.exit(0)
        else:
            print("Scan completed but latest occurrence status is:"+response['latest_occurrence_status']['status_type'])
            sys.exit(1)
    else:
        print("DA Status code is: " + response['schedule']['schedule_status'])
        print("Not completed yet")
        sys.exit(1)
else:
    response = res.json()
    print("Error encountered: " + response['_embedded']['errors'][0]['detail'])
    print("Error executing API Call")
    sys.exit(1)

