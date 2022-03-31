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
dynamic_job = os.getenv("JOB_NAME") + " BRANCH Commit, pipeline ID: " + os.getenv("PIPELINE_ID") #Dynamic Job name will be same as GitLab project name and pipeline ID
api_spec = os.getenv("API_FILE")
spec_name = os.getenv("API_NAME")
dynamic_target = os.getenv("Dynamic_Target")

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


query_params = "spec_name= " + spec_name
spec_file = {'file': open(api_spec,'rb')}

#Retrieve API Spec ID by API Spec name
res = prepared_request('GET', 'https://api.veracode.com/was/configservice/v1/api_specifications', query=("spec_name=" + spec_name))
response = res.json()
try:
    spec_id = response['_embedded']['api_specs'][0]['spec_id']
    print("API Specification located Successfully: " + str(res.status_code) + " API Specification ID is: " + spec_id)
    
    #found update it
    print("Updating the API Specification")
    try:
       #Upload API spec to Veracode platform:

       target = "https://api.veracode.com/was/configservice/v1/api_specifications/" + spec_id
       res = prepared_request('PUT', target, json=None, query=query_params, file=spec_file)
       print("Return code == " + str(res.status_code))
       if res.status_code == 200:
           response = res.json()
           #spec_id = response['spec_id']
           print("API Specification Uploaded Successfully: " + str(res.status_code))
           print("API Specification ID updated: " + spec_id)
    
           #Payload for scheduling the API analysis job:

           data =   {
               "name": dynamic_job,
               "scans":
               [
                   {
                       "action_type": "ADD",
                       "request_id": "0",
                       "scan_config_request":
                       {
                           "target_url":
                           {
                               "url": dynamic_target
                           },
                           "api_scan_setting":
                           {
                               "spec_id": spec_id,
                           }
                       }
                   }
               ],
               "visibility":
               {
                   "setup_type": "SEC_LEADS_ONLY",
                   "team_identifiers":
                   []
               },
             "schedule": {
               "now": True,
               "duration": {
                 "length": 1,
                 "unit": "DAY"
               }
             }
           }
        
           #Add API Spec to dynamic analysis and start scan:
        
           job_options = 'run_verification=false&scan_type=API_SCAN'
           print("Creating new API Scan Job: "+ dynamic_job )
           res2 = prepared_request('POST', 'https://api.veracode.com/was/configservice/v1/analyses', json=data, query=job_options)

       else:
           response = res.json()
           print("Return code == " + str(res.status_code))
           print("Error encountered: " + response['_embedded']['errors'][0]['detail'] + " Error: " + response['_embedded']['errors'][0]['meta']['invalid_spec_error']['error_type'])
           sys.exit(1)
    except:
        print("Error has occurred")
        sys.exit(1)
except:
    #not found create a new one
    print("Creating a new API Specification")
    try:
       #Upload API spec to Veracode platform:

       res = prepared_request('POST', 'https://api.veracode.com/was/configservice/v1/api_specifications', json=None, query=query_params, file=spec_file)
       if res.status_code == 200:
           response = res.json()
           spec_id = response['spec_id']
           print("API Specification Uploaded Successfully: " + str(res.status_code))
           print("API Specification ID Created: " + spec_id)
    
           #Payload for scheduling the API analysis job:

           data =   {
               "name": dynamic_job,
               "scans":
               [
                   {
                       "action_type": "ADD",
                       "request_id": "0",
                       "scan_config_request":
                       {
                           "target_url":
                           {
                               "url": dynamic_target
                           },
                           "api_scan_setting":
                           {
                               "spec_id": spec_id,
                           }
                       }
                   }
               ],
               "visibility":
               {
                   "setup_type": "SEC_LEADS_ONLY",
                   "team_identifiers":
                   []
               },
             "schedule": {
               "now": True,
               "duration": {
                 "length": 1,
                 "unit": "DAY"
               }
             }
           }
        
           #Add API Spec to dynamic analysis and start scan:
        
           job_options = 'run_verification=false&scan_type=API_SCAN'
           print("Creating new API Scan Job: "+ dynamic_job )
           res2 = prepared_request('POST', 'https://api.veracode.com/was/configservice/v1/analyses', json=data, query=job_options)

       else:
           response = res.json()
           print("Error encountered: " + response['_embedded']['errors'][0]['detail'] + " Error: " + response['_embedded']['errors'][0]['meta']['invalid_spec_error']['error_type'])
           sys.exit(1)

    except:
       print("Error has occurred")
       sys.exit(1)
