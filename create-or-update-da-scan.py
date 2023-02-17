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

#Jenkins:
api_id = os.getenv("VeraID")
api_secret = os.getenv("VeraPW")
dynamic_target = os.getenv("Dynamic_Target")
login_user = os.getenv("Dynamic_User")
login_pass = os.getenv("Dynamic_Pass")
print("Dynamic Target is: " + dynamic_target)
print("Login user is: " + login_user)
dynamic_job = os.getenv("JOB_NAME") + "-" + os.getenv("PIPELINE_ID")

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

#res = prepared_request('GET','https://api.veracode.com/appsec/v1/applications/?name=' + dynamic_job)
#response = res.json()
#try:
#    print("looked for app:" + dynamic_job)
#    print("Status code: " + str(res.status_code) )
#    response = res.json()
#    print("Response is: " + str(response))
#    uuid = response['_embedded']['applications'][0]['guid']
#except:
#    print("response failed: "+ res.status_code)
#    print("Error executing API Call")
#    sys.exit(1)

print("Looking for Dynamic Analysis Job: " + dynamic_job )

#Retrieve DA Job ID by project name
res = prepared_request('GET', 'https://api.veracode.com/was/configservice/v1/analyses', query=("name=" + dynamic_job))
response = res.json()
#print("Response for DA Job is: " + str(response))
#          "linked_platform_app_uuid": uuid,  
try:
    job_id = response['_embedded']['analyses'][0]['analysis_id']
except: 
    print("Could not find Dynamic Analysis - Create one")
    #Payload for creating and scheduling new DA job
    data =   {
      "name": dynamic_job,
      "scans": [
        {
          "scan_config_request": {
            "target_url": {
              "url": dynamic_target,
              "http_and_https": True,
              "directory_restriction_type": "DIRECTORY_AND_SUBDIRECTORY"            
           },
           "auth_configuration": {
             "authentications": {
                "AUTO": {
                   "username": login_user,
                   "password": login_pass,
                   "authtype": "AUTO"
                 }
               }
            }
          }
        }
      ],
      "schedule": {
        "now": True,
        "duration": {
          "length": 1,
          "unit": "DAY"
        }
      }
    }

    print("Creating a new Dynamic Analysis Job: " + dynamic_job+os.getenv("PIPELINE_ID") )
    res = prepared_request('POST', 'https://api.veracode.com/was/configservice/v1/analyses', json=data)

    if res.status_code == 201:
        print("Job Created and Submitted Successfully: " + str(res.status_code))
        sys.exit(0)
    else:
        response = res.json()
        print("Error encountered: " + response['_embedded']['errors'][0]['detail'])
        sys.exit(1)

# No exception so job exists
#Payload for updating schedule of existing DA job to start a new one now
#data =   { 
#    "schedule": 
#        {       
#            "now": True,
#            "duration": 
#                {
#                "length": 1,
#                "unit": "DAY"
#                }
#        }
#}

print("Found the Dynamic Analysis - " + dynamic_job)
# Find the scan id to update the scan in the analysis
try:
    print("Get the Dynamic Analysis scans for job_id - " + job_id)
    res = prepared_request('GET', 'https://api.veracode.com/was/configservice/v1/analyses/' + job_id + '/scans')
    response = res.json()
   
    if res.status_code == 200:
        print("Scans were found.  Return code: " + str(res.status_code) )
        scan_id = response['_embedded']['scans'][0]['scan_id']
        print("scan id is: " + scan_id)
    else:
        response = res.json()
        print("Error encountered: " + response['_embedded']['errors'][0]['detail'])
except:
    response = res.json()
    print("Error executing API Call")
    print("Error encountered: " + response['_embedded']['errors'][0]['detail'])
    sys.exit(1)

#data =   {
#  "name": dynamic_job,
#  "scans": [
#    {
#      "scan_id": scan_id,  
#      "action_type": "UPDATE_SELECTIVE",
#      "scan_config_request": {
#        "target_url": {
#          "url": dynamic_target,
#          "http_and_https": True,
#          "directory_restriction_type": "DIRECTORY_AND_SUBDIRECTORY"            
#       },
#       "auth_configuration": {
#         "authentications": {
#            "AUTO": {
#               "username": login_user,
#               "password": login_pass,
#               "authtype": "AUTO"
#             }
#           }
#        }
#      }
#    }
#  ],
data =   {
  "schedule": {
    "now": True,
    "duration": {
      "length": 1,
      "unit": "DAY"
    }
  }
}

#Update Schedule of the existing DA Job
try:

    print("About to update the Dynamic Analysis - " + dynamic_job + " job_id - " + job_id)
    res = prepared_request('PUT', 'https://api.veracode.com/was/configservice/v1/analyses/' + job_id + '?method=PATCH', json=data)
    if res.status_code == 204:
        print("Scan Submitted Successfully: " + str(res.status_code) )
    else:
        response = res.json()
        print("Error encountered: " + response['_embedded']['errors'][0]['detail'])
except:
    print("Error executing API Call")
    sys.exit(1)
