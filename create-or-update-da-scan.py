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
dynamic_target = os.getenv("Dyanamic_Target")
login_user = os.getenv("Dynamic_User")
login_pass = os.getenv("Dynamic_Pass")
print("Dynamic Target is: " + dynamic_target)
print("Login user is: " + login_user)
dynamic_job = os.getenv("JOB_NAME") #Dynamic Job name will be same as environment variable


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

res = prepared_request('GET','https://api.veracode.com/was/configservice/v1/platform_applications?name=' + dynamic_job + '&page=1&size=50)
#res = prepared_request('GET','https://api.veracode.com/appsec/v1/applications/?name=' + dynamic_job)
response = res.json()
try:
    print("looked for app" + dynamic_job)
    for key, value in response.items():
        print(key, ' ', value) # this is how to see the all keys and values in dictionary(json sent by client)
    #uuid = response['_embedded']['platform_applications']['uuid']
    #print("uuid is: " + uuid)
except:
    print("response failed")
    print("Error executing API Call")
    sys.exit(1)

print("Looking for Dynamic Analysis Job: " + dynamic_job )
#Retrieve DA Job ID by project name
res = prepared_request('GET', 'https://api.veracode.com/was/configservice/v1/analyses', query=("name=" + dynamic_job))
response = res.json()
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

    print("Creating a new Dynamic Analysis Job: " + dynamic_job )
    res = prepared_request('POST', 'https://api.veracode.com/was/configservice/v1/analyses', json=data)

    if res.status_code == 201:
        print("Job Created and Submitted Successfully: " + str(res.status_code))
    else:
        response = res.json()
        print("Error encountered: " + response['_embedded']['errors'][0]['detail'])
        sys.exit(1)

# No exception so job exists
#Payload for updating schedule of existing DA job to start now
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
      },
      "action_type": "UPDATE_SELECTIVE"
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

# First delete the original analysis

#try:
#    res = prepared_request('DELETE', 'https://api.veracode.com/was/configservice/v1/analyses/' + job_id)
#    if res.status_code == 204:
#        print("Analysis deleted sucessfully: " + str(res.status_code) )
#    else:
#        response = res.json()
#        print("Analysis failed to delete: " + str(res.status_code) )
#        print("Error encountered: " + response['_embedded']['errors'][0]['detail'])
#except:
#    print("Error executing API Call")
#    sys.exit(1)

#Now create the job over
#Update Schedule of the existing DA Job
try:
#    print("Creating a new Dynamic Analysis Job: " + dynamic_job )
#    res = prepared_request('POST', 'https://api.veracode.com/was/configservice/v1/analyses', json=data)
#
#    if res.status_code == 201:
#        print("Job Created and Submitted Successfully: " + str(res.status_code))
#    else:
#        response = res.json()
#        print("Error encountered: " + response['_embedded']['errors'][0]['detail'])
#        sys.exit(1)

    print("About to update the Dynamic Analysis - " + dynamic_job + "job_id - " + job_id)
    res = prepared_request('PUT', 'https://api.veracode.com/was/configservice/v1/analyses/' + job_id + '?method=PATCH', json=data)
    if res.status_code == 204:
        print("Scan Submitted Successfully: " + str(res.status_code) )
    else:
        response = res.json()
        print("Error encountered: " + response['_embedded']['errors'][0]['detail'])
except:
    print("Error executing API Call")
    sys.exit(1)
