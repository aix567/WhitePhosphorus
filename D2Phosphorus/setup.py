#! /usr/bin/env python

# D2 Exploitation Pack
# 
# Copyright (c) 2007-2010 DSquare Security, LLC
# All rights reserved.
#

import sys, os, shutil

BANNER = "DSQUARE SECURITY, LLC, 2007-2019"

class InstallPack:
  def __init__(self):
    self.system = ''
    self.canvas_path = ''
    self.tparty = ''

  def get_os_host(self):
    print "Select your operating system :\n"
    print "1) Windows"
    print "2) Linux"
    print "3) MacOS X"
    print
    print "-->",
    print "",

    o = raw_input()
    if o == "1":
      self.system = "windows"
    elif o == "2":
      self.system = "linux"
    elif o == "3":
      self.system = "macosx"
    else:
      print "\nPlease answer 1, 2 or 3.\n"
      sys.exit(0)
  
  def display_license(self):
    if self.system == "windows":
      os.system("more /E LICENSE.txt") 
    else: 
      os.system("more LICENSE.txt")
  
    print "\nDo you agree to the terms (yes/no)? [no]"

    while 1:
      o = raw_input().lower()
      if o == "no":
        print "\nDid not accept the LICENSE, exiting setup.\n"
        sys.exit(0)
      elif o == "yes":
        break
      elif o != "yes":
        print "Please answer Yes or No\n"
      continue
    print

  def get_path_canvas(self):
    if self.system == "windows":
      self.canvas_path = "C:\CANVAS"
    if self.system == "linux":
      self.canvas_path = "/opt/CANVAS"
    if self.system == "macosx":
      self.canvas_path = "/Applications/CANVAS_D2_6.62.1/Contents/Resources/CANVAS"
    print "Enter the absolute path of CANVAS installation directory [%s] :" % self.canvas_path,
    print "",

    c = raw_input()
    if len(c) > 0:
      if not os.path.exists(c):
        print "error: can't find %s\n" % c
        sys.exit (1)
      else:
        self.canvas_path = c
    print
  
  def get_path_3rdparty(self):
    self.tparty = os.environ.get("EXPLOITPACKDIRS")
    if self.tparty:
      return
    conf = os.path.join(self.canvas_path, 'canvas.conf')
    lines = open(conf, 'r').readlines()
    for line in lines:
      if line.find('exploit_pack_dirs') >= 0:
        self.tparty = line.split()[2]
        if self.tparty:
          return
    self.tparty = '3rdparty'
    
  def _mkdir(self, parent, dir):
    path = os.path.join(parent, dir)
    if not os.path.exists(path):
      os.mkdir(path)
    return path

  def _copydir(self, title, src, dst):
    print '%s %s' % (title, dst)
    if os.path.exists(dst):
      shutil.rmtree(dst)
    shutil.copytree(src, dst)
     
  def install_pack(self):
    print "Installing the pack to %s\n" % self.canvas_path

    tpath = self._mkdir(self.canvas_path, self.tparty)
    dsquare = self._mkdir(tpath, 'D2SEC')
    resources = self._mkdir(dsquare, 'Resources')
    exploits = self._mkdir(dsquare, 'exploits')
    d2sec = self._mkdir(dsquare, 'd2sec_modules')
    libs = self._mkdir(dsquare, 'libs')
    web = self._mkdir(dsquare, 'd2sec_webmodules')
    xml = self._mkdir(dsquare, 'xml')
    documentation = self._mkdir(dsquare, 'documentation')

    print "1. Copying text files to %s ..." % dsquare
    shutil.copy("README.txt", dsquare)
    shutil.copy("LICENSE.txt", dsquare)
    shutil.copy("package.info", dsquare)
    shutil.copy("Changelog", dsquare)

    print "2. Copying Canvas modules to %s ..." % exploits
    modules = os.listdir("canvas_modules")
    os.chdir("canvas_modules")
    for module in modules:
      dir = os.path.join(exploits, module)
      if os.path.exists(dir):
        shutil.rmtree(dir)
      shutil.copytree(module, dir)
      print "   [#] %s installed" % module
    os.chdir("../")

    print "3. Copying D2SEC modules to %s ..." % d2sec
    modules = os.listdir("d2sec_modules")
    os.chdir("d2sec_modules")
    for module in modules:
      dir = os.path.join(d2sec, module)
      if os.path.exists(dir):
        if dir.find("CVE.txt") >= 0:
          os.unlink(dir)
        else:
          shutil.rmtree(dir)
      if module.find("CVE.txt") >= 0:
        shutil.copy(module, dir)
      else:
        shutil.copytree(module, dir)
      print "   [#] %s installed" % module
    os.chdir("../")

    self._copydir('4. Copying libs to', 'libs', libs)
    self._copydir('5. Copying d2sec_webmodules to', 'd2sec_webmodules', web)
    self._copydir('6. Copying XmlRPC D2 Client to', 'xml', xml)
    shutil.copy('startxml.py', dsquare)
    self._copydir('7. Copying documentation to', 'documentation', documentation)

    print "8. Creating d2sec_config.py to %s ..." % dsquare
    open('d2sec_config.py', 'a').write('CANVASPATH = \'%s\'\n' % self.canvas_path)
    config = os.path.join(dsquare, 'd2sec_config.py')
    shutil.copy('d2sec_config.py', config)
    
    print "9. Requirements:\n"
    print open("libs/requirements.txt", "r").read()
    print "\nCongratulations, you successfully installed the DSquare Exploitation Pack for CANVAS!"
    print "Please contact <support@d2sec.com> if any questions appear"

    print 'Press a key ...'
    raw_input()

  def clear_screen(self):
    if os.name == "posix":
      os.system('clear')
    elif os.name in ("nt", "dos", "ce"):
      os.system('CLS')
    else:
      print '\n'

  def display_documentation(self):
    self.clear_screen()
    print open('documentation/readme_first.txt').read()
    
    print 'Press a key ...'
    raw_input()

    self.clear_screen()
    print """
To list or search d2sec canvas modules, use Canvas gui. See below the available
D2 modules (D2SEC/d2sec_modules) :\n
"""
    print 'D2 Modules Exploits'
    print '---------------------\n'
    print open('d2sec_modules/CVE.txt', 'r').read()
    print

    print 'D2 Modules Tools'
    print '---------------------'
    print """
d2sec_django     : www gui to consult sqlite3 database
d2sec_masspwngui : gui for d2sec_masspwn 
d2sec_proxy      : a simple HTTP proxy to log visited uri 
d2sec_modapache  : Malicious Apache module executing a MOSDEF backdoor (Tool Linux)  
d2sec_rpc        : Tool to do rpc direct scan on Unix servers (Tool Linux)
d2sec_ads        : Tool to play with NTFS streams (Tool Windows)
d2sec_backweb    : a Apache remote backdoor to use with d2sec_clientbackweb (Tool Linux)
d2sec_lotus      : Owning Lotus Notes Server & Client (Tool Windows)
d2sec_phpshell   : an evolved PHP script to upload 
d2sec_ext4       : a PoC to hide/unhide a file on ext2/ext3 filesystem in userland mode (Tool Linux)
d2sec_backssh    : a SSH client backdoor (Tool Linux/Solaris)
d2sec_clsuckit   : a modified suckit client (golden oldie) (Tool Linux)
d2sec_sutrojan   : su trojan horse for Linux 
d2sec_citerm     : Owning Citrix & Terminal Services Client Tool (Tool Windows)
"""
    self.clear_screen()
    print open('documentation/xmlrpc.txt').read()
    self.clear_screen()
    print open('documentation/pycurl.txt').read()
    
if __name__=="__main__":
  print BANNER + "\n"

  pack = InstallPack()
  pack.get_os_host ()
  pack.display_license ()  
  pack.get_path_canvas ()
  pack.get_path_3rdparty()
  pack.install_pack()
  pack.display_documentation()
