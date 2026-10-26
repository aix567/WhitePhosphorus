#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  testsmb2client.py
## Description:
##            :
## Created_On :  Mon Jul 12 14:17:04 2010
## Created_By :  Kostya Kortchinsky
## Modified_On:  Thu Apr 12 11:31:36 CEST 2018
## Modified_By:  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import sys
if '.' not in sys.path:
    sys.path.append('.')
    
import socket
from struct import pack

import libs.newsmb.libsmb2 as libsmb2
import libs.newsmb.smb2const as smb2const
from libs.newsmb.smbconst import *

ip = '192.168.1.95'

sockaddr = (ip, 445)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(sockaddr)

smb = libsmb2.SMB2Client(s, username='matrix$', password='31d6cfe0d16ae931b73c59d7e0c089c0')#, domain='pwn')

smb.negotiate(pack('<HHH', smb2const.DIALECT_SMB_202, smb2const.DIALECT_SMB_210, smb2const.DIALECT_SMB_300))
smb.session_setup()
smb.tree_connect('IPC$', ip)
#fid = smb.create('browser', GENERIC_READ|GENERIC_WRITE, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, 0x00400040)
fid = smb.create('samr', smb2const.IMPERSONATION_IMPERSONATION, FILE_READ_DATA|FILE_WRITE_DATA, ATTR_NORMAL, FILE_SHARE_READ, FILE_OPEN, 0x00000040)

if fid is not None:
    #smb.write(fid)
    smb.samr_connection(fid)
    
    #smb.close(fid)


#smb.tree_disconnect()
#smb.logoff()
s.close()

