#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  samr.py
## Description:
##            :
## Created_On :  Tue Oct 6 CEST 2015
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

# The API is not 100% written but is currently working quite well.
# Implemented from Wireshark && [MS-SAMR].pdf

# Confirmed working with:
#    Windows 2003
#    Windows 2008 R2
#    Windows 7
#    Windows 2012

import sys
import logging
from struct import pack, unpack, calcsize

if '.' not in sys.path:
    sys.path.append('.')

import libs.newsmb.libdcerpc as libdcerpc

from libs.newsmb.libdcerpc import DCERPC, DCERPCString, DCERPCSid
from libs.newsmb.libdcerpc import RPC_C_AUTHN_WINNT
from libs.newsmb.libdcerpc import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from libs.newsmb.Struct import Struct
from libs.Crypto.Cipher.DES import fiftysix_to_sixtyfour

from Crypto.Cipher import DES
###
# Constants
###

# The RPC methods
# TODO.

###
# SAMR Objects.
# No exception handling for these objects.
###

# TODO.

#######################################################################
#####
##### Exception classes
#####
#######################################################################

# TODO.

#######################################################################
#####
##### A couple of useful functions for other parts of CANVAS
#####
#######################################################################

##### The name is inspired from [MS-NRPC] 3.1.4.4.2, there is called InitLMKey
# 2.2.11.1 DES-ECB-LM
# This key transform is used to encrypt and decrypt NT and LM hashes
## 2.2.11.1.2 Encrypting a 64-Bit Block with a 7-Byte Key 
def InitNTLMKey(input_key):
    output_key = []
    output_key.append( chr(ord(input_key[0:1]) >> 0x01) )
    output_key.append( chr(((ord(input_key[0:1])&0x01)<<6) | (ord(input_key[1:2])>>2)) )
    output_key.append( chr(((ord(input_key[1:2])&0x03)<<5) | (ord(input_key[2:3])>>3)) )
    output_key.append( chr(((ord(input_key[2:3])&0x07)<<4) | (ord(input_key[3:4])>>4)) )
    output_key.append( chr(((ord(input_key[3:4])&0x0F)<<3) | (ord(input_key[4:5])>>5)) )
    output_key.append( chr(((ord(input_key[4:5])&0x1F)<<2) | (ord(input_key[5:6])>>6)) )
    output_key.append( chr(((ord(input_key[5:6])&0x3F)<<1) | (ord(input_key[6:7])>>7)) )
    output_key.append( chr(ord(input_key[6:7]) & 0x7F) )

    for i in range(8):
        output_key[i] = chr((ord(output_key[i]) << 1) & 0xfe)

    return "".join(output_key)

# 2.2.11.1.1
def SAMEncryptNTLMHash(encrypted_hash, key):
    block1 = encrypted_hash[:8]
    block2 = encrypted_hash[8:]

    key1 = key[:7]
    key2 = key[7:14]

    encrypted_block1 = DES.new(InitNTLMKey(key1), DES.MODE_ECB).encrypt(block1)
    encrypted_block2 = DES.new(InitNTLMKey(key2), DES.MODE_ECB).encrypt(block2)

    return encrypted_block1 + encrypted_block2
    
###########

# 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
def DeriveKeyFromLittleEndian(key_int):
    """
    Key derivation mechanism used to recover hashes.
    """
    k = pack('<L',key_int)
    k1 = fiftysix_to_sixtyfour(k[0:4] + k[0:3])
    k2 = fiftysix_to_sixtyfour(k[3] + k[0:4] + k[0:2])
    return k1,k2



#######################################################################
SAMR_UUID = u'12345778-1234-ABCD-EF00-0123456789AC' # version 1.0

class Connect(Struct):
    opnum = 0

    st = [
        ['ServerName'   , '0s', ''], #wchar_t *
        ['DesiredAccess', '<L', 0]
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data)

    def pack(self):
        request = ''

        request += pack('<L', 0x1337)

        if self['ServerName'] == '':
            self['ServerName'] = '\0'*4

        request += self['ServerName']

        request += pack('<L', self['DesiredAccess'])

        return request

class ConnectResponse(Struct):
    st = [
        ['ServerHandle' , '20s', '\0'*20],
        ['ErrorCode'    , '<L', 0]
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data = None)

class LookupDomain(Struct):
    opnum = 5

    st = [
        ['ServerHandle' , '20s', '\0'*20],
        ['DomainName'   , '0s', ''],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data=None)

    def pack(self):
        request = ''

        request += self['ServerHandle']
        
        domain_name = self['DomainName'].encode('utf-16le')
        domain_name_length = len(domain_name)

        lsa_string =  libdcerpc.DCERPCString(string=domain_name).pack(1, 0)

        request += pack('<H', len(domain_name)) #name len
        request += pack('<H', len(domain_name)) #name size
        request += pack('<L', 0x1337) #Referent ID
        request += lsa_string

        return request

class LookupDomainResponse(Struct):
    st = [
        ['ReferentID'   , '<L', 0],
        ['Sid'          , '0s', ''],
        ['ErrorCode'    , '<L', 0]
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data=None)

    def unpack(self, data):
        pos = calcsize(self.st[0][1]) 

        self['ReferentID'] = unpack('<L', data[:pos])[0]
        self['Sid'] = data[pos:]
        self['ErrorCode'] = unpack('<L', data[-4:])[0]

class OpenDomain(Struct):
    opnum = 7

    st = [
        ['ServerHandle'     , '20s', '\0'*20],
        ['DesiredAccess'    , '<L', 0],
        ['Sid'              , '20s', '']
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data=None)

    def pack(self):
        request = ''
        
        request += self['ServerHandle']
        request += pack('<L', self['DesiredAccess'])
        request += self['Sid']

        return request

class OpenDomainResponse(Struct):
    st = [
        ['DomainHandle' , '20s', '\0'*20],
        ['ErrorCode'    , '<L', 0]
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data = None)

class EnumDomainUsers(Struct):
    opnum = 13

    st = [
        ['DomainHandle'         , '20s', '\0'],
        ['EnumerationContext'   , '<L', 0],
        ['UserAccountControl'   , '<L', 0], #AccountFlags
        ['PreferedMaximumLength' , '<L', 0]
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data = None)


class Entry(Struct):
    st = [
            ['Rid', '<L', 0],
            ['AccountName', '0s', '']
    ]

def EntryArray(data):
    entries = []
    entries_count = unpack('<L', data[:4])[0]
    entries_raw = data[12:]

    scale = 12
    entries_hdr_size = entries_count * scale

    dummy_entries = ''
    dummy_names = entries_raw[entries_hdr_size:]
    dcestring_hdr_size = libdcerpc.DCERPCString().calcsize()

    for i in range(entries_count):
        dummy_entries = entries_raw[i*scale:]

        entry = Entry()
        entry['Rid'] = unpack('<L', dummy_entries[:4])[0]

        name_len = unpack('<H', dummy_entries[4:6])[0]
        entry['AccountName'] = dummy_names[dcestring_hdr_size:dcestring_hdr_size+name_len].decode('utf-16le')
            
        pad = name_len % 4
        dummy_names = dummy_names[dcestring_hdr_size+name_len+pad:]

        entries.append(entry)

    return entries

class EnumDomainUsersResponse(Struct):
    st = [
        ['EnumerationContext'   , '<L', 0],
        ['ReferentID'           , '<L', 0],
        ['EntriesBuffer'        , '0s', ''],
        ['EnumEntries'          , '<L', 0],
        ['ErrorCode'            , '<L', 0]
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data = None)

    def unpack(self, data):
        pos = 0
        npos = calcsize(self.st[0][1])
        self['EnumerationContext'] = unpack(self.st[0][1], data[pos:npos])[0]

        pos = npos
        npos += calcsize(self.st[1][1])
        self['ReferentID'] = unpack(self.st[0][1], data[pos:npos])[0]

        pos = npos
        npos = len(data) - (calcsize(self.st[3][1]) + calcsize(self.st[4][1]))
        self['EntriesBuffer'] = data[pos:npos]

        pos = npos
        npos += calcsize(self.st[3][1])
        self['EnumEntries'] = unpack(self.st[3][1], data[pos:npos])[0]

        pos = npos
        self['ErrorCode'] = unpack(self.st[4][1], data[npos:])[0]
        
        self['EntriesBuffer'] = EntryArray(self['EntriesBuffer'])
        
class RidToSid(Struct):
    opnum = 65

    st = [
        ['DomainHandle' , '20s', '\0'*20],
        ['Rid'          , '<L', 0]
    ]

class RidToSidResponse(Struct):
    st = [
        ['ReferentID'   , '<L', 0],
        ['Sid'          , '0s', ''],
        ['ErrorCode'    , '<L', 0]
    ]

    def unpack(self, data):
        pos = 0
        npos = calcsize(self.st[0][1])
        self['ReferentID'] = unpack(self.st[0][1], data[pos:npos])[0]

        pos = npos
        npos = len(data) - calcsize(self.st[2][1])
        self['Sid'] = data[pos:npos]

        self['ErrorCode'] = unpack(self.st[2][1], data[npos:])[0]


class SAMRException(Exception):
    pass

class SAMR():
    def __init__(self, ip='', port=0, getsock=None, \
                username=None, password=None, computer=None, domain=None, \
                frag_level=None):
        if ip == '':
            raise SAMRException('The IP is empty')
        self.ip = ip

        if port == 0:
            raise SAMRException('The port is incorrect')
        self.port = port

        self.getsock = getsock

        self.username = username
        self.password = password
        self.computer = computer # Curently we dont' use it, TODO: recheck if its implementation is necessary
        self.domain   = domain

        self.dcerpc = None

    #TODO: implement SAMR over TCP
    def tcp(self):
        pass

    def smb2(self):
        binding = "ncacn_np:%s[\\pipe\\samr]" % self.ip

        self.dcerpc = DCERPC(binding, self.getsock, self.username, 
                            self.password, self.computer, self.domain, smbport=self.port, #the port should be 445
                            is_smb2=True)

        self.dcerpc.bind(uuid = SAMR_UUID, version = u'1.0')

    def fnConnect(self, server_name = '\0'*4, desired_access = 0x02000000): # MAXIMUM_ALLOWED = 0x02000000
        request = Connect()

        request['ServerName'] = server_name
        request['DesiredAccess'] = desired_access

        self.dcerpc.call(request.opnum, request.pack())
        data = self.dcerpc.packet.body['data']

        response = ConnectResponse()
        response.unpack(data)

        return response

    def fnLookupDomain(self, server_handle, domain_name):
        request  = LookupDomain()

        request['ServerHandle'] = server_handle
        request['DomainName'] = domain_name

        self.dcerpc.call(request.opnum, request.pack())
        data = self.dcerpc.packet.body['data']
        
        response = LookupDomainResponse()
        response.unpack(data)

        return response

    def fnOpenDomain(self, server_handle, sid, desired_access = 0x2000000):
        request = OpenDomain()

        request['ServerHandle'] = server_handle
        request['Sid'] = sid
        request['DesiredAccess'] = desired_access

        self.dcerpc.call(request.opnum, request.pack())
        data = self.dcerpc.packet.body['data']

        response = OpenDomainResponse()
        response.unpack(data)

        return response

    def fnEnumDomainUsers(self, domain_handle, enum_ctx = 0, user_acc_ctrl = 0x1d0, max_len = 0xFFFFFFFF):
        request = EnumDomainUsers()

        request['DomainHandle'] = domain_handle
        request['EnumerationContext'] = enum_ctx
        request['UserAccountControl'] = user_acc_ctrl
        request['PreferedMaximumLength'] = max_len

        self.dcerpc.call(request.opnum, request.pack())
        data = self.dcerpc.packet.body['data']

        response = EnumDomainUsersResponse()
        response.unpack(data)

        return response

    def fnRidToSid(self, domain_handle, rid):
        request = RidToSid()

        request['DomainHandle'] = domain_handle
        request['Rid'] = rid

        self.dcerpc.call(request.opnum, request.pack())
        data = self.dcerpc.packet.body['data']

        response = RidToSidResponse()
        response.unpack(data)

        return response

if __name__ == "__main__":
    pass
