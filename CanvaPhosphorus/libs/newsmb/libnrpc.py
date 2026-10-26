#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  libnrpc.py
## Description:  Implementation of Netlogon RPC
##            :
## Created_On :  Wed Jul 22 13:56:57 2009
## Created_By :  Nox
##
## (c) Copyright 2020, Immunity, Inc. all rights reserved.
###############################################################################


import sys
import hmac
import hashlib
import logging
from Crypto.Cipher import AES
from struct import pack, unpack, calcsize

if '.' not in sys.path:
    sys.path.append('.')


import libs.newsmb.libntlm as ntlm

import libs.newsmb.libdcerpc as dcerpc
from libs.newsmb.libdcerpc import NDR32, NDR64
from libs.newsmb.libdcerpc import DCERPC, DCERPCString, DCERPCException

import libs.newsmb.epmap as epmap
from libs.newsmb.epmap import EPMAP, EPTHandle
from libs.newsmb.Struct import Struct


EPMv4_UUID = 'E1AF8308-5D1F-11C9-91A4-08002B14A0FA'
Netlogon_UUID = '12345678-1234-ABCD-EF00-01234567CFFB'


NullSecureChannel = 0,
MsvApSecureChannel = 1,
WorkstationSecureChannel = 2,
TrustedDnsDomainSecureChannel = 3,
TrustedDomainSecureChannel = 4,
UasServerSecureChannel = 5,
ServerSecureChannel = 6,
CdcServerSecureChannel = 7

NETLOGON_SECURE_CHANNEL_TYPE = {
    'NullSecureChannel'             : 0,
    'MsvApSecureChannel'            : 1,
    'WorkstationSecureChannel'      : 2,
    'TrustedDnsDomainSecureChannel' : 3,
    'TrustedDomainSecureChannel'    : 4,
    'UasServerSecureChannel'        : 5,
    'ServerSecureChannel'           : 6,
    'CdcServerSecureChannel'        : 7,
}


# [MS-NRPC] 3.1.4.3.1
def ComputeSessionKey(shared_secret, client_challenge, server_challenge, shared_secret_hash = None):
    if shared_secret_hash is None:
        M4SS = ntlm.NTOWFv1(shared_secret, '', '') #plaintext password
    else:
        M4SS = shared_secret_hash # ntml hash

    m = hmac.new(key=M4SS, digestmod=hashlib.sha256)
    m.update(client_challenge)
    m.update(server_challenge)

    session_key = m.digest()
    return session_key[:16]


# [MS-NRPC] 3.1.4.3.1
def ComputeNetlogonCredentialAES(input_data, session_key):
    return AES.new(session_key, mode=AES.MODE_CFB, IV='\0'*16, segment_size=8).encrypt(input_data)

# [MS-NRPC] 3.1.4.4.2
def ComputeNetlogonCredentialDES():
    pass

class NETLOGON_AUTHENTICATOR(Struct):
    st = [
        ['Credential'   , '8s', '\0'*8],
        ['Timestamp'    , '<L', 0]
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data=None)

# 2.2.1.3.7 NL_TRUST_PASSWORD       
class NL_TRUST_PASSWORD(Struct):
    st = [
        ['Buffer', '512s', '\0'*512],
        ['Length', '<L', 0]
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data = None)

class NetrServerReqChallenge(Struct):
    opnum = 4
    st = [
        ['PrimaryName'      , '0s', ''],
        ['ComputerName'     , '0s', ''],
        ['ClientChallenge'  , '8s', '\0'*8],
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data=None)


    def pack(self):
        request = ''

        if self['PrimaryName'] != '\0'*4:
            request += pack('<L', 0x1337) # Referent ID
            self.value['PrimaryName'] = dcerpc.s_dce_win2k_unistring(self['PrimaryName'], True)
        request += self['PrimaryName']

        self.value['ComputerName'] = dcerpc.s_dce_win2k_unistring(self['ComputerName'], False)
        request += self['ComputerName']

        request += self['ClientChallenge']

        return request


class NetrServerReqChallengeResponse(Struct):
    st = [
        ['ServerChallenge', '8s', '\0'*8],
        ['ErrorCode',      '<L', 0]
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data = None) 

class NetrServerAuthenticate2(Struct):
    opnum = 15
    st = [
        ['PrimaryName'      , '0s', ''],
        ['AccountName'      , '0s', ''],
        ['SecureChannelType', '<H', 0],
        ['ComputerName'     , '0s', ''],
        ['ClientCredential' , '8s', '\0'*8],
        ['NegotiateFlags'   , '<L', 0]
    ]
    
    def __init__(self, data = None):
        Struct.__init__(self, data=None)
        
    def pack(self):
        request = ''
        
        if self['PrimaryName'] != '\0'*4:
            request += pack('<L', 0x1337) # Referent ID
            self.value['PrimaryName'] = dcerpc.s_dce_win2k_unistring(self['PrimaryName'], True)
        request += self['PrimaryName']

        self.value['AccountName'] = dcerpc.s_dce_win2k_unistring(self['AccountName'], False)
        request += self['AccountName']
        
        self.value['SecureChannelType'] = pack('<H', self['SecureChannelType'])
        request += self['SecureChannelType']
        
        pad = (len(self['AccountName']) + calcsize('<H')) % 4
        if  pad != 0:
            request += '\0'*pad
            
        self.value['ComputerName'] = dcerpc.s_dce_win2k_unistring(self['ComputerName'], False)
        request += self['ComputerName']
        
        request += self['ClientCredential']
        
        pad = (len(self['ClientCredential']) + len(self['ComputerName'])) % 4
        if pad != 0:
            request += '\0'*pad

        request += pack('<L', self['NegotiateFlags'])
        return request

class NetrServerAuthenticate2Response(Struct):
    st = [
        ['ServerCredential' , '8s', '\0'*8],
        ['NegotiateFlags'   , '<L', 0],
        ['ErrorCode'        , '<L', 0]
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data = None)


class NetrServerPasswordSet2(Struct):
        opnum = 30
        st  = [
            ['PrimaryName'      , '0s', ''],
            ['AccountName'      , '0s', ''],
            ['SecureChannelType', '<H', 0],
            ['ComputerName'     , '0s', ''],
            ['Authenticator'    , '12s', '\0'*12], # NETLOGON_AUTHENTICATOR
            ['ClearNewPassword' , '0s', '']
        ]

        def __init__(self, data = None):
            Struct.__init__(self, data = None)

        def pack(self):
            request = ''

            if self['PrimaryName'] != '\0'*4:
                request += pack('<L', 0x1337) # Referent ID
                self.value['PrimaryName'] = dcerpc.s_dce_win2k_unistring(self['PrimaryName'], True)
            request += self['PrimaryName']

            self.value['AccountName'] = dcerpc.s_dce_win2k_unistring(self['AccountName'], False)
            request += self['AccountName']

            self.value['SecureChannelType'] = pack('<H', self['SecureChannelType'])
            request += self['SecureChannelType']

            pad = (len(self['AccountName']) + calcsize('<H')) % 4
            if  pad != 0:
                request += '\0'*pad

            self.value['ComputerName'] = dcerpc.s_dce_win2k_unistring(self['ComputerName'], True)
            request += self['ComputerName']

            request += self['Authenticator']
            
            request += self['ClearNewPassword']

            return request

class NetrServerPasswordSet2Response(Struct):
    st = [
        ['ReturnAuthenticator'  , '12s', '\0'*8],
        ['ErrorCode'            , '<L', 0]
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data = None)

    def unpack(self, data):
        authenticator = NETLOGON_AUTHENTICATOR()
        authenticator.unpack(data)
        self.value[self.st[0][0]] = authenticator

        pos = calcsize(self.st[0][1])
        self.value[self.st[1][0]] = unpack('<L', data[pos:])[0]


class NetrServerPasswordSet(Struct):
    opnum = 6
    st  = [
            ['PrimaryName'      , '0s', ''],
            ['AccountName'      , '0s', ''],
            ['SecureChannelType', '<H', 0],         # NETLOGON_SECURE_CHANNEL_TYPE
            ['ComputerName'     , '0s', ''],
            ['Authenticator'    , '12s', '\0'*12],  # NETLOGON_AUTHENTICATOR
            ['UasNewPassword'   , '16s', '\0'*16]   # ENCRYPTED_NT_OWF_PASSWORD
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data = None)

    def pack(self):
        request = ''

        if self['PrimaryName'] != '\0'*4:
            request += pack('<L', 0x1337) # Referent ID
            self.value['PrimaryName'] = dcerpc.s_dce_win2k_unistring(self['PrimaryName'], True)
        request += self['PrimaryName']

        self.value['AccountName'] = dcerpc.s_dce_win2k_unistring(self['AccountName'], False)
        request += self['AccountName']

        self.value['SecureChannelType'] = pack('<H', self['SecureChannelType'])
        request += self['SecureChannelType']

        pad = (len(self['AccountName']) + calcsize('<H')) % 4
        if  pad != 0:
            request += '\0'*pad

        self.value['ComputerName'] = dcerpc.s_dce_win2k_unistring(self['ComputerName'], True)
        request += self['ComputerName']

        request += self['Authenticator']

        request += self['UasNewPassword']

        return request



class NetrServerPasswordSetResponse(Struct):
    st = [
        ['ReturnAuthenticator'  , '12s', '\0'*8],
        ['ErrorCode'            , '<L', 0]
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data = None)

    def unpack(self, data):
        authenticator = NETLOGON_AUTHENTICATOR()
        authenticator.unpack(data)
        self.value[self.st[0][0]] = authenticator

        pos = calcsize(self.st[0][1])
        self.value[self.st[1][0]] = unpack('<L', data[pos:])[0]

class NetlogonException(Exception):
    pass


class Netlogon(object):
    def __init__(self, dc_ip = None, dc_port = 135, getsock=None, Host=None, password=None, computer=None, domain=None, frag_level=None):
        self.dc_ip = dc_ip
        self.dc_port = dc_port

        self.my_dcercp = None
        self.my_nrpc = None

        self.is64 = False

    def detect_arch(self, n_ctx_elems, ctx_elems):
        scale = dcerpc.CtxElement(None).calcsize()
       
        for _ in range(n_ctx_elems+1):
            chunk = ctx_elems[_*scale:(_+1)*scale]
            ctx_item = dcerpc.CtxElement(chunk)
            ctx_item.unpack()

            if ctx_item['result'] == dcerpc.ctx_def_result['Acceptance']:
                if ctx_item['uuid'].upper() == NDR64:
                    logging.info('x64 architecture detected')
                    self.is64 = True
                    return True
                elif ctx_item['uuid'].upper() == NDR32:
                    logging.info('x86 architecture detected')
                    self.is64 = False
                    return True
                else:
                    logging.error('Error detecting the arquitecture')
                    return False
                break
        
        return False
    
    def TowerArray(self, data = None):
        if self.is64:
            return epmap.TowerArray64(data)
        else:
            return epmap.TowerArray32(data)

    def Tower(self, data = None):
        if self.is64:
            return epmap.Tower64(data)
        else:
            return epmap.Tower32(data)


    #TODO: Parser all towers to search the tcp_port
    def epm_negotiation(self):
        self.my_dcerpc.ept_map(unicode(Netlogon_UUID), u'1.0') # Netlogon

        epm_response = epmap.EPMAPResponse(self.my_dcerpc.reassembled_data)
        epm_response.unpack()

        num_towers = epm_response['num_towers']
        tower_array = self.TowerArray(epm_response['p_tower_array'])
        tower_array.unpack()

        raw_towers = tower_array['p_tower'] # start of tower array :>
        tower = self.Tower(raw_towers)
        tower.unpack()

        raw_floors = tower['p_floors']
        size = 0
        for _ in range(tower['n_floors']): #only parse the first tower to take the tcp
            chunk = raw_floors[size:]

            floor = epmap.Floor(chunk)
            if floor['protocol_id'] == epmap.DOD_TCP:
               dod_tcp = epmap.DODTCPFloor(chunk)
               dod_tcp.unpack()
               return dod_tcp['tcp_port']

            size += floor.calcsize()

    """    
    def epm_connection(self):
        self.dcerpc.ept_map(unicode(NetLogon_UUID), u'1.0') # NetLogon

        epm_response = EPMapResponse(self.dcerpc.reassembled_data)
        epm_response.unpack()

        num_towers = epm_response['num_towers']
        tower_array = self.TowerArray(epm_response['p_tower_array'])

        raw_towers = tower_array['p_tower'] # start of tower array :>

        offset_ntower = self.Tower().calcsize() # variable size of tower
        for __ in range(num_towers): ## usually the first tower has the port used for netlogon connection
            tower = self.Tower(raw_towers)
            raw_floors = tower['p_floors']

            size_floors = 0
            nsize_floors = Floor(raw_floors).calcsize()
            for _ range(tower['n_floors']):
                floor = Floor(raw_floors[size_floors:nsize_floors])
                if floor['protocol_id'] == DOD_TCP:

    """

    def tcp(self):
        self.my_dcerpc = EPMAP('ncacn_ip_tcp:%s[%d]' % (self.dc_ip, self.dc_port))

        try:
            self.my_dcerpc.bind(unicode(EPMv4_UUID), u'3.0')
            raw_entire_ctx_elem = self.my_dcerpc.packet.body['p_result_list']

            entire_ctx_elem = dcerpc.EntireCtxElement(raw_entire_ctx_elem)
            entire_ctx_elem.unpack()

            if not self.detect_arch(entire_ctx_elem['n_results'], entire_ctx_elem['p_result_t']):
                logging.error('The architecture couln\'t be determinated')
                return False

        except Exception, ex:
            raise NetlogonException("Error on TCP implementation %s" % str(ex))

        netlogon_port = self.epm_negotiation()

        try:
            self.my_nrpc =  EPMAP('ncacn_ip_tcp:%s[%d]' % (self.dc_ip, netlogon_port))
            self.my_nrpc.bind(unicode(Netlogon_UUID), u'1.0')
        except Exception, ex:
            raise NetlogonException('Netlogon TCP negotiation error %s' % str(ex))

    def fnNetrServerReqChallenge(self, primary_name = '\0'*4, computer_name = '', client_challenge = '\0'*8):
        if computer_name == '':
            raise NetlogonException('fnNetrServerReqChallenge request has empty \'ComputerName\' argument')
        
        request = NetrServerReqChallenge()

        request['PrimaryName'] = primary_name
        request['ComputerName'] = computer_name
        request['ClientChallenge'] = client_challenge

        self.my_nrpc.call(request.opnum, request.pack(), response = True)

        if self.my_nrpc.reassembled_data == '':
            raise NetlogonException('An error has occurred calling fnNetrServerReqChallenge')

        response = NetrServerReqChallengeResponse()
        response.unpack(self.my_nrpc.reassembled_data)

        return response

    def fnNetrServerAuthenticate2(self, primary_name = '\0'*4, 
                                    account_name = '', security_channel_type = 0, 
                                    computer_name = '', client_credential = '\0'*8, 
                                    negotiate_flags = 0):
        if account_name == '':
            raise NetlogonException('fnNetrServerAuthenticate2 request has empty \'AccountName\' argument')    
        
        if account_name.endswith('$') is False:
            account_name += '$'
            
        if computer_name == '':
            raise NetlogonException('fnNetrServerReqChallenge request has empty \'ComputerName\' argument')    
        
        request = NetrServerAuthenticate2()
        
        request['PrimaryName'] = primary_name
        request['AccountName'] = account_name
        request['SecureChannelType'] = security_channel_type
        request['ComputerName'] = computer_name
        request['ClientCredential'] = client_credential
        request['NegotiateFlags'] = negotiate_flags
        
        self.my_nrpc.call(request.opnum, request.pack(), response = True)

        if self.my_nrpc.reassembled_data == '':
            raise NetlogonException('An error has occurred calling fnNetrServerAuthenticate2')

        response = NetrServerAuthenticate2Response()
        response.unpack(self.my_nrpc.reassembled_data)
        
        return response
        
    def fnNetrServerPasswordSet2(self, primary_name = '\0'*4, 
                                    account_name = '', secure_channel_type = 0,
                                    computer_name = '', authenticator = '',
                                    clear_new_password= ''):
        if account_name == '':
            raise NetlogonException('fnNetrServerPasswordSet2 request empty \'AccountName\' argument')

        if account_name.endswith('$') is False:
            account_name += '$'
        
        request = NetrServerPasswordSet2()

        request['PrimaryName'] = primary_name
        request['AccountName'] = account_name
        request['SecureChannelType'] = secure_channel_type
        request['ComputerName'] = computer_name
        request['Authenticator'] = authenticator
        request['ClearNewPassword'] = clear_new_password

        self.my_nrpc.call(request.opnum, request.pack(), response = True)

        if self.my_nrpc.reassembled_data == '':
            raise NetlogonException('An error has occurred calling fnNetrServerPasswordSet2')

        response = NetrServerPasswordSet2Response()
        response.unpack(self.my_nrpc.reassembled_data)

        return response

    def fnNetrServerPasswordSet(self, primary_name = '\0'*4,
                                    account_name = '', secure_channel_type = 0,
                                    computer_name = '', authenticator = '',
                                    uas_new_password= ''):
        if account_name == '':
            raise NetlogonException('fnNetrServerPasswordSet request has \'AccountName\' argument empty')

        if account_name.endswith('$') is False:
            account_name += '$'

        request = NetrServerPasswordSet()

        request['PrimaryName'] = primary_name
        request['AccountName'] = account_name
        request['SecureChannelType'] = secure_channel_type
        request['ComputerName'] = computer_name
        request['Authenticator'] = authenticator
        request['UasNewPassword'] = uas_new_password

        self.my_nrpc.call(request.opnum, request.pack(), response = True)

        if self.my_nrpc.reassembled_data == '':
            raise NetlogonException('An error has occurred calling fnNetrServerPasswordSet')

        response = NetrServerPasswordSetResponse()
        response.unpack(self.my_nrpc.reassembled_data)

        return response
       
