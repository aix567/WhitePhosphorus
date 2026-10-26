import sys
import uuid
import logging
from struct import pack, unpack, calcsize

if "." not in sys.path:
    sys.path.append(".")

from libs.newsmb.Struct import Struct

import libs.newsmb.libdcerpc as libdcerpc
from libs.newsmb.libdcerpc import NDR32, NDR64
from libs.newsmb.libdcerpc import DCERPC, DCERPCContext, DCERPCException, RPC_C_EP_ALL_ELTS
from libs.newsmb.libsmb import assert_unicode

EPT_MAP = 0x3
EPT_LOOKUP = 0x2

class EPMAP(DCERPC):
    def __init__(self, binding, getsock=None, username=None, password=None, computer=None, domain=None, frag_level=None, smbport=445):
        DCERPC.__init__(self, binding, getsock, username, password, computer, domain, frag_level, smbport=smbport)

    def ept_map(self, uuid, version):
        tower = ''
        tower += pack('<H', 5) #5 Floors
        tower += pack('<HB', 0x13, 0xd)        #Floor 1
        tower += DCERPCContext(uuid=uuid, version=version).tower_pack()
        tower += pack('<HH', 2, 0)
        tower += pack('<HB', 0x13, 0xd)        #Floor 2
        tower += DCERPCContext(uuid = u'8a885d04-1ceb-11c9-9fe8-08002b104860', version = u'2.0').tower_pack()
        tower += pack('<HH', 2, 0)
        tower += pack('<HBHH', 1, 0xb, 2, 0)   #Floor 3
        tower += pack('<HBH', 1, 0x7, 2)       #Floor 4
        tower += pack('>H', 135)
        tower += pack('<HBHL', 1, 0x9, 4, 0)   #Floor 5

        data = ''
        data += pack('<L', 1)
        data += '\0' * 16
        data += pack('<L', 2)
        data += pack('<LL', len(tower), len(tower))
        data += tower
        size = len(data) % 4
        if size != 0:
            data += '\0' * (4 - size)
        data += '\0' * 20
        data += pack('<L', 4)

        self.call(EPT_MAP, data, response = True)

        data = self.reassembled_data
        logging.debug('%s' % data.encode('hex'))
        status = unpack('<L', data[-4:])[0]
        if status != 0:
            logging.debug('Unexpected status: %d' % status)
        p = calcsize('<L16sLLLL')
        if len(data) < p:
            logging.debug('Not enough data')
        _, _, n_towers, _, _, _ = unpack('<L16sLLLL', data[:p])
        data = data[p:]
        for i in range(n_towers):
            p = calcsize('<LLLH')
            _, size, _, n_floors = unpack('<LLLH', data[:p])
            data = data[p:]
            for j in range(n_floors):
                p = calcsize('<H')
                lhs_length = unpack('<H', data[:p])[0]
                data = data[p:]
                key = data[:lhs_length]
                data = data[lhs_length:]
                if lhs_length > 0:
                    p = calcsize('<B')
                    protocol = unpack('<B', key[:p])[0]
                    key = key[p:]
                    if protocol == 0x0d: #uuid
                        p = calcsize('<16sBB')
                        uuid, major_version, minor_version = unpack('<16sBB', key[:p])
                    elif protocol == 0x0b: #?
                        pass
                    elif protocol == 0x07: #port
                        pass
                    elif protocol == 0x09: #ip
                        pass
                p = calcsize('<H')
                if len(data) < 2:
                    logging.debug('Not enough data')
                    return

                rhs_length = unpack('<H', data[:p])[0]
                data = data[p:]
                value = data[:rhs_length]
                data = data[rhs_length:]
                logging.debug('%s:%s'%(key.encode('hex'),value.encode('hex')))


    def ept_lookup(self, handle):
        """
        Lookup HANDLE (20-byte buffer) and return dict of results or None.

        Dict should contain the following keys:
        'handle' -> 20 bytes long buffer, this can be reused in subsequent calls
        'annotation length'

        Dict may contain the following keys:
        'uuid'
        'version'
        'tcp'
        'udp'
        'ip'
        'netbios'
        'http'
        'ncalrpc'
        """
        result = {}
        data = ''
        data += pack('<L', RPC_C_EP_ALL_ELTS)
        data += '\0'*4 # NULL object reference
        data += '\0'*4 # NULL interface reference
        data += '\0'*4 # Version
        data += handle # Initial handle
        data += pack('<L', 1) # Maxents

        try:
            self.call(EPT_LOOKUP, data, response=True)
        except DCERPCException, ex:
            logging.debug('EPT Lookup exception: %s' % ex)
            return None

        data = self.reassembled_data

        if data == '':
            return None # Should raise Exception, probably FAULT

        status = unpack('<L', data[-4:])[0]
        if status != 0: # Should raise Exception
            logging.debug('EPT Lookup response status is: %x' % status)
            return None

        result['handle'], data = data[:20], data[20:]
        numents = unpack('<L', data[:4])[0]

        if numents == 0:
            return None

        data = data[40:]
        # load the annotation
        annotation_length, data = unpack('<L', data[:4])[0], data[4:]
        result['annotation length'] = annotation_length

        # here we also correct for mod 4 padding
        pad_length = 4 - annotation_length % 4

        if pad_length == 4:
            pad_length = 0

        # here we skip some stuff (tower lengths)?
        data = data[(annotation_length+pad_length)+8:]
        floors, data = unpack('<H', data[:2])[0], data[2:]
        floor = 1

        while floor <= floors:
            tint, data = unpack('<H', data[:2])[0], data[2:]
            if floor == 1:
                result['uuid'] = data[1:17]
                result['version'] = unpack('<H', data[17:19])[0]
            elif floor in (2, 3):
                pass
            else:
                address_type = ord(data[0])

            # second tint
            data = data[tint:]
            tint, data = unpack('<H', data[:2])[0], data[2:]
            backup = data

            if floor > 3:
                if address_type == 0x07:
                    result['tcp'] = unpack('>H', data[:2])[0]
                elif address_type == 0x08:
                    result['udp'] = unpack('>H', data[:2])[0]
                elif address_type == 0x09:
                    result['ip'] = u'%s.%s.%s.%s' % (ord(data[0]),
                                                     ord(data[1]),
                                                     ord(data[2]),
                                                     ord(data[3]))
                elif address_type == 0x0f:
                    index=data.find("\x00")
                    result['np'] = unicode(data[:index])
                elif address_type == 0x10:
                    index = data.find("\x00")
                    result['ncalrpc'] = unicode(data[:index])
                elif address_type == 0x11:
                    index = data.find("\x00")
                    result['netbios'] = unicode(data[:index])
                elif address_type == 0x1f:
                    result['http'] = unpack('>H', data[:2])[0]
                else:
                    logging.debug("Unknown address type: %d (floor %d, %d bytes)" % (address_type, floor, tint))

            floor += 1
            data = backup[tint:]

        if result['handle'][4:] == '\x00'*16:
            return None

        return result

    def dump(self):
        """
        Exhaustively call ept_lookup and return list of results (dictionaries).
        """
        handle = '\0'*20
        ret = True
        result = []

        while ret != None:
            ret = self.ept_lookup(handle)
            if ret != None:
                result.append(ret)
                handle = ret['handle']

        return result


class EPTHandle:
    def __init__(self, handle_dict=None):
        self.handle_dict = handle_dict

        if self.handle_dict == None:
            self.handle_dict = {}
            self.handle_dict['handle'] =  '\0'*20

    def getuuid(self):
        return uuid.UUID(bytes_le = self.handle_dict['uuid'])

    def getversion(self):
        return self.handle_dict.get('version')

    def get_type_info(self):
        type_info = ''

        if 'tcp' in self.handle_dict:
            type_info += u'tcp:%d:' % self.handle_dict['tcp']

        if 'udp' in self.handle_dict:
            type_info += u'udp:%d:' % self.handle_dict['udp']

        if 'netbios' in self.handle_dict:
            type_info += u'netbios:%s:' % self.handle_dict['netbios']

        if 'np' in self.handle_dict:
            type_info += u'namedpipe:%s:' % self.handle_dict['np']

        if 'http' in self.handle_dict:
            type_info += u'http:%s:' % self.handle_dict['http']

        if 'ip' in self.handle_dict:
            type_info += u'ip:%s:' % self.handle_dict['ip']

        if 'ncalrpc' in self.handle_dict:
            type_info += u'ncalrpc:%s:' % self.handle_dict['ncalrpc']

        return type_info


    def getinfo(self):
        u         = self.getuuid()
        version   = self.getversion()
        type_info = self.get_type_info()

        return u'%s:%d:%s' % (u, version, type_info)

    def getendpoint(self, ip):
        """
        Gets a nicely displayed and compatible endpoint.
        ip argument is only used when it is not provided internally, for named pipes.
        """
        if 'tcp' in self.handle_dict:
            return u'ncacn_ip_tcp:%s[%d]' % (self.handle_dict['ip'],
                                             self.handle_dict['tcp'])
        elif 'udp' in self.handle_dict:
            return u'ncacn_ip_udp:%s[%d]' % (self.handle_dict['ip'],
                                             self.handle_dict['udp'])
        elif 'np' in self.handle_dict:
            return u'ncacn_np:%s[%s]' % (ip, self.handle_dict['np'])
        elif 'http' in self.handle_dict:
            return u'ncacn_http:%s[%d]' % (self.handle_dict['ip'],
                                           self.handle_dict['http'])
        elif 'ncalrpc' in self.handle_dict:
            return u'ncalrpc:[%s]' % self.handle_dict['ncalrpc']
        else:
            return u''

    def isUUID(self, UUID):
        UUID = assert_unicode(UUID)
        return UUID == unicode(uuid.UUID(bytes_le=self.handle_dict['uuid']))

    def isRemote(self):
        return self.isHTTP() or self.isNP() or self.isTCP() or self.isUDP()

    def isTCP(self):
        return 'tcp' in self.handle_dict

    def isUDP(self):
        return 'udp' in self.handle_dict

    def isNP(self):
        return 'np' in self.handle_dict

    def isHTTP(self):
        return 'http' in self.handle_dict

    def __str__(self):
        return self.getendpoint(self.handle_dict['ip'])


# Probably this structure is the output arguments of ept_map function
class EPMAPResponse(Struct):
    st = [
        ['handle'       , '20s',  '\0'*20],
        ['num_towers'   , '<L',   0],
        ['p_tower_array', '0s',   ''], #
        ['return_code'  , '<L',   0 ]
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data = None)

        if data is not None:
            init_pos = 0
            fin_pos = calcsize('20s')
            self['handle'] = data[init_pos:fin_pos]

            init_pos = fin_pos
            fin_pos += calcsize('<L')
            self['num_towers'] = data[init_pos:fin_pos]

            init_pos = fin_pos
            fin_pos = len(data)-4
            self['p_tower_array'] = data[init_pos:fin_pos]

            init_pos = fin_pos
            self['return_code'] = data[fin_pos:]

    def unpack(self):
        for i in range(len(self.st)):
            if self.st[i][1] != '0s':
                self.value[self.st[i][0]] = unpack(self.st[i][1], self.value[self.st[i][0]])[0]

class TowerArray64(Struct):
    st = [
        ['max_count'    , '<Q', 0],
        ['offset'       , '<Q', 0],
        ['actual_count' , '<Q', 0],
        ['p_towers'      , '0s', '']#tower pointer
    ]

    def __init__(self):
        Struct.__init__(self, data = None)

        if data is not None:
            pos = 0
            for i in range(len(self.st)):
                if self.st[i][1] != '0s':
                    npos = pos + calcsize(self.st[i][1])
                    self[self.st[i][0]] = data[pos:npos]
                    pos = npos

            self['p_tower'] = data[pos:]


    def pack(self):
        return Struct.pack(self) + self['p_tower']

    def unpack(self):
        for i in range(len(self.st)):
            if self.st[i][1] != '0s':
                self.value[self.st[i][0]] = unpack(self.st[i][1], self.value[self.st[i][0]])[0]

class TowerArray32(Struct):
    st = [
        ['max_count'    , '<L', 0],
        ['offset'       , '<L', 0],
        ['actual_count' , '<L', 0],
        ['referent_id'  , '0s', ''],
        ['p_tower'      , '0s', '']
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data = None)

        if data is not None:
            pos = 0
            for i in range(len(self.st)):
                if self.st[i][1] != '0s':
                    npos = pos + calcsize(self.st[i][1])
                    self[self.st[i][0]] = data[pos:npos]
                    pos = npos

        if isinstance(self['actual_count'], str):
            cnt = unpack('<L', self['actual_count'])[0]
        else:
            cnt = self['actual_count']    

        npos = pos + (calcsize('<L')*cnt)
        self['referent_id'] = data[pos:npos]

        pos = npos
        self['p_tower'] = data[pos:]

    def pack(self):
        return Struct.pack(self) + self['referent_id'] + self['p_tower']

    def unpack(self):
        for i in range(len(self.st)):
            if self.st[i][1] != '0s':
                self.value[self.st[i][0]] = unpack(self.st[i][1], self.value[self.st[i][0]])[0]


class Tower32(Struct):
    st = [
        ['length1'      , '<L', 0],
        ['length2'      , '<L', 0],
        ['n_floors'     , '<H', 0],
        ['p_floors'     , '0s', '']
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data=None)

        if data is not None:
            pos = 0
            for i in range(len(self.st)):
                if self.st[i][1] != '0s':
                    npos = pos + calcsize(self.st[i][1])
                    self.value[self.st[i][0]] = data[pos:npos]
                    pos = npos

            self['p_floors'] = data[pos:]

    def pack(self):
        return Struct.pack(self) + self['p_floors']

    def unpack(self):
        pos = 0
        for i in range(len(self.st)):
            if self.st[i][1] != '0s':
                npos = pos + calcsize(self.st[i][1])
                self.value[self.st[i][0]] = unpack(self.st[i][1], self.value[self.st[i][0]])[0]
                pos = npos


class Tower64(Struct):
    st = [
        ['length1'      , '<Q', 0],
        ['length2'      , '<L', 0],
        ['n_floors'     , '<H', 0],
        ['p_floors'     , '0s', '']
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data=None)

        if data is not None:
            pos = 0
            for i in range(len(self.st)):
                if self.st[i][1] != '0s':
                    npos = pos + calcsize(self.st[i][1])
                    self.value[self.st[i][0]] = data[pos:nops]
                    pos = npos

            self['p_floors'] = data[pos:]

    def pack(self):
        return Struct.pack(self) + self['p_floors']

    def unpack(self):
        pos = 0
        for i in range(len(self.st)):
            if self.st[i][1] != '0s':
                npos = pos + calcsize(self.st[i][1])
                self.value[self.st[i][0]] = unpack(self.st[i][1], self.value[self.st[i][0]])[0]
                pos = npos

# [C706]: Appendix I
# Protocol Identifiers

OSI_TP4                 = 5
OSI_CLNS                = 6
DOD_TCP                 = 7 # port
DOD_UDP                 = 8 # port
DOD_IP                  = 9 # host address
RPC_CONNECTIONLESS_PROTOCOL = 0xA
RPC_CONNECTION_ORIENTED_PROTOCOL = 0xB
UUID_TYPE                = 0xD

class UUIDFloor(Struct):
    st = [
        ['LHS'          , '<H', 0],
        ['procotol_id'  , '<B', 0], # 0xD
        ['uuid'         , '16s', '\0'*16],
        ['version'      , '<H', 0],
        ['RHS'          , '<H', 0],
        ['version_minor', '<H', 0]

    ]

    def __init__(self, data=None):
        Struct.__init__(self, data = None)

        if data is not None:
            pos = 0
            for i in range(len(self.st)):
                npos = pos + calcsize(self.st[i][1])
                self.value[self.st[i][0]] = data[pos:npos]
                pos = npos

    def unpack(self):
        pos = 0
        for i in range(len(self.st)):
            if self.st[i][1] != '16s':
                npos = pos + calcsize(self.st[i][1])
                self.value[self.st[i][0]] = unpack(self.st[i][1], self.value[self.st[i][0]])[0]
                pos = npos
            else:
                self.value[self.st[i][0]] = str(uuid.UUID(bytes_le=self.value[self.st[i][0]]))

# DOD TCP
class DODTCPFloor(Struct):
    st = [
        ['LHS'          , '<H', 0],
        ['protocol_id'  , '<B', 0],
        ['RHS'          , '<H', 0],
        ['tcp_port'     , '>H', 0]
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data = None)

        if data is not None:
            pos = 0
            for i in range(len(self.st)):
                npos = pos + calcsize(self.st[i][1])
                self.value[self.st[i][0]] = data[pos:npos]
                pos = npos

    def unpack(self):
        pos = 0
        for i in range(len(self.st)):
            npos = pos + calcsize(self.st[i][1])
            self.value[self.st[i][0]] = unpack(self.st[i][1], self.value[self.st[i][0]])[0]
            pos = npos

"""
just to calculate the size of a floor
argument is mandatory
"""
class Floor(Struct):
    st = [
        ['LHS'          , '<H', 0],
        ['protocol_id'  , '<B', 0],
        ['remaining'    , '0s', '']
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data = None)

        pos = 0
        for i in range(len(self.st)):
            if self.st[i][1] != '0s':
                npos = pos + calcsize(self.st[i][1])
                self.value[self.st[i][0]] = unpack(self.st[i][1], data[pos:npos])[0]
                pos = npos


        self['remaining'] = data[pos:]

    def calcsize(self):
        lhs = self['LHS']
        c = lhs-1+calcsize(self.st[0][1])
        rhs = unpack('<H', self['remaining'][lhs-1:c])[0]
        return lhs+rhs+(calcsize(self.st[0][1])*2)


class EPTClient():
    def __init__(self, binding_dict):

        self.binding_dict = binding_dict
    
        self.username = None
        self.password = None
        self.domain = None

        self.is64 = False

        self.epm = None

    def set_credentials(self, username = None, password = None, domain = None):
        if username is not None:
            self.username = username
        if password is not None:
            self.password = password
        if domain is not None:
            self.domain = domain

    def __detect_arch(self, n_ctx_elems, ctx_elems):
        scale = libdcerpc.CtxElement(None).calcsize()

        for _ in range(n_ctx_elems+1):
            chunk = ctx_elems[_*scale:(_+1)*scale]
            ctx_item = libdcerpc.CtxElement(chunk)
            ctx_item.unpack()

            if ctx_item['result'] == libdcerpc.ctx_def_result['Acceptance']:
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
            return TowerArray64(data)
        else:
            return TowerArray32(data)

    def Tower(self, data = None):
        if self.is64:
            return Tower64(data)
        else:
            return Tower32(data)

    def ept_bind(self):
        self.epm = EPMAP(self.get_endpoint())

        self.epm.bind(uuid=u'E1AF8308-5D1F-11C9-91A4-08002B14A0FA', version=u'3.0')
        raw_entire_ctx_elem = self.epm.packet.body['p_result_list']

        entire_ctx_elem = libdcerpc.EntireCtxElement(raw_entire_ctx_elem)
        entire_ctx_elem.unpack()

        if not self.__detect_arch(entire_ctx_elem['n_results'], entire_ctx_elem['p_result_t']):
            logging.error('The architecture couln\'t be determinated')
            return False

    def ept_negotiation(self, uuid, version):
        self.epm.ept_map(uuid = uuid, version=version)

        epm_response = EPMAPResponse(self.epm.reassembled_data)
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

            floor = Floor(chunk)
            if floor['protocol_id'] == DOD_TCP:
               dod_tcp = DODTCPFloor(chunk)
               dod_tcp.unpack()
               return dod_tcp['tcp_port']

            size += floor.calcsize()

    def get_endpoint(self, ept_port = None):
        if 'tcp' in self.binding_dict:
            return u'ncacn_ip_tcp:%s[%d]' % (self.binding_dict['ip'],
                                             ept_port if ept_port is not None else self.binding_dict['tcp'])
        elif 'udp' in self.binding_dict:
            return u'ncacn_ip_udp:%s[%d]' % (self.binding_dict['ip'],
                                            ept_port if ept_port is not None else self.binding_dict['udp']) 
        elif 'np' in self.binding_dict:
            return u'ncacn_np:%s[%s]' % (self.binding_dict['ip'], 
                                         ept_port if ept_port is not None else self.binding_dict['np'])

        elif 'http' in self.binding_dict:
            return u'ncacn_http:%s[%d]' % (self.binding_dict['ip'],
                                           ept_port if ept_port is not None else self.binding_dict['http'])
        elif 'ncalrpc' in self.binding_dict:
            return u'ncalrpc:[%s]' % ept_port if ept_port is not None else self.binding_dict['ncalrpc']

    def _ept_map(self, uuid, version):
        ept_port = self.ept_negotiation(uuid, version)

        self.epm = EPMAP(self.get_endpoint(ept_port), username = self.username, password = self.password, domain = self.domain)
        self.epm.bind(uuid, version)

if __name__ == '__main__':

    if len(sys.argv) > 1 and sys.argv[1] == '-v':
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

    ip = '10.0.0.1'
    epm = EPMAP(u'ncacn_ip_tcp:%s[135]' % (ip), getsock=None)
    epm.bind(u'e1af8308-5d1f-11c9-91a4-08002b14a0fa', u'3.0')
    try:
        print epm.dump()
        epm.ept_map(u'12345678-1234-abcd-ef00-01234567cffb', u'1.0') #NetLogon UUID
        epm.ept_map(u'1FF70682-0A51-30E8-076D-740BE8CEE98B', u'1.0')
    except Exception as e:
        logging.error('A parsing error occured: %s' % str(e))
