import drsuapi
import libdcerpc
import samr
from samr import SAMR

from hexdump import hexdump

samr = SAMR('192.168.1.95', 445, username='matrix$', password='31d6cfe0d16ae931b73c59d7e0c089c0')
samr.smb2()

connect_response = samr.fnConnect()

server_domain_name = samr.dcerpc.dcerpc_connection.get_server_domain() 
print(server_domain_name)
lookupdomain_response = samr.fnLookupDomain(connect_response['ServerHandle'], server_domain_name)

opendomain_response = samr.fnOpenDomain(connect_response['ServerHandle'], lookupdomain_response['Sid'])

enumdomainusers_response = samr.fnEnumDomainUsers(opendomain_response['DomainHandle'])

entries = enumdomainusers_response['EntriesBuffer']

print entries
print entries[0]['Rid']

response = samr.fnRidToSid(opendomain_response['DomainHandle'], entries[0]['Rid'])
#hexdump(response['Sid'])

dcerpc_sid = libdcerpc.DCERPCSid(response['Sid'])

print dcerpc_sid.get_sid()
print"*"*20

raw_input("press ANY key to exit")
