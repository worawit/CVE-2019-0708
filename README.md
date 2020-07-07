# CVE-2019-0708 (BlueKeep)

~~Currently, I public only the exploitation note for Windows 7 x64 only.~~ See [NOTE.md](NOTE.md)

**Note:** Windows 2008 R2 with default configuration (fDisableCam=1) can be exploited. Reliability is same as Windows 7.

## Update (July 2020)

- Add info for Windows Server 2008 to [NOTE.md](NOTE.md)
- Add PoCs for filling target kernel unpaged pool
- Add script for detecting target info
- Add PoC code execution on Windows 7 x86

#### Files

 * **myrdp.py** My RDP library (messy)
 * **myasn1.py** My ASN.1 for RDP (required by myrdp.py)
 * **rdp4mppc.py** MPPC-Based Bulk Data Compression for RDP 4.0
 * **rdp_detect_info.py** For detecting info related to vulnerability from RDP server
 * **poc_rdpsnd.py** PoC code execution on Windows 7 x86
 * **poc_rdpsnd_fill.py** PoC for filling kernel nonpaged pool over RDPSND channel
 * **poc_rdpdr_fill.py** PoC for filling kernel nonpaged pool over RDPDR channel
 * **poc_refreshrect_fill.py** PoC for filling kernel nonpaged pool with REFRESHRECT pdu
