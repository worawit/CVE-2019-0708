#!/usr/bin/env python
import sys
import ssl
import socket
from struct import pack, unpack, unpack_from
from myasn1 import *
from rdp4mppc import RDP4MPPC
import hashlib
import threading

ENCRYPTION_METHOD_NONE = 0x00
ENCRYPTION_METHOD_40BIT = 0x01
ENCRYPTION_METHOD_128BIT = 0x02
ENCRYPTION_METHOD_56BIT = 0x08
ENCRYPTION_METHOD_FIPS = 0x10

# SecurityHeaders
# TS_SECURITY_HEADER flags
SEC_EXCHANGE_PKT = 0x0001
SEC_ENCRYPT = 0x0008
SEC_RESET_SEQNO = 0x0010
SEC_IGNORE_SEQNO = 0x0020
SEC_INFO_PKT = 0x0040
SEC_LICENSE_PKT = 0x0080
SEC_LICENSE_ENCRYPT_CS = 0x0200
SEC_LICENSE_ENCRYPT_SC = 0x0200
SEC_REDIRECTION_PKT = 0x0400
SEC_SECURE_CHECKSUM = 0x0800
SEC_FLAGSHI_VALID = 0x8000

# fix request desktop width and height
DESKTOP_WIDTH = 800
DESKTOP_HEIGHT = 600

###########
# RDPDR channel constants
RDPDR_CTYP_CORE = 0x4472
PAKID_CORE_SERVER_ANNOUNCE = 0x496E
PAKID_CORE_CLIENTID_CONFIRM = 0x4343
PAKID_CORE_CLIENT_NAME = 0x434E
PAKID_CORE_CLIENTID_CONFIRM = 0x4343
PAKID_CORE_CLIENT_CAPABILITY = 0x4350
PAKID_CORE_DEVICELIST_ANNOUNCE = 0x4441

def make_tpkt(data):
    return pack("!BBH", 3, 0, 4+len(data)) + data

def make_x224(type, data):
    return pack("!BB", 1+len(data), type) + data

# x224 type 0xf0 (Data TPDU), 0x80 (EOT)
x224_data_hdr = make_x224(0xf0, pack("!B", 0x80))
def make_tpkt_data(data):
    return make_tpkt(x224_data_hdr + data)

# little endian
def int2bytes(n, size):
    s = [0]*size
    i = 0
    while n > 0:
        s[i] = n&0xff
        n >>= 8
        i += 1
    return pack('B'*i, *s)

def bytes2int(s):
    n = 0
    for b in reversed(unpack('B'*len(s), s)):
        n = (n<<8)|b
    return n

def str2wchar(s, l=None):
    if l is None:
        l = len(s) + 1
    out = bytearray(s, 'utf-16-le')
    return out + b"\x00"*((l*2)-len(out))
    
class PublicKey:
    def __init__(self):
        self.e = 65537
        self.n = 0
        self.size = 0
    
# http://msdn.microsoft.com/en-us/library/cc240782%28v=prot.10%29.aspx
def rsa_pubkey_encrypt(txt, key):
    out = pow(bytes2int(txt), key.e, key.n)
    return int2bytes(out, key.size)

class RC4:
    def __init__(self, key):
        # prepare key
        k = bytearray(key)
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + k[i % len(k)]) % 256
            S[i], S[j] = S[j], S[i]
        self._S = S
        self._i = 0
        self._j = 0
    
    # encrypt/decrypt
    def _crypt(self, data):
        S = self._S
        i, j = self._i, self._j
        out = []
        data = bytearray(data)
        for p in range(len(data)):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append( data[p] ^ S[(S[i] + S[j]) % 256] )
        self._S = S
        self._i = i
        self._j = j
        return pack('B'*len(data), *out)
        
    encrypt = _crypt
    decrypt = _crypt
    
###################################################
# functions for crafting RDP request
###################################################
def encode_domain_params(maxChannelIds, maxUserIds, maxTokenIds, numPriorities, minThroughput, maxHeight, maxMCSPDUSize, protocolVersion):
    return ber_encode_seqof(b""
        + ber_encode_int(maxChannelIds)
        + ber_encode_int(maxUserIds)
        + ber_encode_int(maxTokenIds)
        + ber_encode_int(numPriorities)
        + ber_encode_int(minThroughput)
        + ber_encode_int(maxHeight)
        + ber_encode_int(maxMCSPDUSize)
        + ber_encode_int(protocolVersion)
    )

def fix_user_id(userId):
    return userId if userId <= 1001 else userId - 1001

def make_user_data_block(btype, data):
    return pack('<HH', btype, len(data)+4) + data
    
def create_gcc_userdata_init(selectedProtocol, channels):
    clientCoreData = (b"\x04\x00"+b"\x08\x00" # client version
        + pack('<HH', DESKTOP_WIDTH, DESKTOP_HEIGHT) # desktop width, height
        + b"\x01\xca" # color depth
        + b"\x03\xaa" # SASSequence
        + b"\x09\x04\x00\x00" # keyboard layout
        + b"\x28\x0a\x00\x00" # client build number
        + str2wchar("HOST", 16) # client name - WCHAR[16]
        + b"\x04\x00\x00\x00" # keyboard type
        + b"\x00\x00\x00\x00" # kbd subType
        + b"\x0c\x00\x00\x00" # kbd FuncKey
        + str2wchar("", 32) # imeFileName - WCHAR[32]
        + b"\x01\xca" # postBeta2ColorDepth
        + b"\x01\x00" # clientProductId
        + b"\x00\x00\x00\x00" # serialNumber
        + b"\x10\x00" # highColorDepth (16-bit)
        + b"\x07\x00" # supportedColorDepths
        + b"\x01\x00" # earlyCapabilityFlags (errInfo, connectionType? 0x21)
        #+ str2wchar("00000-000-0000000-00000", 32) # clientDigProductId - WCHAR[32]
        + str2wchar("", 32) # clientDigProductId - WCHAR[32]
        + b"\x04" # connectionType
        + b"\x00" # pad1octet
        + pack('<I', selectedProtocol) # serverSelectedProtocol
        #+ b"\x56\x02\x0c\x00" # desktopPhysicalWidth
        #+ b"\x50\x01\x00\x00" # desktopPhysicalHeight
        #+ b"\x00\x00" # desktopOrientation
        #+ b"\x64\x00\x00\x00" # desktopScaleFactor
        #+ b"\x64\x00\x00\x00" # deviceScaleFactor
    )
    
    clientClusterData = pack('<II', 0x9, 0) # flags (REDIRECTION_SUPPORTED, VERSION3), redirectedSessionId
    
    clientSecurityData = pack('<II', 0xb, 0) # encryptionMethods, extEncryptionMethods
    
    clientNetworkData = pack('<I', len(channels)) # channel count
    for name, flag in channels:
        clientNetworkData += bytearray(name, 'ascii').ljust(8, b'\x00') + pack('<I', flag)
    
    # Note: if there are multiple user data block, server use last one (might be useful for detection evasion)
    userdata = (b"" # this is not asn.1
        # clientCoreData (TS_UD_CS_CORE)
        + make_user_data_block(0xc001, clientCoreData)
        # clientCoreData (TS_UD_CS_CLUSTER)
        + make_user_data_block(0xc004, clientClusterData)
        # clientSecurityData (TS_UD_CS_SEC)
        + make_user_data_block(0xc002, clientSecurityData)
        # clientNetworkData (TS_UD_CS_NET)
        + make_user_data_block(0xc003, clientNetworkData)
        # clientMonitorData (not present)
    )
    userdata = (b""
        + b"\x00\x08\x00\x10\x00\x01\xc0\x00"+b"\x44\x75\x63\x61"
        + per_encode_length(len(userdata)) + userdata
    )
    userdata = (b""
        # gccCCrq
        + b"\x00\x05\x00\x14\x7c\x00\x01"
        + per_encode_length(len(userdata)) + userdata
    )
    return userdata #+ "USER"*100


###################################################
# functions for parsing RDP response
###################################################
def recv_all(sk, n):
    data = b''
    while len(data) < n:
        tmpdata = sk.recv(n - len(data))
        if tmpdata == 0: # connection lost
            raise Exception('connection lost')
        data += tmpdata
    return data
    
# Note: no value checking
def recv_x224_data(sk):
    # TPKT Header (4 bytes), X.224 Data TPTU (3 bytes)
    hdr = sk.recv(7)
    l = unpack("!H", hdr[2:4])[0]
    if hdr[:2] != b'\x03\x00':
        print('invalid header: {}'.format(hdr.encode('hex')))
    return recv_all(sk, l-7)
    
def extract_x224_data(pkt):
    l = unpack("!H", pkt[2:4])[0]
    # TPKT Header (4 bytes), X.224 Data TPTU (3 bytes)
    return (pkt[7:l], pkt[l:])
    
###################################################

class RDP:
    def __init__(self, sk, verbose=True):
        # TODO: init all attributes here
        self.verbose = verbose
        self.selectedProtocol = 0
        self.pubkey = PublicKey()
        self.channels = {}
        self.io_channel_id = None
        self.user_id = None
        self.server_user_id = 0x3ea
        self.share_id = 0x000103ea
        self.client_random = "A"*32
        self.pktEncryptFlag = 0
        self.sk = sk  # might be changed to ssl socket
        self.channel_data_cb = None
        self.fastpath_cb = None
        self.on_disconnected_cb = None
        self.orig_so_rcvbuf = 0
        self.rdp4mppc = RDP4MPPC()
        self.rdpdr_channel_id = 0
        self.rdpdr_client_id = 0
        self.rdpdr_event = None
    
    def close(self):
        self.running = False
        self.sk.shutdown(socket.SHUT_RDWR)
        self.sk.close()
    
    def disconnect(self):
        self.send(self.create_pkt_disconnect_provider())
        self.close()
    
    def _print(self, msg):
        if self.verbose:
            print(msg)
        
    def create_pkt_connection_request(self, neg_ssl=False):
        data = pack("!HHB", 0, 0, 0) + b'Cookie: mstshash=administator\x0d\x0a'
        if neg_ssl:
            # TYPE_RDP_NEG_REQ = 1, flags=0, len=8, PROTOCOL_SSL=1
            data += pack("<BBHI", 1, 0, 8, 1)
        return make_tpkt( make_x224(0xe0, data) )
    
    def send(self, data):
        self.sk.send(data)
    
    def recv(self):
        return recv_x224_data(self.sk)
    
    def create_pkt_connect_initial(self, maxChannelIds, maxUserIds, channels):
        userdata = create_gcc_userdata_init(self.selectedProtocol, channels)
        mcs_data = (
            ber_encode_string(b"\x01") + # callingDomainSelector
            ber_encode_string(b"\x01") + # calledDomainSelector
            ber_encode_bool(True) + # upwardFlag
            encode_domain_params(maxChannelIds, maxUserIds, 0, 1, 0, 1, 0xffff, 2) + # target params
            encode_domain_params(1, 1, 1, 1, 0, 1, 0x420, 2) + # min params
            encode_domain_params(65535, 64535, 65535, 1, 0, 1, 0xffff, 2) + # max params
            ber_encode_string(userdata) # userData
        )
        mcs = ber_encode_tag(b"\x7f\x65", mcs_data)
        return make_tpkt_data(mcs)
    
    def create_pkt_erect_domain_req(self):
        return make_tpkt_data(b"\x04\x01\x00\x01\x00")
        
    def create_pkt_attach_user_req(self):
        return make_tpkt_data(b"\x28")
        
    def create_pkt_channel_join_req(self, userId, channelId):
        userId = fix_user_id(userId)
        return make_tpkt_data(b"\x38" + pack("!HH", userId, channelId))
        
    def create_pkt_disconnect_provider(self):
        return make_tpkt_data(b"\x21\x80") # DisconnectProviderUltimatum
    
    def parse_negotiation_response(self, data):
        if len(data) == 4:
            return
        if len(data) != 12:
            raise Exception('invalid negotiation response')
        ptype, flags, length, protocol = unpack('<BBHI', data[4:])
        if ptype != 2:
            if ptype == 3:
                raise Exception('RDP negotiation failure: {}'.format(protocol))
            raise Exception('not negotiation response')
        self._print('negotiation response flag: 0x{:x}'.format(flags))
        self.selectedProtocol = protocol
        
    def parse_connection_response(self, data, channelInfos):
        data = data[2:] # APP TYPE 102
        n, data = ber_decode_length(data) #
        result, data = ber_decode_enum(data) # result (should check?)
        if result != 0:
            print(result)
            print(data.hex())
        n, data = ber_decode_int(data) # callConnectId
        dom_param, data = ber_decode_seqof(data) # domain parameters
        data, junk = ber_decode_string(data)
        # now junk should be empty
        data = data[7:] # skip key::object (PER encoded)
        data = data[10:] # ??? (lazy to read, not important for now)
        data = data[4:] # skip H.211 key "McDn"
        n, l = per_decode_length(data)
        user_data = data[l:]
        
        # important data below
        # for SC_SECURITY - encryption_method, random_data, exponent, modulus
        # for SC_NET - channel id
        while len(user_data) > 0:
            ptype, blen = unpack("<HH", user_data[:4])
            
            data = user_data[4:blen]
            # ignore type SC_CORE (0x0c01)
            if ptype == 0x0c02: # SC_SECURITY
                encryption_method, encryption_level = unpack("<II", data[:8])
                self.encryption_method = encryption_method
                self.encryption_level = encryption_level
                if encryption_method != 0 and encryption_level != 0:
                    self.pktEncryptFlag = SEC_ENCRYPT
                    random_len, cert_len = unpack("<II", data[8:16])
                    data = data[16:]
                    self.server_random = data[:random_len] # random_len must be 32
                    data = data[random_len:]
                    cert_data = data[:cert_len]
                    data = data[cert_len:]
                    # parse certificate
                    version, sig_alg, key_alg, pubkey_blob_type, pubkey_blob_len = unpack("<IIIHH", cert_data[:16])
                    cert_data = cert_data[16:]
                    pubkey_blob = cert_data[:pubkey_blob_len-8] # remove padding
                    cert_data = cert_data[pubkey_blob_len:]
                    # lazy to write this part
                    # skip to exponent, modulus in pubkey_blob
                    self.pubkey.e = unpack("<I", pubkey_blob[16:20])[0]
                    self.pubkey.n = bytes2int(pubkey_blob[20:])
                    self.pubkey.size = pubkey_blob_len-28
                    # in cert_data now is signature blob, skip it (no check)
            elif ptype == 0x0c03: # SC_NET
                self.io_channel_id, i = unpack("<HH", data[:4])
                self.channel_ids = unpack("<"+"H"*i, data[4:4+i*2])
                for cid, cinfo in zip(self.channel_ids, channelInfos):
                    self.channels[cid] = cinfo[0]
                    if cinfo[0].lower() == 'rdpdr':
                        # found rdpdr channel
                        self.rdpdr_channel_id = cid
                        self.rdpdr_event = threading.Event()
                self.server_user_id = self.io_channel_id - 1
            
            user_data = user_data[blen:]
            
        return self
        
    def parse_attach_user_confirm(self, data):
        if data[:2] != b"\x2e\x00":
            return None # fail
        userId = unpack("!H", data[2:4])[0] +1001 # userId
        self.user_id = userId
        return userId
    
    # first step
    def do_connection_initiation(self, req_ssl=True):
        # send x224 connection request
        # req_ssl is None for auto. req_ssl is False for disable
        self.send(self.create_pkt_connection_request(req_ssl != False))
        # recv x224 connection confirm
        data = self.recv()
        self.parse_negotiation_response(data)
        if req_ssl and self.selectedProtocol == 0:
            raise Exception('Target has no TLS support')
        
        if self.selectedProtocol == 1: # ssl
            tls = ssl.wrap_socket(self.sk, do_handshake_on_connect=False)
            tls.do_handshake()
            self.sk = tls

    # second step
    def do_basic_settings_exchange(self, channels):
        # send MCS Connect Initial with GCC CCR
        pkt = self.create_pkt_connect_initial(40, 2, channels)
        self.send(pkt)
        # recv MCS Connect Response with GCC CCR
        data = self.recv()
        self.parse_connection_response(data, channels)
    
    # third step
    def do_channel_connection(self):
        # erect domain and attach user
        self.send(self.create_pkt_erect_domain_req())
        self.send(self.create_pkt_attach_user_req())
        self.parse_attach_user_confirm(self.recv())

        # join user channel
        self._print('join user channel id: {}'.format(self.user_id))
        self.send(self.create_pkt_channel_join_req(self.user_id, self.user_id))
        self.recv()
        # join i/o channel
        self._print('join i/o channel id: {}'.format(self.io_channel_id))
        self.send(self.create_pkt_channel_join_req(self.user_id, self.io_channel_id))
        self.recv()
        # join other channels
        for channel_id in self.channel_ids:
            #print('join channel id: {}'.format(channel_id))
            self.send(self.create_pkt_channel_join_req(self.user_id, channel_id))
            self.recv()
        
    def _salted_hash(self, S, I):
        return hashlib.md5(S + hashlib.sha1(I + S + self.client_random + self.server_random).digest()).digest()

    def _final_hash(self, K):
        return hashlib.md5(K + self.client_random + self.server_random).digest()
        
    def _init_session_key(self):
        # http://msdn.microsoft.com/en-us/library/cc240785%28v=prot.10%29.aspx
        pre_master_secret = self.client_random[:24] + self.server_random[:24]
        master_secret = (
            self._salted_hash(pre_master_secret, b"\x41") +
            self._salted_hash(pre_master_secret, b"\x42"*2) +
            self._salted_hash(pre_master_secret, b"\x43"*3)
        )
        
        MACKey128 = self._salted_hash(master_secret, b"\x58")
        InitialClientDecryptKey128 = self._final_hash(self._salted_hash(master_secret, b"\x59"*2))
        InitialClientEncryptKey128 = self._final_hash(self._salted_hash(master_secret, b"\x5a"*3))
        if self.encryption_method == ENCRYPTION_METHOD_40BIT:
            self.macKey = b"\xd1\x26\x9e" + MACKey128[3:8]
            self.decryptKey = b"\xd1\x26\x9e" + InitialClientDecryptKey128[3:8]
            self.encryptKey = b"\xd1\x26\x9e" + InitialClientEncryptKey128[3:8]
        elif self.encryption_method == ENCRYPTION_METHOD_56BIT:
            self.macKey = b"\xd1" + MACKey128[1:8]
            self.decryptKey = b"\xd1" + InitialClientDecryptKey128[1:8]
            self.encryptKey = b"\xd1" + InitialClientEncryptKey128[1:8]
        elif self.encryption_method == ENCRYPTION_METHOD_128BIT:
            self.macKey = MACKey128
            self.decryptKey = InitialClientDecryptKey128
            self.encryptKey = InitialClientEncryptKey128
            
        self.encrypt_cnt = 0
        self.encryptor = RC4(self.encryptKey)
        self.decryptor = RC4(self.decryptKey)

    def _salted_mac_signature(self, data):
        # http://msdn.microsoft.com/en-us/library/cc240789%28v=prot.10%29.aspx
        sha = hashlib.sha1(self.macKey + b"\x36"*40 + pack("<I", len(data)) + data + pack("<I", self.encrypt_cnt)).digest()
        return hashlib.md5(self.macKey + b"\x5c"*48 + sha).digest()[:8]
        
    def _mac_signature(self, data):
        # http://msdn.microsoft.com/en-us/library/cc240788%28v=prot.10%29.aspx
        sha = hashlib.sha1(self.macKey + b"\x36"*40 + pack("<I", len(data)) + data).digest()
        return hashlib.md5(self.macKey + b"\x5c"*48 + sha).digest()[:8]
        
    # flags - http://msdn.microsoft.com/en-us/library/cc240579%28v=prot.10%29.aspx
    def create_pkt_security_exchange(self):
        self.client_random = b"A"*32
        self._init_session_key()
        
        random_data = rsa_pubkey_encrypt(self.client_random, self.pubkey) + b"\x00"*8
        data = pack("<I", len(random_data)) + random_data
        pkt = self._create_send_data_req(SEC_LICENSE_ENCRYPT_SC|SEC_EXCHANGE_PKT, data)
        return make_tpkt_data(pkt)

    def create_pkt_client_info(self):
        #userId = fix_user_id(self.user_id)
        
        domain = b"\x00\x00"  #str2wchar('NTDEV')
        username = str2wchar('administrator')
        password = b"\x00\x00"
        altshell = b"\x00\x00"
        workdir = b"\x00\x00"
        
        client_addr = str2wchar('1.1.1.1')
        client_dir = str2wchar('C:\\WINNT\\System32\\mstscax.dll')
        
        # time zone info
        time_info = (
            pack("<I", 7) # bias
            + str2wchar('GMT', 32) # standard name
            + pack("<HHHHHHHH", 0, 0, 0, 0, 0, 0, 0, 0) # standard time (TS_SYSTEMTIME)
            + pack("<I", 0) # standard bias
            + str2wchar('GMT', 32) # daylight name
            + pack("<HHHHHHHH", 0, 0, 0, 0, 0, 0, 0, 0) # daylight time (TS_SYSTEMTIME)
            + pack("<I", 0) # daylight bias
        )
        
        info_pkt = (
            pack("<I", 0) # code page
            + pack("<I", 0x000001b3) # flags (INFO_MOUSE | INFO_DISABLECTRLALTDEL | INFO_UNICODE | INFO_COMPRESSION | PACKET_COMPR_TYPE_8K)
            + pack("<H", len(domain) - 2)
            + pack("<H", len(username) - 2)
            + pack("<H", len(password) - 2)
            + pack("<H", len(altshell) - 2)
            + pack("<H", len(workdir) - 2)
            + domain + username + password + altshell + workdir
            # extended info packet
            + pack("<H", 0x0002)
            + pack("<H", len(client_addr)) + client_addr
            + pack("<H", len(client_dir)) + client_dir
            + time_info
            + pack("<I", 0) # client session id
            + pack("<I", 0x00000027) # performance flags
            + pack("<H", 0) # auto reconnect len
        )

        pkt = self._create_send_data_req(SEC_INFO_PKT|self.pktEncryptFlag, info_pkt)
        return make_tpkt_data(pkt)
    
    def _create_channel_send_data_req(self, channel_id, user_data, flags, data_priority=1, segmentation=3, flagsHi=0):
        prior_seg = pack('B', (data_priority << 6) | (segmentation << 4))
        userId = fix_user_id(self.user_id)
        data = b''
        # if using SSL, securityHeader fields (from client) is not existed except client info packet (SEC_INFO_PKT)
        if self.encryption_method != ENCRYPTION_METHOD_NONE or (flags & SEC_INFO_PKT):
            data += pack("<HH", flags, flagsHi) # TS_SECURITY_HEADER
            
        if flags & SEC_ENCRYPT:
            if flags & SEC_SECURE_CHECKSUM:
                data += self._salted_mac_signature(user_data)
            else:
                data += self._mac_signature(user_data)
            data += self.encryptor.encrypt(user_data)
            self.encrypt_cnt += 1
        else:
            data += user_data
        pkt = b"\x64" + pack("!HH", userId, channel_id) + prior_seg + per_encode_length_data(data)
        return pkt
    
    # send data to I/O channel
    def _create_send_data_req(self, flags, user_data, data_priority=1, segmentation=3, flagsHi=0):
        return self._create_channel_send_data_req(self.io_channel_id, user_data, flags, data_priority, segmentation, flagsHi)
    
    def create_send_channel_data(self, channel_id, data, do_compress=False):
        flag = 3
        if do_compress:
            data = self.rdp4mppc.compress(data)
            flag |= 0x00200000 | 0x00400000  # CHANNEL_PACKET_COMPRESSED | CHANNEL_PACKET_AT_FRONT
        if len(data) > 1600:
            raise Exception('too large channel data')
        pdu = pack('<II', len(data), flag) + data
        pkt = self._create_channel_send_data_req(channel_id, pdu, self.pktEncryptFlag, data_priority=3)
        return make_tpkt_data(pkt)
    
    def send_channel_data(self, channel_id, data, do_compress=False):
        self.send(self.create_send_channel_data(channel_id, data, do_compress))
    
    def _decrypt_data(self, enc_data, sig):
        # ignore signature
        return self.decryptor.decrypt(enc_data)
        
    def parse_send_data_ind(self, data):
        data = data[1:]
        user_id, channel_id = unpack("!HH", data[:4])
        user_id += 1001
        # ignore dataPriority and segmentation
        data = data[5:]
        n, l = per_decode_length(data)
        data = data[l:l+n]
        flags = 0
        # if using SSL, securityHeader fields (from server) is not existed except license pdu (SEC_LICENSE_PKT)
        if self.encryption_method != ENCRYPTION_METHOD_NONE or (not self.got_license_pdu):
            flags, flagsHi = unpack("<HH", data[:4])
            if flags & SEC_ENCRYPT:
                data = self._decrypt_data(data[12:], data[4:12])
            else:
                data = data[4:]
        
        if flags & SEC_LICENSE_PKT:
            # license
            self._print("got license pkt")
            pass
        elif channel_id != self.io_channel_id:
            # virtual channels data
            dlen, dflags = unpack_from('<II', data)
            data = data[8:]
            self._print('got channel data: user_id: {}, channel id: {}, name: {}'.format(user_id, channel_id, self.channels[channel_id]))
            if channel_id == self.rdpdr_channel_id:
                component, pktId = unpack('<HH', data[:4])
                if pktId == PAKID_CORE_SERVER_ANNOUNCE:
                    major, minor, client_id = unpack('<HHI', data[4:])
                    self.rdpdr_client_id = client_id
                    self.rdpdr_event.set()
            if self.channel_data_cb:
                self.channel_data_cb(channel_id, data)
        else: # share
            # parse header
            total_len, pdu_type, pdu_src = unpack("<HHH", data[:6])
            pdu_type = pdu_type & 0xf
            if pdu_type == 0x01: # demand active pdu
                self._print("got demand active pdu")
                # extract server user id (TS_SHARECONTROLHEADER::pduSource) and share id
                self.server_user_id = pdu_src
                self.share_id = unpack("<I", data[6:10])[0]
                #print("  pdu_src: {}".format(pdu_src))
                #print("  share_id: {}".format(self.share_id))
                data = data[10:]
                lenSD, lenCC = unpack_from("<HH", data)
                sD = data[4:4+lenSD]
                data = data[4+lenSD:]
                numCaps = unpack('<H', data[:2])[0]
                capSets = data[4:lenCC]
                pos = 0
                '''
                type 0x1 (GENERAL): refreshRectSupport
                type 0x14 (VIRTUALCHANNEL): flag can check compression support. max chunk size (VCChunkSize. default is 0x640 (1600))
                '''
                #for i in range(numCaps):
                #	capType, capLen = unpack_from('<HH', capSets[pos:])
                #	print('  - Type: 0x{:x}, {}'.format(capType, capSets[pos+4:pos+capLen].encode('hex')))
                #	pos += capLen
            elif pdu_type == 0x07: # data pdu (can be compressed)
                #print("got data pdu, user_id: {}, channel id: {}, from pdu_src: {}".format(user_id, channel_id, pdu_src))
                #print('  ' + data[6:].hex())
                share_id, _, _, _, pdu_type2 = unpack_from('<IBBHB', data[6:])
                if pdu_type2 == 0x2f:
                    errCode = unpack('<I', data[18:18+4])[0]
                    print('  Error pdu: code: 0x{:x}'.format(errCode))
            elif pdu_type == 0x06: # PDUTYPE_DEACTIVATEALLPDU
                # do nothing. shutdown request pdu will come soon (then disconnect)
                #print('PDUTYPE_DEACTIVATEALLPDU')
                pass
            else:
                print("unknown PDU type {}, user_id: {}, channel id: {}".format(pdu_type, user_id, channel_id))
                print(data.encode('hex'))
        return data
        
    def parse_x224_data(self, data):
        b0, b1 = unpack_from('BB', data)
        if b0 == 0x7f:
            ptype = b1
        else:
            ptype = b0 >> 2
        
        if ptype == 26: # sendDataIndication
            self.parse_send_data_ind(data)
        elif ptype == 8: # disconnectProviderUltimatum
            reason = ((b0 & 3) << 1) | (b1 >> 7)
            if self.on_disconnected_cb:
                self.on_disconnected_cb(reason)
            else:
                print("got disconnectProviderUltimatum reason: {}".format(reason))
            return False
        elif ptype == 11: # attachUserConfirm
            self.parse_attach_user_confirm(data)
        elif ptype == 102: # Connect-Response
            print("got Connect-Response")
            self.parse_connection_response(data, None)
        else:
            print("unknown x224 type: {}".format(ptype))
            #print('  '+data.encode('hex'))
        return True
    
    def _create_share_control_header(self, pduType, data, pduSrc = None):
        if pduSrc == None:
            pduSrc = self.user_id
        control_hdr = pack("<HHH",
            6 + len(data), # totalLength
            pduType, # pduType
            pduSrc # PDUSource
        )
        return control_hdr + data
        
    def _create_share_data_pdu(self, streamId, pduType2, pdu_data, pduSrc = None):
        data_hdr = pack("<IBBHBBH",
            self.share_id, # shareId
            0, # pad1
            streamId, # streamId
            18 + len(pdu_data), # uncompressedLength (include share control header)
            pduType2, # pduType2
            0, # generalCompressedType
            0 # generalCompressedLength
        )
        # pduType: 0x17 (TS_PROTOCOL_VERSION | PDUTYPE_DATAPDU)
        return self._create_share_control_header(0x17, data_hdr + pdu_data, pduSrc)
    
    def create_pkt_confirm_active(self):
        sourceDescriptor = b"MSTSC\x00"
        caps = [
            # General Capability Set (24 bytes)
            b"\x01\x00\x18\x00\x01\x00\x03\x00\x00\x02\x00\x00\x00\x00\x1d\x04"
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            # Bitmap Capability Set (28 bytes)  (16 bit, 800x600)
            b"\x02\x00\x1c\x00\x10\x00\x01\x00\x01\x00\x01\x00\x20\x03\x58\x02"
            b"\x00\x00\x01\x00\x01\x00\x00\x00\x01\x00\x00\x00",
            # Order Capability Set (88 bytes)
            b"\x03\x00\x58\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\x00\x14\x00\x00\x00\x01\x00\x00\x00\x2a\x00"
            #b"\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x00\x01\x00\x00\x00\x01"  # cap
            #b"\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x00\x00\x00\x00\x00"
            b"\x01\x01\x01\x01\x00\x00\x00\x00\x01\x01\x00\x01\x00\x00\x00\x00"  # 01010101 00000000 01010101 00010100
            b"\x00\x00\x00\x00\x01\x01\x01\x00\x00\x01\x01\x01\x00\x00\x00\x00"  # 00000000 01010100 00010101 00000000
            b"\xa1\x06\x00\x00\x00\x00\x00\x00\x00\x84\x03\x00"
            b"\x00\x00\x00\x00\xe4\x04\x00\x00",
            # Bitmap Cache Rev. 2 Capability Set (40 bytes)
            b"\x13\x00\x28\x00"
            #b"\x03\x00\x00\x03\x78\x00\x00\x00\x78\x00\x00\x00"  # Note: can omit sending persistent key pdu from flag
            #b"\xfb\x09\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x03\x78\x00\x00\x00\x78\x00\x00\x00"
            b"\x50\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            # Color Table Cache Capability Set (8 bytes)
            b"\x0a\x00\x08\x00\x06\x00\x00\x00",
            # Window Activation Capability Set (12 bytes)
            b"\x07\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            # Control Capability Set (12 bytes)
            b"\x05\x00\x0c\x00\x00\x00\x00\x00\x02\x00\x02\x00",
            # Pointer Capability Set (10 bytes)
            b"\x08\x00\x0a\x00\x01\x00\x14\x00\x14\x00",
            # Share Capability Set (8 bytes)
            b"\x09\x00\x08\x00\x00\x00\x00\x00",
            # Input Capability Set (88 bytes)
            b"\x0d\x00\x58\x00\x01\x00\x00\x00"
            b"\x09\x04\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00"  # keyboard info (should be same as ClientCoreData)
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # imeFilename
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            # Sound Capability Set (8 bytes)
            b"\x0c\x00\x08\x00\x01\x00\x00\x00",
            # Font Capability Set (8 bytes)
            b"\x0e\x00\x08\x00\x01\x00\x00\x00",
            # Glyph Cache Capability Set (52 bytes)
            b"\x10\x00\x34\x00\xfe\x00\x04\x00\xfe\x00\x04\x00\xfe\x00\x08\x00"
            b"\xfe\x00\x08\x00\xfe\x00\x10\x00\xfe\x00\x20\x00\xfe\x00\x40\x00"
            b"\xfe\x00\x80\x00\xfe\x00\x00\x01\x40\x00\x00\x08\x00\x01\x00\x01"
            b"\x02\x00\x00\x00",
            # Brush Capability Set (8 bytes)
            b"\x0f\x00\x08\x00\x01\x00\x00\x00",
            # Offscreen Bitmap Cache Capability Set (12 bytes)
            #b"\x11\x00\x0c\x00\x01\x00\x00\x00\x00\x1e\x64\x00",
            # Virtual Channel Capability Set (8 bytes)
            b"\x14\x00\x08\x00\x01\x00\x00\x00",
            # DrawNineGridCache Capability Set (12 bytes)
            #b"\x15\x00\x0c\x00\x02\x00\x00\x00\x00\x0a\x00\x01",
            # DrawGdiPlus Capability Set (40 bytes)
            #b"\x16\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            #b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            #b"\x00\x00\x00\x00\x00\x00\x00\x00",
        ]
        combined_caps = pack("<HH", len(caps), 0) + b"".join(caps)
        pdu_data = pack("<IHHH",
            self.share_id, # shareID
            self.server_user_id, # originatorID
            len(sourceDescriptor), # lengthSourceDescriptor
            len(combined_caps), # lengthCombinedCapabilities
        ) + sourceDescriptor + combined_caps
        data = self._create_share_control_header(0x13, pdu_data)
        pkt = self._create_send_data_req(self.pktEncryptFlag, data)
        return make_tpkt_data(pkt)
        
    def create_pkt_synchronize(self):
        pdu_data = pack("<HH",
            1, # messageType
            self.server_user_id, # targetUser
        )
        data = self._create_share_data_pdu(0x01, 31, pdu_data, self.user_id)
        pkt = self._create_send_data_req(self.pktEncryptFlag, data)
        return make_tpkt_data(pkt)
        
    def create_pkt_control(self, action):
        pdu_data = pack("<HHI",
            action, # action
            0, # grantId
            0, # controlId
        )
        data = self._create_share_data_pdu(0x01, 20, pdu_data)
        pkt = self._create_send_data_req(self.pktEncryptFlag, data)
        return make_tpkt_data(pkt)
        
    def create_pkt_persistent_key_list(self):
        # TODO: should have entries
        pdu_data = pack("<HHHHH",
            0, # numEntries[0]
            0, # numEntries[1]
            0, # numEntries[2]
            0, # numEntries[3]
            0, # numEntries[4]
        )
        pdu_data += pack("<HHHHH",
            0, # totalEntries[0]
            0, # totalEntries[1]
            0, # totalEntries[2]
            0, # totalEntries[3]
            0, # totalEntries[4]
        )
        pdu_data += pack("<BBH",
            3, # bBitMask
            0, # Pad2
            0, # Pad3
        )
        data = self._create_share_data_pdu(0x01, 43, pdu_data)
        pkt = self._create_send_data_req(self.pktEncryptFlag, data)
        return make_tpkt_data(pkt)
        
    def create_pkt_input_sync(self):
        pdu_data = pack("<IH",
            1, # eventTime (ignored by server)
            0, # messageType
        )
        pdu_data += pack("<HI", # synchronize event
            0, # pad
            0, # toggleFlags
        ) + b'\x00'*4
        data = self._create_share_data_pdu(0x01, 0x1c, pdu_data)
        pkt = self._create_send_data_req(self.pktEncryptFlag, data)
        return make_tpkt_data(pkt)
        
    def create_pkt_font_list(self):
        pdu_data = pack("<HHHH",
            0, # numEntries
            0, # totalNumEntries
            3, # listFlags
            0x32, # entrySize
        )
        data = self._create_share_data_pdu(0x01, 39, pdu_data)
        pkt = self._create_send_data_req(self.pktEncryptFlag, data)
        return make_tpkt_data(pkt)
    
    # 4th step
    def do_security_exchange(self):
        if self.encryption_method != ENCRYPTION_METHOD_NONE:
            #print "sending security exchange ..."
            self.send(self.create_pkt_security_exchange())
        #print "sending client info ..."
        self.send(self.create_pkt_client_info())
        # recv license
        self.got_license_pdu = False
        self.parse_x224_data(self.recv()) # have to parse (at least for decryption)
        self.got_license_pdu = True
    
    # 5th step
    def do_capability_exchange(self):
        # demand active
        data = self.recv()
        self.parse_x224_data(data)
        self.send(self.create_pkt_confirm_active())

    # last step for establishing connection
    def do_connection_finalization(self, send_fontList=True):
        #print("sending synchronize ...")
        self.send(self.create_pkt_synchronize())
        #print("sending control cooperate ...")
        self.send(self.create_pkt_control(4))
        #print("sending control request ...")
        self.send(self.create_pkt_control(1))
        #print("sending persistent key list ...")
        self.send(self.create_pkt_persistent_key_list())
        if send_fontList:
            #print("sending font list ...")
            self.send(self.create_pkt_font_list())

        # synchronize
        self.parse_x224_data(self.recv())
        # control coperate
        self.parse_x224_data(self.recv())
        # control granted
        self.parse_x224_data(self.recv())
        if send_fontList:
            # font map
            self.parse_x224_data(self.recv())
    
    # wrapper for do full RDP handshake
    def do_rdp_handshake(self, channels, req_ssl=True, do_all_finalization=True):
        self._print("sending X.224 connection request ...")
        self.do_connection_initiation(req_ssl)

        self._print("sending MCS connect initial ...")
        self.do_basic_settings_exchange(channels)

        self._print("do channel connection (erect domain/attach user/channel join) ...")
        self.do_channel_connection()

        self._print("do security exchange ...")
        self.do_security_exchange()

        self._print("do capability exchange ...")
        self.do_capability_exchange()

        self._print("do connection finialztion ...")
        self.do_connection_finalization(do_all_finalization)
    
    def _create_pkt_mouse_input(self, pointerFlags, xPos, yPos):
        # do left click at (x, y)
        pdu_data = pack("<HH", 1, 0) # numEvents, pad2Octets
        pdu_data += pack("<IH",
            0, # eventTime (ignored by server)
            0x8001, # messageType (INPUT_EVENT_MOUSE)
        )
        pdu_data += pack("<HHH",
            pointerFlags,
            xPos, yPos
        )
        data = self._create_share_data_pdu(0x01, 0x1c, pdu_data)
        pkt = self._create_send_data_req(self.pktEncryptFlag, data)
        return make_tpkt_data(pkt)
    
    def _send_pkt_mouse_input(self, pointerFlags, xPos, yPos):
        self.send(self._create_pkt_mouse_input(pointerFlags, xPos, yPos))
        
    def create_pkt_mouse_click(self, xPos, yPos):
        # do left click at (x, y)
        # pointerFlags: PTRFLAGS_DOWN (0x8000) | PTRFLAGS_BUTTON1 (0x1000)
        # also need without PTRFLAGS_DOWN to release mouse down
        return self._create_pkt_mouse_input(0x9000, xPos, yPos) + self._create_pkt_mouse_input(0x1000, xPos, yPos)
        
    def send_pkt_mouse_click(self, xPos, yPos):
        self.send(self.create_pkt_mouse_click(xPos, yPos))
    
    def send_pkt_mouse_move(self, xPos, yPos):
        # do mouse move to (x, y)
        # PTRFLAGS_MOVE (0x0800)
        self._send_pkt_mouse_input(0x0800, xPos, yPos)
    
    # areas to refresh is array 8 bytes (TS_RECTANGLE16). max array is 255
    def create_refresh_rect_pkt(self, areasToRefresh):
        pdu_data = pack("<BBH",
            len(areasToRefresh), # numberOfAreas
            0, 0, # pad3Octets
        ) + b''.join(areasToRefresh) # areasToRefresh
        data = self._create_share_data_pdu(0x01, 33, pdu_data) # PDUTYPE2_REFRESH_RECT
        # Note: no compression
        pkt = self._create_send_data_req(self.pktEncryptFlag, data)
        return make_tpkt_data(pkt)
    
    def send_refresh_rect(self, areasToRefresh):
        self.send(self.create_refresh_rect_pkt(areasToRefresh))
        
    def create_shutdown_request_pkt(self):
        data = self._create_share_data_pdu(0x01, 36, b"")
        pkt = self._create_send_data_req(self.pktEncryptFlag, data)
        return make_tpkt_data(pkt)

    def send_shutdown_request(self):
        self.send(self.create_shutdown_request_pkt())
    
    def create_pkt_client_random(self):
        crandom = b'A'*256 # max is 0x200
        pdu_data = pack("<HI",
            0, # pad
            len(crandom),
        ) + crandom
        pdu_data = pack("<HI",
            0, # pad
            513,
        )
        data = self._create_share_control_header(0x19, pdu_data)
        pkt = self._create_send_data_req(self.pktEncryptFlag, data)
        return make_tpkt_data(pkt)
    
    def _recv_packet(self):
        hdr = self.sk.recv(4)
        if len(hdr) != 4:
            return False
        
        if hdr[0:1] == b'\x03':
            # TPKT Header (4 bytes), X.224 Data TPTU (3 bytes)
            l = unpack("!H", hdr[2:4])[0]
            self.sk.recv(3)
            data = recv_all(self.sk, l-7)
            return self.parse_x224_data(data)
        
        # fast path
        fpHdr, l1, l2 = unpack_from('!BBB', hdr)
        fpFlags = fpHdr >> 6
        if l1 & 0x80:
            l = ((l1 ^ 0x80) << 8) | l2
            data = hdr[3:]
        else:
            l = l1
            data = hdr[2:]
        data += recv_all(self.sk, l - 4)
        if self.encryption_method == ENCRYPTION_METHOD_FIPS:
            fipsInfo, data = data[:4], data[4:]
        if fpFlags & 0x2: # FASTPATH_OUTPUT_ENCRYPTED
            data = self._decrypt_data(data[8:], data[:8])
        
        updateHdr = unpack_from('<B', data)[0]
        updateCode = updateHdr & 0xf
        fragment = (updateHdr >> 4) & 0x3
        isCompress = (updateHdr >> 6) == 2
        # assume no compression
        if self.fastpath_cb is not None:
            self.fastpath_cb(data, updateCode, fragment, isCompress)
        else:
            self._print('fast path len: {}, data len: {}, code: {}, fragment: {}, compress: {}'.format(l, len(data), updateCode, fragment, isCompress))
        return True
        
    def _recv_loop(self):
        while self.running:
            ok = self._recv_packet()
            if not ok:
                break
    
    def start_recv_loop(self, channel_data_cb=None, fastpath_cb=None, on_disconnected_cb=None):
        if self.orig_so_rcvbuf != 0:
            self.sk.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.orig_so_rcvbuf)
            self.orig_so_rcvbuf = 0
        self.running = True
        self.channel_data_cb = channel_data_cb
        self.fastpath_cb = fastpath_cb
        self.on_disconnected_cb = on_disconnected_cb
        self.recv_thr = threading.Thread(target=self._recv_loop)
        self.recv_thr.start()
        
    def join_recv_thread(self):
        self.recv_thr.join()
        self.recv_thr = None

    def stop_recv_and_minimize_buffer(self):
        self.running = False
        if self.orig_so_rcvbuf == 0:
            self.orig_so_rcvbuf = self.sk.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) // 2
        self.sk.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128)

    ###############
    # rdpdr related methods
    def wait_for_rdpdr_client_id(self, timeout=5):
        self.rdpdr_event.wait(timeout=timeout)

    def create_rdpdr_announce_reply_packet(self, do_compress=False):
        channel_data = pack('<HH', RDPDR_CTYP_CORE, PAKID_CORE_CLIENTID_CONFIRM) + pack('<HHI', 1, 12, self.rdpdr_client_id)
        return self.create_send_channel_data(self.rdpdr_channel_id, channel_data, do_compress)


default_channels = [ ('cliprdr', 0xc0a00000), ('rdpsnd', 0xc0800000), ('snddbg', 0xc0000000), ('rdpdr', 0x80800000) ]

default_t120_channels = [ ('cliprdr', 0xc0a00000), ('rdpsnd', 0xc0800000), ('snddbg', 0xc0000000), ('rdpdr', 0x80800000), ('MS_T120', 0x80800000) ]

default_t120s_channels = [ ('cliprdr', 0xc0a00000), ('rdpsnd', 0xc0800000), ('snddbg', 0xc0000000), ('rdpdr', 0x80800000), ('MS_T120', 0x80800000) ]
for i in range(25):
    default_t120s_channels.append(('dummy'+str(i), 0))
default_t120s_channels.append(('MS_T120', 0x80800000))

def create_rdp(host, channels=default_channels, req_ssl=True, do_all_finalization=True, verbose=True):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    sk.connect((host,3389))

    rdp = RDP(sk, verbose)
    rdp.do_rdp_handshake(channels, req_ssl=req_ssl, do_all_finalization=do_all_finalization)
    return rdp
