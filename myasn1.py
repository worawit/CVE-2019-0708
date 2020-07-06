#!/usr/bin/env python

"""
My quick and dirty asn.1 functions for RDP
"""
from struct import pack, unpack
    
def per_encode_length(n):
    if n <= 0x7f:
        return pack('B', n)
    if n <= 0x3fff:
        return pack("!H", n|0x8000)
    # use per_encode_length_data, first byte must be "11xx xxxx"
    return False

def per_encode_length_data(data):
    n = len(data)
    if n <= 0x7f:
        return pack('B', n) + data
    if n <= 0x3fff:
        return pack("!H", n|0x8000) + data
    if n > 65535:
        return False
    n1 = n & 0xffc000
    n2 = n & 0x3fff
    return pack('B', 0xc0|(n1>>14))+data[:n1] + per_encode_length(n2)+data[n1:]

def per_decode_length(data):
    n = unpack('B', data[0:1])[0]
    if n <= 0x7f:
        return (n, 1)
    if n & 0x40:
        # i don't know
        # first byte must be "11xx xxxx"
        return ("per_decode_length error", 1)
    return ( ((n^0x80)<<8)|unpack('B', data[1:2])[0], 2 )
    
##############################################
# BER Encoders
##############################################
def ber_pack_int(n):
    if n == 0:
        return b"\x00"
    l = b""
    while n != 0:
        l = pack('B', n & 0xff) + l
        n >>= 8
    return l
    
def ber_encode_length(n):
    if n <= 0x7f:
        return pack('B', n)
    l = ber_pack_int(n)
    return pack('B', 0x80|len(l))+l
    
def ber_encode_tag(tag, data):
    return tag + ber_encode_length(len(data)) + data
    
def ber_encode_int(n):
    return ber_encode_tag(b"\x02", ber_pack_int(n))

def ber_encode_bool(b):
    return ber_encode_tag(b"\x01", b"\xff" if b else b"\x00")
    
# OctetString
def ber_encode_string(s):
    return ber_encode_tag(b"\x04", s)

def ber_encode_seqof(data):
    return ber_encode_tag(b"\x30", data)

##############################################
# BER Decoders
# Note: skip type checking
##############################################
def ber_unpack_int(data):
    n = 0
    for b in unpack('B'*len(data), data):
        n = (n << 8) | b
    return n

def _ber_decode_length(data):
    n = unpack('B', data[0:1])[0]
    if n & 0x80 == 0:
        return (n, 1)
    n = (n^0x80) + 1
    return (ber_unpack_int(data[1:n]), n)
    
def ber_decode_length(data):
    n, l = _ber_decode_length(data)
    return (n, data[l:])
    
def ber_decode_generic(data, tag):
    p = len(tag)
    n, l = _ber_decode_length(data[p:])
    n += p + l
    return (data[p+l:n], data[n:])

def ber_decode_int(data):
    out, data = ber_decode_generic(data, b"\x02")
    return (ber_unpack_int(out), data)
    
def ber_decode_enum(data):
    out, data = ber_decode_generic(data, b"\x0a")
    return (ber_unpack_int(out), data)

def ber_decode_bool(data):
    out, data = ber_decode_generic(data, b"\x01")
    return (out == b"\xff", data)
    
# OctetString
def ber_decode_string(data):
    return ber_decode_generic(data, b"\x04")
    
def ber_decode_seqof(data):
    return ber_decode_generic(data, b"\x30")
