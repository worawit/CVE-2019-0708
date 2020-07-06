#!/usr/bin/python

# MPPC-Based Bulk Data Compression for RDP 4.0
# History size: 8192 bytes
# output is None if the output size is larger than input
# modified from https://github.com/parc-ccnx-archive/CCNxz/blob/master/mppc.py

import array

class RDP4MPPC(object):
    HISTORY_SIZE = 8192
    
    # Used as bit patterns in Offset Encoding (RFC2118 Sec 4.2.1)
    __offset_pattern_64 = 0b1111
    __offset_pattern_320 = 0b1110
    __offset_pattern_8191 = 0b110

    __length_pattern_3    = 0b0
    __length_pattern_8    = 0b10
    __length_pattern_16   = 0b110
    __length_pattern_32   = 0b1110
    __length_pattern_64   = 0b11110
    __length_pattern_128  = 0b111110
    __length_pattern_256  = 0b1111110
    __length_pattern_512  = 0b11111110
    __length_pattern_1024 = 0b111111110
    __length_pattern_2048 = 0b1111111110
    __length_pattern_4096 = 0b11111111110
    __length_pattern_8192 = 0b111111111110

    def __init__(self):
        self.__in = None
        self.__inOffset = 0
        self.__out = None
        self.__outByte = 0
        self.__outBit = 0  # 0-7
        self.__history = bytearray(RDP4MPPC.HISTORY_SIZE)
        self.__historyOffset = 0
    
    def __setInData(self, data):
        self.__in = bytearray(data)
        self.__inOffset = 0
        # output size cannot be larger than input. input size is limited by HISTORY_SIZE
        self.__out = bytearray(RDP4MPPC.HISTORY_SIZE)
        self.__outByte = 0
        self.__outBit = 0
        self.__historyOffset = 0

    def __findLongestHistory(self):
        longestLen = 0
        longestOffset = 0
        searchPos = 0
        history = self.__history
        historyOffset = self.__historyOffset
        data = self.__in[self.__inOffset:]
        
        firstVal = data[0:1] # to make compatible on python 2 and 3
        searchPos = history.find(firstVal, 0, historyOffset)
        while searchPos != -1:
            # fill history array while matching
            history[historyOffset] = data[0]
            matchLen = 1
            while matchLen < len(data) and data[matchLen] == history[searchPos+matchLen]:
                history[historyOffset+matchLen] = data[matchLen]
                matchLen += 1
            if matchLen >= longestLen:
                longestLen = matchLen
                longestOffset = searchPos
            searchPos = history.find(firstVal, searchPos+1, historyOffset)

        if longestLen > 2:
            #print("Found longest match (off = {}, len = {})".format(longestOffset, longestLen))
            return (longestOffset, longestLen)
        else:
            return (None, None)

    def __pushByteToHistory(self, byte):
        self.__history[self.__historyOffset] = byte
        self.__historyOffset += 1

    def __encode7bitLiteral(self, byte):
        byte_offset = self.__outByte
        bit_offset = self.__outBit

        if bit_offset == 0:
            self.__out[byte_offset] = byte
        else:
            self.__out[byte_offset] |= byte >> bit_offset
            self.__out[byte_offset+1] = (byte << (8 - bit_offset)) & 0xff
        self.__outByte += 1

    def __encodeLiteral(self):
        byte = self.__in[self.__inOffset]
        self.__inOffset += 1

        if byte < 0x80:
            self.__encode7bitLiteral(byte)
        else:
            # write a "1" bit, then write the byte as a 7-bit literal
            self.__out[self.__outByte] |= 1 << (7 - self.__outBit)
            if self.__outBit == 7:
                self.__outByte += 1
                self.__outBit = 0
            else:
                self.__outBit += 1

            self.__encode7bitLiteral(byte & 0x7F)

        self.__pushByteToHistory(byte)

    def __encodebits(self, bits, bit_length):
        bit_offset = self.__outBit

        available_bits = 8 - bit_offset
        if bit_length <= available_bits:
            # we can fit the whole thing, shift the bits
            # up so we pack the top of the byte first
            shift = available_bits - bit_length
            x = bits << shift

            self.__out[self.__outByte] |= x
            self.__outBit += bit_length
            if self.__outBit == 8:
                self.__outByte += 1
                self.__outBit = 0
        else:
            # grab 'available_bits' from the top
            shift = bit_length - available_bits
            self.__encodebits(bits >> shift, available_bits)

            bit_length -= available_bits
            mask = (1 << bit_length) - 1
            bits &= mask
            self.__encodebits(bits, bit_length)


    def __encodeTupleOffset(self, offset):
        if offset < 64:
            # Encoded as '1111' plus lower 6 bits
            self.__encodebits(RDP4MPPC.__offset_pattern_64, 4)
            self.__encodebits(offset, 6)

        elif offset < 320:
            # Encoded as '1110' plus lower 8 bits of (value - 64)
            self.__encodebits(RDP4MPPC.__offset_pattern_320, 4)
            self.__encodebits(offset - 64, 8)

        else:
            # Encoded as '110' followed by lower 13 bits of (value - 320)
            self.__encodebits(RDP4MPPC.__offset_pattern_8191, 3)
            self.__encodebits(offset - 320, 13)

    def __encodeTupleLength(self, length):
        if length == 3:
            self.__encodebits(RDP4MPPC.__length_pattern_3, 1)
        elif length < 8:
            self.__encodebits(RDP4MPPC.__length_pattern_8, 2)
            self.__encodebits(length & 0x0003, 2)
        elif length < 16:
            self.__encodebits(RDP4MPPC.__length_pattern_16, 3)
            self.__encodebits(length & 0x0007, 3)
        elif length < 32:
            self.__encodebits(RDP4MPPC.__length_pattern_32, 4)
            self.__encodebits(length & 0x000F, 4)
        elif length < 64:
            self.__encodebits(RDP4MPPC.__length_pattern_64, 5)
            self.__encodebits(length & 0x001F, 5)
        elif length < 128:
            self.__encodebits(RDP4MPPC.__length_pattern_128, 6)
            self.__encodebits(length & 0x003F, 6)
        elif length < 256:
            self.__encodebits(RDP4MPPC.__length_pattern_256, 7)
            self.__encodebits(length & 0x007F, 7)
        elif length < 512:
            self.__encodebits(RDP4MPPC.__length_pattern_512, 8)
            self.__encodebits(length & 0x00FF, 8)
        elif length < 1024:
            self.__encodebits(RDP4MPPC.__length_pattern_1024, 9)
            self.__encodebits(length & 0x01FF, 9)
        elif length < 2048:
            self.__encodebits(RDP4MPPC.__length_pattern_2048, 10)
            self.__encodebits(length & 0x03FF, 10)
        elif length < 4096:
            self.__encodebits(RDP4MPPC.__length_pattern_4096, 11)
            self.__encodebits(length & 0x07FF, 11)
        else:
            self.__encodebits(RDP4MPPC.__length_pattern_8192, 12)
            self.__encodebits(length & 0x0FFF, 12)

    def __encodeCopyTuple(self, offset, length):
        self.__encodeTupleOffset(self.__historyOffset - offset)
        self.__encodeTupleLength(length)

        endOffset = self.__inOffset + length
        while self.__inOffset < endOffset:
            byte = self.__in[self.__inOffset]
            self.__pushByteToHistory(byte)
            self.__inOffset += 1

    def __getOutput(self):
        outSize = self.__outByte
        if self.__outBit != 0:
            # +1 because we need the length including the last byte
            outSize += 1

        #print("outSize = {}".format(outSize))
        if outSize >= len(self.__in):
            return None
        return bytes(self.__out[:outSize])

    @property
    def history(self):
        return self.__history

    def compress(self, data):
        if len(data) > RDP4MPPC.HISTORY_SIZE:
            return None
        self.__setInData(data)
        while self.__inOffset < len(data):
            (longestOffset, longestLen) = self.__findLongestHistory()
            if longestOffset is None:
                self.__encodeLiteral()
            else:
                self.__encodeCopyTuple(longestOffset, longestLen)

        return self.__getOutput()
