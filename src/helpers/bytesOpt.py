import sys
import struct
import os
from dataclasses import dataclass


class byteReader_C:

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_u8(self):
        value = self.data[self.pos]
        self.pos = self.pos + 1
        return value

    def read_u16(self):
        value = struct.unpack('!H', self.data[self.pos:self.pos+2])[0]
        self.pos = self.pos + 2
        return value

    def read_u32(self):
        value = struct.unpack('!I', self.data[self.pos:self.pos+4])[0]
        self.pos = self.pos + 4
        return value

    def read_bytes(self, length):
        value = self.data[self.pos:self.pos+length]
        self.pos = self.pos + length
        return value



class byteBuilder_C:
    """
        e.g.
        
        builder.add_u16(query_id)
        builder.add_u16(flags)
        builder.add_u16(qdcount)
        builder.add_u16(ancount)
        builder.add_u16(nscount)
        builder.add_u16(arcount)
    """

    def __init__(self):
        self.data = bytearray()

    def add_u8(self, value):
        self.data.extend(struct.pack('!B', value))

    def add_u16(self, value):
        self.data.extend(struct.pack('!H', value))

    def add_u32(self, value):
        self.data.extend(struct.pack('!I', value))

    def add_bytes(self, value):
        self.data.extend(value)

    def get_bytes(self):
        return bytes(self.data)