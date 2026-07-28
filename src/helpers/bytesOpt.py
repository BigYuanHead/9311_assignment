import struct


class byteReader_C:

    def __init__(self, data: bytes):
        """ pointer is managed by parser """
        self.data = data

    def read_u8(self, pos):
        value = self.data[pos]
        next_pos = pos + 1
        return value, next_pos

    def read_u16(self, pos):
        value = struct.unpack('!H', self.data[pos:pos+2])[0]
        next_pos = pos + 2
        return value, next_pos

    def read_u32(self, pos):
        value = struct.unpack('!I', self.data[pos:pos+4])[0]
        next_pos = pos + 4
        return value, next_pos

    def read_bytes(self, pos, length):
        value = self.data[pos:pos+length]
        next_pos = pos + length
        return value, next_pos



class byteBuilder_C:
    """
        build a byte series
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