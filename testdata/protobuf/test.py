import math
import struct
# from gen import sample_pb2
from generated.generated import fields_pb2

class Reader:
    def __init__(self, data):
        self.offset = 0
        self.data = data

    def read_field(self):
        if self.offset >= len(self.data):
            return None
        start = self.offset
        cur = self.read_varint()

        field_number = cur >> 3
        wire_type = cur & 0x7

        print("offset 0x%d, field_number %d, wire_type %d" % (
            start, field_number, wire_type))

        if wire_type == 0:
            return self.read_varint()
        elif wire_type == 1:
            return self.read_64bit()
        elif wire_type == 2:
            return self.read_length_delimited()
        elif wire_type == 5:
            return self.read_32bit()
        else:
            raise Exception("Offset %d: Unknown wire_type %d" % (start, wire_type))

    def read_varint(self):
        start = self.offset
        old_value = self.read_varint_old()
        self.offset = start
        new_value = self.read_varint_new()
        assert old_value == new_value
        return new_value

    def read_varint_old(self):
        value = 0
        bits = 0
        while True:
            if self.offset >= len(self.data):
                raise Exception("EOF while reading varint")
            cur = self.data[self.offset]

            value = ((cur & 0x7f) << bits) | value
            bits += 7
            self.offset += 1

            if cur & 0x80 == 0:
                # print("end byte %02x %s" % (cur, format(cur, "08b")))
                return value
            # else:
            #     print("con byte %02x %s" % (cur, format(cur, "08b")))

    def read_varint_new(self):
        value = 0
        bits = 0

        start = self.offset
        num_bytes = 0

        while True:
            if self.offset >= len(self.data):
                raise Exception("EOF while reading varint")
            cur = self.data[self.offset]
            num_bytes += 1
            self.offset += 1
            if cur & 0x80 == 0:
                break

        i = start + num_bytes - 1
        while i >= start:
            cur = self.data[i]
            value = (value << 7) | (cur & 0x7f)
            i -= 1

        return value

    def read_length_delimited(self):
        nbytes = self.read_varint()
        if self.offset + nbytes > len(self.data):
            raise Exception("EOF while reading length-delimited")
        value = self.data[self.offset:self.offset + nbytes]
        self.offset += nbytes
        return value

    def read_32bit(self):
        if self.offset + 4 > len(self.data):
            raise Exception("EOF while reading 32-bit value")
        value = struct.unpack_from("I", self.data, self.offset)
        self.offset += 4
        return value

    def read_64bit(self):
        if self.offset + 8 > len(self.data):
            raise Exception("EOF while reading 64-bit value")
        value = struct.unpack_from("Q", self.data, self.offset)
        self.offset += 8
        return value


def parse_data(binary_data):
    reader = Reader(binary_data)
    while reader.offset < len(reader.data):
        value = reader.read_field()
        if value is None:
            break
        if isinstance(value, int):
            print("read %x" % (value))
        elif isinstance(value, bytes):
            print("read", end="")
            for i in range(0, len(value)):
                print(" %02x" % (value[i]), end="")
            print()
        else:
            print("read %s" % (value))
    # offset = 0
    # while offset < len(binary_data):
    #     cur = binary_data[offset]
    #     field_number = cur >> 3
    #     wire_type = cur & 0x7
    #     print("field_number %d, wire_type %d" % (field_number, wire_type))
    #     break
    #     # print("byte %02x" % (binary_data[offset]))
    #     offset += 1
    # # print(binary_data[300])


def main():
    msg = fields_pb2.FieldTypes()
    msg.test_string_nonempty = "jdoe@example.com"
    msg.test_bytes_nonempty = bytes([1, 2, 3, 4, 5])
    msg.test_bool_true = True

    binary_data = msg.SerializeToString()
    parse_data(binary_data)

if __name__ == "__main__":
    main()
