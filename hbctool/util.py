# Copyright 2026 github.com/Kirlif

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from struct import pack, unpack

# File Object


class BitWriter(object):
    def __init__(self, f):
        self.out = f
        self.accumulator = 0
        self.bcount = 0
        self.write = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.flush()

    def __del__(self):
        try:
            self.flush()
        except ValueError:  # I/O operation on closed file.
            pass

    def _writebyte(self, b):
        assert not self.bcount, "bcount is not zero."
        self.out.write(bytes([b]))
        self.write += 1

    def flush(self):
        self.align()
        try:
            self.out.flush()
        except Exception:
            pass

    def pad(self, alignment):
        assert (
            alignment > 0 and alignment <= 8 and ((alignment & (alignment - 1)) == 0)
        ), "Support alignment as many as 8 bytes."
        l = self.tell()
        if l % alignment == 0:
            return
        b = alignment - (l % alignment)
        self.writeall([0] * (b))

    def seek(self, i):
        self.out.seek(i)
        self.write = i

    def tell(self):
        return self.write

    def writebytes(self, v, n):
        while n > 0:
            self._writebyte(v & 0xFF)
            v = v >> 8
            n -= 1
        return v

    def write_bits(self, bits, n):
        assert n >= 0, "n must be >= 0"
        if n:
            bits &= (1 << n) - 1
        while n:
            space = 8 - self.bcount
            take = min(space, n)
            chunk = bits & ((1 << take) - 1)
            self.accumulator |= chunk << self.bcount
            self.bcount += take
            bits >>= take
            n -= take
            if self.bcount == 8:
                self.out.write(bytes((self.accumulator,)))
                self.accumulator = 0
                self.bcount = 0
                self.write += 1

    def write_bit(self, b):
        self.write_bits(1 if b else 0, 1)

    def writeall(self, bs):
        self.out.write(bytes(bs))
        self.write += len(bs)

    def align(self):
        if self.bcount == 0:
            return 0
        pad = 8 - self.bcount
        self.out.write(bytes((self.accumulator,)))
        self.accumulator = 0
        self.bcount = 0
        return pad

    def close(self):
        self.flush()
        try:
            self.out.close()
        except Exception:
            pass


class BitReader:
    def __init__(self, f):
        self.input = f
        self.accumulator = 0
        self.bcount = 0
        self.read = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def _readbit(self):
        b = self.input.read(1)
        self.read += 1
        if not b:
            return False
        self.accumulator = b[0]
        self.bcount = 8
        return True

    def _readbyte(self):
        assert not self.bcount, "bcount is not zero."
        a = self.input.read(1)
        self.read += 1
        return ord(a)

    def readbits(self, n):
        assert n >= 0, "n must be >= 0"
        result = 0
        shift = 0
        while n:
            assert self.bcount != 0 or self._readbit(), "not enough bits"
            take = min(self.bcount, n)
            mask = (1 << take) - 1
            chunk = self.accumulator & mask
            result |= chunk << shift
            self.accumulator >>= take
            self.bcount -= take
            shift += take
            n -= take
        return result

    def readbytes(self, n=1):
        v = 0
        while n > 0:
            v = (v << 8) | self._readbyte()
            n -= 1
        return v

    def seek(self, i):
        self.input.seek(i)
        self.read = i

    def tell(self):
        return self.read

    def pad(self, alignment):
        assert (
            alignment > 0 and alignment <= 8 and ((alignment & (alignment - 1)) == 0)
        ), "Support alignment as many as 8 bytes."
        l = self.tell()
        if l % alignment == 0:
            return
        b = alignment - (l % alignment)
        self.seek(l + b)

    def readall(self):
        a = self.input.read()
        self.read += len(a)
        return list(a)


# File utilization function
# Read


def readuint(f, bits=64, signed=False):
    assert bits % 8 == 0, "Not support"
    if bits == 8:
        return f.readbytes(1)

    x = 0
    s = 0
    for _ in range(bits // 8):
        b = f.readbytes(1)
        x |= (b & 0xFF) << s
        s += 8

    if signed and (x & (1 << (bits - 1))):
        x = -((1 << (bits)) - x)

    if x.bit_length() > bits:
        print(f"--> Int {x} longer than {bits} bits")
    return x


def readint(f, bits=64):
    return readuint(f, bits, signed=True)


def readbits(f, bits=8):
    return f.readbits(bits)


def read(f, format):
    type = format[0]
    bits = format[1]
    n = format[2]
    r = []
    for i in range(n):
        if type == "uint":
            r.append(readuint(f, bits=bits))
        elif type == "int":
            r.append(readint(f, bits=bits))
        elif type == "bit":
            r.append(readbits(f, bits=bits))
        else:
            raise Exception(f"Data type {type} is not supported.")

    if len(r) == 1:
        return r[0]
    else:
        return r


# Write


def writeuint(f, v, bits=64, signed=False):
    assert bits % 8 == 0, "Not support"

    if signed:
        v += 1 << bits

    if bits == 8:
        f.writebytes(v, 1)
        return

    s = 0
    for _ in range(bits // 8):
        f.writebytes(v & 0xFF, 1)
        v = v >> 8
        s += 8


def writeint(f, v, bits=64):
    return writeuint(f, v, bits, signed=True)


def writebits(f, v, bits=8):
    f.write_bits(v, bits)


def write(f, v, format):
    t = format[0]
    bits = format[1]
    n = format[2]

    if not isinstance(v, list):
        v = [v]

    for i in range(n):
        if t == "uint":
            writeuint(f, v[i], bits=bits)
        elif t == "int":
            writeint(f, v[i], bits=bits)
        elif t == "bit":
            writebits(f, v[i], bits=bits)
        else:
            raise Exception(f"Data type {t} is not supported.")


# Unpacking


def to_uint8(buf):
    return buf[0]


def to_uint16(buf):
    return unpack("<H", bytes(buf[:2]))[0]


def to_uint32(buf):
    return unpack("<L", bytes(buf[:4]))[0]


def to_int8(buf):
    return unpack("<b", bytes([buf[0]]))[0]


def to_int32(buf):
    return unpack("<i", bytes(buf[:4]))[0]


def to_double(buf):
    return unpack("<d", bytes(buf[:8]))[0]


# Packing


def from_uint8(val):
    return [val]


def from_uint16(val):
    return list(pack("<H", val))


def from_uint32(val):
    return list(pack("<L", val))


def from_int8(val):
    return list(pack("<b", val))


def from_int32(val):
    return list(pack("<i", val))


def from_double(val):
    return list(pack("<d", val))


# Buf Function


def memcpy(dest, src, start, length):
    for i in range(length):
        dest[start + i] = src[i]
