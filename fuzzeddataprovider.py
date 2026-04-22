"""Pure-Python FuzzedDataProvider matching the atheris API.

This is a drop-in replacement for atheris.FuzzedDataProvider that requires
no native compilation. It matches atheris's consumption semantics:
  - ConsumeBytes/ConsumeInt/ConsumeFloat/ConsumeUnicode consume from the FRONT
  - ConsumeIntInRange/ConsumeBool/PickValueInList consume from the BACK

Reference: https://github.com/google/atheris
"""

import struct


class FuzzedDataProvider:
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes or bytearray")
        self._data = bytes(data)
        self._front = 0
        self._back = len(self._data)

    def remaining_bytes(self):
        return max(0, self._back - self._front)

    def buffer(self):
        return self._data[self._front : self._back]

    # -- Front-consuming methods (ConsumeBytes, ConsumeInt, etc.) --

    def _consume_front(self, n):
        n = min(n, self.remaining_bytes())
        result = self._data[self._front : self._front + n]
        self._front += n
        return result

    def ConsumeBytes(self, count):
        count = max(0, int(count))
        return self._consume_front(count)

    def ConsumeInt(self, byte_count):
        byte_count = max(0, int(byte_count))
        raw = self._consume_front(byte_count)
        if not raw:
            return 0
        val = int.from_bytes(raw, "little")
        bits = len(raw) * 8
        if val >= (1 << (bits - 1)):
            val -= 1 << bits
        return val

    def ConsumeUInt(self, byte_count):
        byte_count = max(0, int(byte_count))
        raw = self._consume_front(byte_count)
        if not raw:
            return 0
        return int.from_bytes(raw, "little")

    def ConsumeFloat(self):
        raw = self._consume_front(8)
        if len(raw) < 8:
            raw = raw + b"\x00" * (8 - len(raw))
        return struct.unpack("<d", raw)[0]

    def ConsumeRegularFloat(self):
        val = self.ConsumeFloat()
        if val != val or val == float("inf") or val == float("-inf"):
            return 0.0
        return val

    def ConsumeUnicode(self, count):
        count = max(0, int(count))
        if count == 0 or self.remaining_bytes() == 0:
            return ""
        # First byte selects encoding mode (matching atheris behavior)
        mode_byte = self._consume_front(1)
        mode = mode_byte[0] if mode_byte else 0
        if mode == 1:
            # ASCII mode: one byte per character, masked to 0-127
            raw = self._consume_front(count)
            return "".join(chr(b & 0x7F) for b in raw)
        elif mode == 2:
            # UTF-16 mode: two bytes per character
            raw = self._consume_front(count * 2)
            chars = []
            for i in range(0, len(raw) - 1, 2):
                cp = int.from_bytes(raw[i : i + 2], "little")
                chars.append(chr(cp))
            return "".join(chars[:count])
        else:
            # UTF-32 mode: four bytes per character, clamped to valid range
            raw = self._consume_front(count * 4)
            chars = []
            for i in range(0, len(raw) - 3, 4):
                cp = int.from_bytes(raw[i : i + 4], "little") & 0x10FFFF
                try:
                    chars.append(chr(cp))
                except (ValueError, OverflowError):
                    chars.append(" ")
            return "".join(chars[:count])

    def ConsumeUnicodeNoSurrogates(self, count):
        count = max(0, int(count))
        if count == 0 or self.remaining_bytes() == 0:
            return ""
        mode_byte = self._consume_front(1)
        mode = mode_byte[0] if mode_byte else 0
        if mode == 1:
            raw = self._consume_front(count)
            return "".join(chr(b & 0x7F) for b in raw)
        elif mode == 2:
            raw = self._consume_front(count * 2)
            chars = []
            for i in range(0, len(raw) - 1, 2):
                cp = int.from_bytes(raw[i : i + 2], "little")
                if 0xD800 <= cp <= 0xDFFF:
                    cp -= 0xD800
                chars.append(chr(cp))
            return "".join(chars[:count])
        else:
            raw = self._consume_front(count * 4)
            chars = []
            for i in range(0, len(raw) - 3, 4):
                cp = int.from_bytes(raw[i : i + 4], "little") & 0x10FFFF
                if 0xD800 <= cp <= 0xDFFF:
                    cp -= 0xD800
                try:
                    chars.append(chr(cp))
                except (ValueError, OverflowError):
                    chars.append(" ")
            return "".join(chars[:count])

    def ConsumeString(self, count):
        return self.ConsumeUnicode(count)

    # -- Back-consuming methods (ConsumeIntInRange, ConsumeBool, etc.) --

    def _consume_back(self, n):
        n = min(n, self.remaining_bytes())
        result = self._data[self._back - n : self._back]
        self._back -= n
        return result

    def ConsumeIntInRange(self, lo, hi):
        lo, hi = int(lo), int(hi)
        if lo > hi:
            lo, hi = hi, lo
        if lo == hi:
            return lo
        rng = hi - lo
        # Match LLVM: consume ceil(bits_needed/8) bytes from back
        # LLVM loops while offset < sizeof(T)*8 && (range >> offset) > 0
        nbytes = (rng.bit_length() + 7) // 8
        raw = self._consume_back(nbytes)
        if not raw:
            return lo
        # LLVM reads bytes from back as big-endian accumulation:
        #   result = (result << 8) | next_byte_from_back
        # which equals int.from_bytes(reversed_bytes, 'big')
        # But since _consume_back returns bytes in memory order and
        # int.from_bytes(raw, 'little') produces the same value, we use that.
        val = int.from_bytes(raw, "little")
        return lo + (val % (rng + 1))

    # Alias for LLVM naming compatibility
    ConsumeIntegralInRange = ConsumeIntInRange

    def ConsumeBool(self):
        # Matches LLVM: 1 & ConsumeIntegral<uint8_t>()
        # ConsumeIntegral<uint8_t>() = ConsumeIntegralInRange(0, 255)
        return (self.ConsumeIntInRange(0, 255) & 1) == 1

    def ConsumeProbability(self):
        # Matches LLVM: ConsumeIntegral<uint64_t>() / UINT64_MAX
        # ConsumeIntegral<uint64_t>() = ConsumeIntegralInRange(0, 2^64-1)
        # When range == UINT64_MAX, no modulo is applied (special case)
        raw = self._consume_back(8)
        if not raw:
            return 0.0
        val = int.from_bytes(raw, "little")
        return val / float((1 << 64) - 1)

    def ConsumeFloatInRange(self, lo, hi):
        lo, hi = float(lo), float(hi)
        if lo > hi:
            lo, hi = hi, lo
        p = self.ConsumeProbability()
        return lo + (hi - lo) * p

    def PickValueInList(self, lst):
        if not lst:
            raise ValueError("list must not be empty")
        idx = self.ConsumeIntInRange(0, len(lst) - 1)
        return lst[idx]

    # -- List methods --

    def ConsumeIntList(self, count, byte_count):
        count = max(0, int(count))
        return [self.ConsumeInt(byte_count) for _ in range(count)]

    def ConsumeIntListInRange(self, count, lo, hi):
        count = max(0, int(count))
        return [self.ConsumeIntInRange(lo, hi) for _ in range(count)]

    def ConsumeFloatList(self, count):
        count = max(0, int(count))
        return [self.ConsumeFloat() for _ in range(count)]

    def ConsumeFloatListInRange(self, count, lo, hi):
        count = max(0, int(count))
        return [self.ConsumeFloatInRange(lo, hi) for _ in range(count)]

    def ConsumeProbabilityList(self, count):
        count = max(0, int(count))
        return [self.ConsumeProbability() for _ in range(count)]

    def ConsumeRegularFloatList(self, count):
        count = max(0, int(count))
        return [self.ConsumeRegularFloat() for _ in range(count)]

    # -- Arbitrary value --

    _ANY_TYPE_INT = 0
    _ANY_TYPE_FLOAT = 1
    _ANY_TYPE_BOOL = 2
    _ANY_TYPE_BYTES = 3
    _ANY_TYPE_STRING = 4
    _ANY_TYPE_NONE = 5

    def ConsumeRandomValue(self):
        """Return a value of a randomly chosen primitive type."""
        t = self.ConsumeIntInRange(self._ANY_TYPE_INT, self._ANY_TYPE_NONE)
        if t == self._ANY_TYPE_INT:
            return self.ConsumeInt(4)
        elif t == self._ANY_TYPE_FLOAT:
            return self.ConsumeFloat()
        elif t == self._ANY_TYPE_BOOL:
            return self.ConsumeBool()
        elif t == self._ANY_TYPE_BYTES:
            return self.ConsumeBytes(self.ConsumeIntInRange(0, 64))
        elif t == self._ANY_TYPE_STRING:
            return self.ConsumeUnicode(self.ConsumeIntInRange(0, 64))
        else:
            return None
