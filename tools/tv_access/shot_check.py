#!/usr/bin/env python3
"""Warn when a tv-shot PNG is almost entirely black or transparent.

The compositor capture leaves out protected video, live TV and HDMI inputs, so
screenshots of them come out empty. Standard library only. A PNG this cannot
read is never reported as empty, and the exit status is always 0.
"""
import struct
import sys
import zlib

DARK = 24  # channel values up to this count as black (RGB) or transparent (alpha)
CONTENT_SHARE = 0.02  # an image with less visible content than this is "empty"
MAX_PIXELS = 8192 * 8192
VISIBLE = bytes(value > DARK for value in range(256))
WARNING = ('tv-shot: warning: the screenshot is almost entirely black or transparent. '
           'Protected video, live TV and HDMI inputs are not captured; '
           'try again on Home or Settings.')


def read_png(data):
    """Return (width, height, bytes per pixel, scanlines) or None if unsupported."""
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        return None
    pos, header, idat = 8, None, []
    while pos + 12 <= len(data):
        size, kind = struct.unpack('>I4s', data[pos:pos + 8])
        if kind == b'IHDR' and size == 13:
            header = struct.unpack('>2I5B', data[pos + 8:pos + 21])
        elif kind == b'IDAT':
            idat.append(data[pos + 8:pos + 8 + size])
        elif kind == b'IEND':
            break
        pos += 12 + size
    if header is None:
        return None
    width, height, depth, colour, _, _, interlace = header
    # tv-shot captures are 8-bit RGBA; RGB is cheap to support as well.
    if depth != 8 or colour not in (2, 6) or interlace or not 0 < width * height <= MAX_PIXELS:
        return None
    bpp = 3 if colour == 2 else 4
    expected = height * (width * bpp + 1)
    raw = zlib.decompressobj().decompress(b''.join(idat), expected)
    if len(raw) != expected:
        return None
    return width, height, bpp, raw


def unfilter(kind, line, prev, bpp):
    """Undo one PNG scanline filter (PNG specification, section 9)."""
    row = bytearray(line)
    if kind == 1:
        for i in range(bpp, len(row)):
            row[i] = (row[i] + row[i - bpp]) & 255
    elif kind == 2:
        for i in range(len(row)):
            row[i] = (row[i] + prev[i]) & 255
    elif kind == 3:
        for i in range(len(row)):
            left = row[i - bpp] if i >= bpp else 0
            row[i] = (row[i] + ((left + prev[i]) >> 1)) & 255
    elif kind == 4:
        for i in range(len(row)):
            a = row[i - bpp] if i >= bpp else 0
            b, c = prev[i], prev[i - bpp] if i >= bpp else 0
            pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
            row[i] = (row[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
    elif kind:
        raise ValueError(f'invalid PNG filter type {kind}')
    return row


def scanlines(width, height, bpp, raw):
    """Yield decoded rows. Uniform areas are cheap: the same filtered input on
    top of the same previous row decodes to that row again."""
    stride = width * bpp
    prev, before, last = bytes(stride), None, None
    for y in range(height):
        start = y * (stride + 1)
        current = raw[start], raw[start + 1:start + 1 + stride]
        row = prev if current == last and prev == before else unfilter(*current, prev, bpp)
        yield row
        before, prev, last = prev, row, current


def visible_pixels(row, bpp):
    """Count pixels that are neither black nor (for RGBA) transparent."""
    colour = 0
    for channel in range(3):
        colour |= int.from_bytes(row[channel::bpp].translate(VISIBLE), 'big')
    if bpp == 4:
        colour &= int.from_bytes(row[3::4].translate(VISIBLE), 'big')
    return bin(colour).count('1')


def mostly_empty(data):
    """True if under CONTENT_SHARE of pixels are visible, None if unreadable."""
    try:
        png = read_png(data)
        if png is None:
            return None
        width, height, bpp, raw = png
        limit, seen, last = width * height * CONTENT_SHARE, 0, None
        for row in scanlines(width, height, bpp, raw):
            if row is not last:
                count, last = visible_pixels(row, bpp), row
            seen += count
            if seen >= limit:
                return False  # stop early: most screenshots have content near the top
        return True
    except (ValueError, struct.error, zlib.error):
        return None


def main(argv):
    if len(argv) != 2:
        print('Usage: shot_check.py IMAGE.png', file=sys.stderr)
        return 0
    try:
        with open(argv[1], 'rb') as image:
            data = image.read()
    except OSError:
        return 0
    if mostly_empty(data):
        print(WARNING, file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
