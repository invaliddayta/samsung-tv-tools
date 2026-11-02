"""Empty-screenshot check: stdlib PNG decoding and the warning threshold."""
import contextlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import shot_check


def paeth(a, b, c):
    pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
    return a if pa <= pb and pa <= pc else b if pb <= pc else c


def encode(rows, width, bpp=4, filters=(0, 1, 2, 3, 4), colour=None, depth=8, interlace=0):
    """Encode rows as a PNG, cycling through the given scanline filters."""
    raw, prev = bytearray(), bytes(width * bpp)
    for y, row in enumerate(rows):
        kind = filters[y % len(filters)]
        out = bytearray([kind])
        for i, value in enumerate(row):
            a = row[i - bpp] if i >= bpp else 0
            b, c = prev[i], prev[i - bpp] if i >= bpp else 0
            # Invalid filter types (5) are written unfiltered.
            predictor = (0, a, b, (a + b) >> 1, paeth(a, b, c), 0)[kind]
            out.append((value - predictor) & 255)
        raw += out
        prev = row

    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    if colour is None:
        colour = 6 if bpp == 4 else 2
    header = struct.pack('>2I5B', width, len(rows), depth, colour, 0, 0, interlace)
    compressed = zlib.compress(bytes(raw))
    # Split IDAT like real encoders do.
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header) + chunk(b'tEXt', b'Comment\0x') +
            chunk(b'IDAT', compressed[:7]) + chunk(b'IDAT', compressed[7:]) + chunk(b'IEND', b''))


def image(width, height, lit=0, pixel=(255, 255, 255, 255), background=(0, 0, 0, 255), bpp=4):
    """Rows of `background` with the first `lit` pixels (row-major) set to `pixel`."""
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            row += bytes((pixel if y * width + x < lit else background)[:bpp])
        rows.append(bytes(row))
    return rows


class DecodeTests(unittest.TestCase):
    def test_every_filter_round_trips(self):
        width, height = 13, 11
        rows = [bytes((x * 37 + y * 101 + c * 59 + (x * y) % 7) & 255
                      for x in range(width) for c in range(4)) for y in range(height)]
        for filters in ((0,), (1,), (2,), (3,), (4,), (4, 2, 1, 3, 0)):
            with self.subTest(filters=filters):
                png = shot_check.read_png(encode(rows, width, filters=filters))
                self.assertEqual([bytes(row) for row in shot_check.scanlines(*png)], rows)

    def test_uniform_rows_reuse_the_previous_row(self):
        rows = image(9, 6, lit=4) + image(9, 6, background=(30, 40, 50, 255))
        for kind in range(5):
            with self.subTest(filter=kind):
                png = shot_check.read_png(encode(rows, 9, filters=(kind,)))
                self.assertEqual([bytes(row) for row in shot_check.scanlines(*png)], rows)

    def test_rgb(self):
        rows = image(10, 5, lit=17, bpp=3)
        png = shot_check.read_png(encode(rows, 10, bpp=3, filters=(4, 1)))
        self.assertEqual(png[2], 3)
        self.assertEqual([bytes(row) for row in shot_check.scanlines(*png)], rows)


class EmptyTests(unittest.TestCase):
    def check(self, rows, width, **options):
        return shot_check.mostly_empty(encode(rows, width, **options))

    def test_black_and_transparent_captures(self):
        for background in ((0, 0, 0, 255), (0, 0, 0, 0), (255, 255, 255, 0), (24, 24, 24, 255)):
            with self.subTest(background=background):
                self.assertIs(self.check(image(50, 40, background=background), 50), True)

    def test_small_overlay_is_still_empty(self):
        # 1.95% visible, like player controls over protected video.
        self.assertIs(self.check(image(100, 100, lit=195), 100, filters=(4,)), True)

    def test_content_threshold(self):
        self.assertIs(self.check(image(100, 100, lit=200), 100, filters=(4,)), False)
        self.assertIs(self.check(image(100, 100, lit=200, bpp=3), 100, bpp=3), False)

    def test_dark_ui_counts_as_content(self):
        dark = image(40, 30, background=(0, 30, 40, 255))
        self.assertIs(self.check(dark, 40), False)

    def test_unsupported_or_invalid_images_are_not_judged(self):
        black = image(8, 8)
        valid = encode(black, 8)
        for data in (b'', b'not a png', valid[:40], valid[:-30],
                     encode(black, 8, depth=16), encode(black, 8, colour=3),
                     encode(black, 8, interlace=1), encode(black, 8, filters=(5,))):
            with self.subTest(size=len(data)):
                self.assertIsNone(shot_check.mostly_empty(data))

    def test_command_warns_but_always_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty, full = Path(tmp)/'empty.png', Path(tmp)/'full.png'
            empty.write_bytes(encode(image(20, 20), 20))
            full.write_bytes(encode(image(20, 20, lit=400), 20))
            for path, warned in ((empty, True), (full, False), (Path(tmp)/'missing.png', False)):
                with self.subTest(path=path.name), contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(shot_check.main(['shot_check.py', str(path)]), 0)
                    self.assertEqual('almost entirely black' in err.getvalue(), warned)


if __name__ == '__main__':
    unittest.main()
