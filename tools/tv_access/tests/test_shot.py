"""Screenshot integration tests: real shell utilities behind a fake root channel."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
CHUNK = 524288
MAX_SIZE = 32 * 1024 * 1024

# Execute the submitted TV shell commands locally, with isolated paths and a fake
# compositor. Enforce the real root channel cap, and inject transfer failures.
CHANNEL = r'''
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys

root = Path(os.environ['SHOT_FIXTURE'])
command = sys.argv[-1].replace('/tmp/tv-shot.', str(root/'remote/tv-shot.'))
mode = os.environ.get('SHOT_MODE', '')
kind = ('cleanup' if command.startswith('rm -rf ') else
        'chunk' if 'dd if=' in command else 'capture')
index = int(re.search(r'\bskip=(\d+)', command)[1]) if kind == 'chunk' else None
if kind == 'cleanup' and mode == 'cleanup_failed':
    code, out, err = 125, b'', b'offline cleanup failure\n'
else:
    result = subprocess.run(['sh', '-c', command], capture_output=True, timeout=10)
    code, out, err = result.returncode, result.stdout, result.stderr
if kind == 'capture' and code == 0:
    if mode == 'lost_capture':
        code, out, err = 125, b'', b'offline lost capture reply\n'
    elif mode == 'sha_mismatch':
        out = out.split()[0] + b' ' + b'0'*64 + b'\n'
    elif mode == 'bad_metadata':
        out = b''
    elif mode == 'oversize_metadata':
        out = b'33554433 ' + b'0'*64 + b'\n'
if kind == 'chunk' and index == 1:
    data = base64.b64decode(out)
    if mode == 'short':
        out = base64.encodebytes(data[:-1])
    elif mode == 'long':
        out = base64.encodebytes(data + b'\0')
    elif mode == 'corrupt':
        out = base64.encodebytes(bytes([data[0] ^ 1]) + data[1:])
    elif mode == 'invalid_base64':
        out = b'!not base64!'
    elif mode == 'failed':
        code, out, err = 125, b'', b'offline chunk failure\n'
if len(out) > 1048576 or len(err) > 1048576:
    code, out, err = 125, b'', b'offline root response exceeds 1 MiB\n'
with (root/'channel.jsonl').open('a') as log:
    log.write(json.dumps({'kind': kind, 'index': index, 'size': len(out),
                          'code': code, 'timeout': sys.argv[2]}) + '\n')
sys.stdout.buffer.write(out)
sys.stderr.buffer.write(err)
sys.exit(code)
'''

COMPOSITOR = r'''
import os
from pathlib import Path
import shutil
import sys
import time

mode = os.environ.get('SHOT_MODE', '')
if mode == 'capture_timeout':
    time.sleep(30)
if mode == 'no_image':
    sys.exit(1)
out = Path(sys.argv[sys.argv.index('-p')+1])/sys.argv[sys.argv.index('-n')+1]
shutil.copyfile(Path(os.environ['SHOT_FIXTURE'])/'source.png', out)
'''

CONVERTER = r'''
import json
import os
from pathlib import Path
import shutil
import sys

root = Path(os.environ['SHOT_FIXTURE'])
(root/'convert.json').write_text(json.dumps(sys.argv[1:]))
if os.environ.get('SHOT_MODE') == 'resize_failed':
    Path(sys.argv[-1]).write_bytes(b'partial resized image')
    sys.exit(9)
shutil.copyfile(sys.argv[1], sys.argv[-1])
'''


def png(size):
    """A valid tiny PNG with an ancillary chunk padding it to an exact size."""
    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack(
            '!I', zlib.crc32(kind + data))
    image = b'\x89PNG\r\n\x1a\n'
    image += chunk(b'IHDR', struct.pack('!2I5B', 1, 1, 8, 2, 0, 0, 0))
    image += chunk(b'IDAT', zlib.compress(b'\0\0\0\0'))
    tail = chunk(b'IEND', b'')
    padding = b'Comment\0' + b'x' * (size - len(image) - len(tail) - 20)
    return image + chunk(b'tEXt', padding) + tail


class ShotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root/'bin'
        for directory in (self.bin, self.root/'remote', self.root/'work', self.root/'output'):
            directory.mkdir()
        shutil.copyfile(ROOT/'tv-shot', self.bin/'tv-shot')
        self.script('tv-access', CHANNEL)
        self.script('enlightenment_info', COMPOSITOR)
        self.script('magick', CONVERTER)
        # Exercise utility failures inside the real TV-side shell command too.
        self.script('dd', '''
import os
from pathlib import Path
import sys
if os.environ.get('SHOT_MODE') == 'dd_failed' and 'skip=1' in sys.argv:
    Path(next(arg[3:] for arg in sys.argv if arg.startswith('of='))).write_bytes(b'partial')
    sys.exit(6)
os.execv(''' + repr(shutil.which('dd')) + ''', ['dd', *sys.argv[1:]])
''')
        # Keep the actual eight-iteration capture deadline, but shorten its sleeps.
        self.script('sleep', 'import time\ntime.sleep(.1)\n')
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        SHOT_FIXTURE=str(self.root), TMPDIR=str(self.root/'work'))
        self.source = self.root/'source.png'
        self.out = self.root/'output/screen shot.png'
        self.source.write_bytes(png(2 * CHUNK + 17))

    def script(self, name, code):
        path = self.bin/name
        path.write_text('#!' + sys.executable + '\n' + code)
        path.chmod(0o755)

    def shot(self, mode='', full=True):
        args = ['bash', str(self.bin/'tv-shot'), str(self.out)]
        if full:
            args.append('--full')
        result = subprocess.run(args, env=dict(self.env, SHOT_MODE=mode),
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(list((self.root/'work').iterdir()), [], result.stderr)
        self.assertEqual(list((self.root/'output').glob('.tv-shot.*')), [], result.stderr)
        if mode != 'cleanup_failed':
            self.assertEqual(list((self.root/'remote').iterdir()), [], result.stderr)
        return result

    def calls(self):
        return [json.loads(line) for line in (self.root/'channel.jsonl').read_text().splitlines()]

    def test_chunk_boundaries(self):
        for size in (CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 1):
            with self.subTest(size=size):
                self.source.write_bytes(png(size))
                (self.root/'channel.jsonl').unlink(missing_ok=True)
                result = self.shot()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, str(self.out) + '\n')
                self.assertEqual(self.out.read_bytes(), self.source.read_bytes())
                chunks = [call for call in self.calls() if call['kind'] == 'chunk']
                self.assertEqual([call['index'] for call in chunks],
                                 list(range((size + CHUNK - 1) // CHUNK)))
                self.assertTrue(all(call['size'] < 750000 for call in chunks))
                self.assertTrue(all(call['timeout'] == '15' for call in self.calls()))

    def test_reported_image_size(self):
        self.source.write_bytes(png(2190348))
        result = self.shot()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.out.stat().st_size, 2190348)
        self.assertEqual(hashlib.sha256(self.out.read_bytes()).digest(),
                         hashlib.sha256(self.source.read_bytes()).digest())
        self.assertEqual(len([c for c in self.calls() if c['kind'] == 'chunk']), 5)

    def test_transfer_errors_discard_partial_and_preserve_existing_output(self):
        for mode, code, diagnostic in (
                ('short', 4, 'chunk size mismatch'),
                ('long', 4, 'chunk size mismatch'),
                ('failed', 125, 'chunk retrieval failed at byte 524288'),
                ('dd_failed', 6, 'chunk retrieval failed at byte 524288'),
                ('invalid_base64', 4, 'invalid base64 chunk'),
                ('corrupt', 4, 'SHA-256 mismatch'),
                ('sha_mismatch', 4, 'SHA-256 mismatch')):
            with self.subTest(mode=mode):
                self.out.write_bytes(b'keep existing screenshot')
                result = self.shot(mode)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertIn(diagnostic, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertEqual(self.out.read_bytes(), b'keep existing screenshot')

    def test_failed_transfer_leaves_no_new_output(self):
        result = self.shot('short')
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertFalse(self.out.exists())

    def test_capture_failures_and_metadata(self):
        for mode, code, diagnostic in (
                ('no_image', 3, 'no image produced'),
                ('capture_timeout', 3, 'compositor capture timed out'),
                ('lost_capture', 125, 'lost capture reply'),
                ('bad_metadata', 4, 'invalid screenshot size or SHA-256'),
                ('oversize_metadata', 4, 'limit 32 MiB')):
            with self.subTest(mode=mode):
                result = self.shot(mode)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertIn(diagnostic, result.stderr)
                self.assertFalse(self.out.exists())
                self.assertEqual(result.stdout, '')

    def test_overall_size_limit(self):
        with self.source.open('wb') as source:
            source.truncate(MAX_SIZE + 1)
        result = self.shot()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('PNG exceeds 32 MiB size limit', result.stderr)
        self.assertFalse(self.out.exists())
        self.assertFalse(any(c['kind'] == 'chunk' for c in self.calls()))

    def test_size_limit_is_inclusive(self):
        self.source.write_bytes(png(MAX_SIZE))
        result = self.shot()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.out.stat().st_size, MAX_SIZE)
        self.assertEqual(hashlib.sha256(self.out.read_bytes()).digest(),
                         hashlib.sha256(self.source.read_bytes()).digest())
        self.assertEqual(len([c for c in self.calls() if c['kind'] == 'chunk']), 64)

    def test_default_resize_still_uses_960_pixels(self):
        result = self.shot(full=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads((self.root/'convert.json').read_text())
        self.assertEqual(arguments[1:3], ['-resize', '960x'])
        self.assertEqual(self.out.read_bytes(), self.source.read_bytes())
        self.assertEqual(result.stdout, str(self.out) + '\n')

    def test_resize_failure_removes_partial_output(self):
        self.out.write_bytes(b'keep existing screenshot')
        result = self.shot('resize_failed', full=False)
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertEqual(self.out.read_bytes(), b'keep existing screenshot')
        self.assertEqual(result.stdout, '')

    def test_cleanup_failure_is_reported_without_publishing(self):
        result = self.shot('cleanup_failed')
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertIn('could not clean up TV temporary directory', result.stderr)
        self.assertFalse(self.out.exists())
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
