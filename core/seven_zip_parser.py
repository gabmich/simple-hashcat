"""
7z file parser for hash extraction.
Python port of john's 7z2john.pl logic.
Supports encrypted 7z archives including encrypted headers.
"""

import struct
import lzma
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from pathlib import Path


# 7z signature
SIGNATURE = b'7z\xbc\xaf\x27\x1c'

# 7zAES codec ID (AES-256 + SHA-256)
CODEC_7ZAES = bytes([0x06, 0xf1, 0x07, 0x01])

# Compression codec IDs
CODEC_LZMA1 = bytes([0x03, 0x01, 0x01])
CODEC_LZMA2 = bytes([0x21])
CODEC_PPMD = bytes([0x03, 0x04, 0x01])
CODEC_BZIP2 = bytes([0x04, 0x02, 0x02])
CODEC_DEFLATE = bytes([0x04, 0x01, 0x08])
CODEC_COPY = bytes([0x00])

# Property IDs
kEnd = 0x00
kHeader = 0x01
kMainStreamsInfo = 0x04
kFilesInfo = 0x05
kPackInfo = 0x06
kUnPackInfo = 0x07
kSubStreamsInfo = 0x08
kSize = 0x09
kCRC = 0x0a
kFolder = 0x0b
kCodersUnPackSize = 0x0c
kNumUnPackStream = 0x0d
kEncodedHeader = 0x17

# Compression types for hash output
COMP_NONE = 0
COMP_LZMA1 = 1
COMP_LZMA2 = 2
COMP_PPMD = 3


@dataclass
class Coder:
    id: bytes
    num_in: int = 1
    num_out: int = 1
    props: bytes = b''


@dataclass
class Folder:
    coders: List[Coder] = field(default_factory=list)
    unpack_sizes: List[int] = field(default_factory=list)
    crc: Optional[int] = None
    has_crc: bool = False


@dataclass
class StreamsInfo:
    pack_pos: int = 0
    pack_sizes: List[int] = field(default_factory=list)
    folders: List[Folder] = field(default_factory=list)


class SevenZipParser:
    """Parser for 7z encrypted archives."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_data = b''
        self.data = b''
        self.pos = 0
        self.data_start = 32  # After signature header

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError(f"EOF at pos {self.pos}")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            n = len(self.data) - self.pos
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_uint32(self) -> int:
        return struct.unpack('<I', self.read_bytes(4))[0]

    def read_number(self) -> int:
        """Read 7z variable-length number."""
        first = self.read_byte()
        mask = 0x80
        value = 0
        for i in range(8):
            if (first & mask) == 0:
                value |= ((first & (mask - 1)) << (8 * i))
                return value
            if self.pos >= len(self.data):
                return value
            value |= self.read_byte() << (8 * i)
            mask >>= 1
        return value

    def read_bools_default(self, count: int) -> List[bool]:
        """Read booleans with 'all defined' marker."""
        all_def = self.read_byte()
        if all_def:
            return [True] * count
        result = []
        b = 0
        mask = 0
        for _ in range(count):
            if mask == 0:
                b = self.read_byte()
                mask = 0x80
            result.append(bool(b & mask))
            mask >>= 1
        return result

    def extract_hash(self) -> Optional[str]:
        """Main entry: extract hash from 7z file."""
        with open(self.file_path, 'rb') as f:
            self.file_data = f.read()

        # Find signature
        sig_pos = self.file_data.find(SIGNATURE)
        if sig_pos == -1:
            raise ValueError("7z signature not found")

        # Parse start header
        pos = sig_pos + 6
        pos += 2  # version

        pos += 4  # start_crc
        next_offset = struct.unpack('<Q', self.file_data[pos:pos+8])[0]
        pos += 8
        next_size = struct.unpack('<Q', self.file_data[pos:pos+8])[0]

        self.data_start = sig_pos + 32
        header_pos = self.data_start + next_offset

        if header_pos + next_size > len(self.file_data):
            raise ValueError("Invalid header position")

        # Read header
        self.data = self.file_data[header_pos:header_pos + next_size]
        self.pos = 0

        if len(self.data) == 0:
            raise ValueError("Empty header")

        prop_id = self.read_byte()

        if prop_id == kEncodedHeader:
            return self._parse_encoded_header()
        elif prop_id == kHeader:
            return self._parse_main_header()
        else:
            raise ValueError(f"Unknown header type: 0x{prop_id:02x}")

    def _parse_encoded_header(self) -> Optional[str]:
        """Parse encoded header - may need to decompress to get real header."""
        # Read the streams info that describes how to decode the real header
        streams = self._read_streams_info()
        if not streams or not streams.folders:
            raise ValueError("No streams info")

        folder = streams.folders[0]

        # Check if there's an AES coder here
        aes_coder = None
        comp_coder = None

        for coder in folder.coders:
            if coder.id == CODEC_7ZAES:
                aes_coder = coder
            elif coder.id in [CODEC_LZMA1, CODEC_LZMA2]:
                comp_coder = coder

        if aes_coder:
            # AES is in this header, extract directly
            return self._extract_from_streams(streams, folder, aes_coder, comp_coder)

        # No AES here - the header describes compression only
        # This means the real header with AES info is in the compressed stream
        # We need to decompress it first

        if not comp_coder:
            raise ValueError("No compression coder found")

        # The main encrypted data is BEFORE pack_pos
        # pack_pos points to where the compressed header stream starts
        # The encrypted main stream occupies bytes [data_start : data_start + pack_pos]

        main_stream_size = streams.pack_pos

        # Decompress the header stream to get real header
        header_stream_offset = self.data_start + streams.pack_pos
        header_stream_size = streams.pack_sizes[0] if streams.pack_sizes else 0
        header_stream = self.file_data[header_stream_offset:header_stream_offset + header_stream_size]

        real_header = self._decompress_header(header_stream, comp_coder)
        if not real_header:
            raise ValueError("Failed to decompress header")

        # Parse the decompressed real header
        self.data = real_header
        self.pos = 0

        prop_id = self.read_byte()
        if prop_id != kHeader:
            raise ValueError(f"Expected kHeader in decompressed data, got 0x{prop_id:02x}")

        # Now parse the real header which should contain AES info
        return self._parse_real_header_with_main_stream(main_stream_size)

    def _decompress_header(self, compressed: bytes, coder: Coder) -> Optional[bytes]:
        """Decompress LZMA1/LZMA2 compressed header."""
        try:
            if coder.id == CODEC_LZMA1:
                # Parse LZMA1 properties: lc, lp, pb, dict_size
                if len(coder.props) >= 5:
                    props_byte = coder.props[0]
                    lc = props_byte % 9
                    props_byte //= 9
                    lp = props_byte % 5
                    pb = props_byte // 5
                    dict_size = struct.unpack('<I', coder.props[1:5])[0]

                    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[
                        {'id': lzma.FILTER_LZMA1, 'dict_size': dict_size, 'lc': lc, 'lp': lp, 'pb': pb}
                    ])
                    return decompressor.decompress(compressed)

            elif coder.id == CODEC_LZMA2:
                dict_size = 1 << (coder.props[0] + 12) if coder.props else (1 << 24)
                decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[
                    {'id': lzma.FILTER_LZMA2, 'dict_size': dict_size}
                ])
                return decompressor.decompress(compressed)

        except Exception as e:
            pass

        return None

    def _parse_real_header_with_main_stream(self, main_stream_size: int) -> Optional[str]:
        """Parse real header and extract hash using main stream size."""
        streams = None

        while self.pos < len(self.data):
            prop_id = self.read_byte()
            if prop_id == kEnd:
                break
            elif prop_id == kMainStreamsInfo:
                streams = self._read_streams_info()
            elif prop_id == kFilesInfo:
                self._skip_files_info()

        if not streams or not streams.folders:
            raise ValueError("No MainStreamsInfo in real header")

        folder = streams.folders[0]

        # Find AES coder
        aes_coder = None
        comp_coder = None

        for coder in folder.coders:
            if coder.id == CODEC_7ZAES:
                aes_coder = coder
            elif coder.id in [CODEC_LZMA1, CODEC_LZMA2, CODEC_PPMD]:
                comp_coder = coder

        if not aes_coder:
            raise ValueError("No AES encryption in real header")

        # Parse AES properties
        aes_props = self._parse_aes_props(aes_coder.props)
        num_cycles, salt_len, salt, iv_len, iv = aes_props

        # Compression type
        comp_type = COMP_NONE
        comp_props = b''
        if comp_coder:
            comp_type = self._get_comp_type(comp_coder.id)
            comp_props = comp_coder.props

        # The encrypted data is in the main stream (before the compressed header)
        # Use main_stream_size as the data length
        enc_data = self.file_data[self.data_start:self.data_start + main_stream_size]

        # Unpack size from folder
        unpack_size = folder.unpack_sizes[-1] if folder.unpack_sizes else main_stream_size

        # CRC
        crc_val = folder.crc if folder.has_crc else 0
        crc_len = 4 if folder.has_crc else 0

        return self._format_hash(
            comp_type=comp_type,
            num_cycles=num_cycles,
            salt_len=salt_len,
            salt=salt,
            iv_len=iv_len,
            iv=iv,
            crc=crc_val,
            data_len=len(enc_data),
            unpack_size=unpack_size,
            data=enc_data,
            crc_len=crc_len,
            comp_props=comp_props
        )

    def _parse_main_header(self) -> Optional[str]:
        """Parse main header (standard non-encoded header)."""
        streams = None

        while self.pos < len(self.data):
            prop_id = self.read_byte()
            if prop_id == kEnd:
                break
            elif prop_id == kMainStreamsInfo:
                streams = self._read_streams_info()
            elif prop_id == kFilesInfo:
                self._skip_files_info()

        if not streams or not streams.folders:
            return None

        folder = streams.folders[0]

        aes_coder = None
        comp_coder = None

        for coder in folder.coders:
            if coder.id == CODEC_7ZAES:
                aes_coder = coder
            elif coder.id in [CODEC_LZMA1, CODEC_LZMA2, CODEC_PPMD]:
                comp_coder = coder

        if not aes_coder:
            return None

        return self._extract_from_streams(streams, folder, aes_coder, comp_coder)

    def _extract_from_streams(self, streams: StreamsInfo, folder: Folder,
                               aes_coder: Coder, comp_coder: Optional[Coder]) -> str:
        """Extract hash from streams info."""
        aes_props = self._parse_aes_props(aes_coder.props)
        num_cycles, salt_len, salt, iv_len, iv = aes_props

        comp_type = COMP_NONE
        comp_props = b''
        if comp_coder:
            comp_type = self._get_comp_type(comp_coder.id)
            comp_props = comp_coder.props

        pack_size = streams.pack_sizes[0] if streams.pack_sizes else 0
        enc_offset = self.data_start + streams.pack_pos
        enc_data = self.file_data[enc_offset:enc_offset + pack_size]

        unpack_size = folder.unpack_sizes[-1] if folder.unpack_sizes else 0
        crc_val = folder.crc if folder.has_crc else 0
        crc_len = 4 if folder.has_crc else 0

        return self._format_hash(
            comp_type=comp_type,
            num_cycles=num_cycles,
            salt_len=salt_len,
            salt=salt,
            iv_len=iv_len,
            iv=iv,
            crc=crc_val,
            data_len=len(enc_data),
            unpack_size=unpack_size,
            data=enc_data,
            crc_len=crc_len,
            comp_props=comp_props
        )

    def _read_streams_info(self) -> StreamsInfo:
        """Read StreamsInfo structure."""
        info = StreamsInfo()

        while self.pos < len(self.data):
            prop_id = self.read_byte()

            if prop_id == kEnd:
                break
            elif prop_id == kPackInfo:
                info.pack_pos = self.read_number()
                num_streams = self.read_number()

                while self.pos < len(self.data):
                    sub_id = self.read_byte()
                    if sub_id == kEnd:
                        break
                    elif sub_id == kSize:
                        for _ in range(num_streams):
                            info.pack_sizes.append(self.read_number())
                    elif sub_id == kCRC:
                        defs = self.read_bools_default(num_streams)
                        for d in defs:
                            if d:
                                self.read_uint32()

            elif prop_id == kUnPackInfo:
                info.folders = self._read_unpack_info()

            elif prop_id == kSubStreamsInfo:
                self._skip_substreams_info(len(info.folders))

        return info

    def _read_unpack_info(self) -> List[Folder]:
        """Read UnpackInfo structure."""
        folders = []

        while self.pos < len(self.data):
            prop_id = self.read_byte()

            if prop_id == kEnd:
                break
            elif prop_id == kFolder:
                num_folders = self.read_number()
                external = self.read_byte()
                if external:
                    self.read_number()

                for _ in range(num_folders):
                    folders.append(self._read_folder())

            elif prop_id == kCodersUnPackSize:
                for folder in folders:
                    for _ in range(len(folder.coders)):
                        folder.unpack_sizes.append(self.read_number())

            elif prop_id == kCRC:
                defs = self.read_bools_default(len(folders))
                for i, d in enumerate(defs):
                    if d:
                        folders[i].crc = self.read_uint32()
                        folders[i].has_crc = True

        return folders

    def _read_folder(self) -> Folder:
        """Read a single Folder definition."""
        folder = Folder()
        num_coders = self.read_number()

        total_in = 0
        total_out = 0

        for _ in range(num_coders):
            flags = self.read_byte()
            id_size = flags & 0x0f
            is_complex = bool(flags & 0x10)
            has_props = bool(flags & 0x20)

            coder = Coder(id=self.read_bytes(id_size))

            if is_complex:
                coder.num_in = self.read_number()
                coder.num_out = self.read_number()

            if has_props:
                props_size = self.read_number()
                coder.props = self.read_bytes(props_size)

            total_in += coder.num_in
            total_out += coder.num_out
            folder.coders.append(coder)

        # Bind pairs
        num_bind = total_out - 1
        for _ in range(num_bind):
            self.read_number()
            self.read_number()

        # Pack streams
        num_pack = total_in - num_bind
        if num_pack > 1:
            for _ in range(num_pack):
                self.read_number()

        return folder

    def _skip_substreams_info(self, num_folders: int):
        """Skip SubStreamsInfo."""
        num_unpack = [1] * num_folders

        while self.pos < len(self.data):
            prop_id = self.read_byte()
            if prop_id == kEnd:
                break
            elif prop_id == kNumUnPackStream:
                for i in range(num_folders):
                    num_unpack[i] = self.read_number()
            elif prop_id == kSize:
                for i in range(num_folders):
                    for _ in range(num_unpack[i] - 1):
                        self.read_number()
            elif prop_id == kCRC:
                total = sum(num_unpack)
                defs = self.read_bools_default(total)
                for d in defs:
                    if d:
                        self.read_uint32()

    def _skip_files_info(self):
        """Skip FilesInfo."""
        num_files = self.read_number()
        while self.pos < len(self.data):
            prop_id = self.read_byte()
            if prop_id == kEnd:
                break
            size = self.read_number()
            self.pos += size

    def _parse_aes_props(self, props: bytes) -> Tuple[int, int, bytes, int, bytes]:
        """Parse AES properties. Returns (cycles, salt_len, salt, iv_len, iv)."""
        if not props:
            return (19, 0, b'\x00' * 16, 16, b'\x00' * 16)

        first = props[0]
        pos = 1

        num_cycles = first & 0x3f
        salt_len = 0
        iv_len = 0

        if first & 0x80:
            # Has explicit salt/iv sizes byte
            if pos < len(props):
                sizes = props[pos]
                pos += 1
                salt_len = (sizes >> 4) & 0x0f
                iv_len = sizes & 0x0f
                if salt_len:
                    salt_len += 1
                if iv_len:
                    iv_len += 1
        elif first & 0x40:
            # Has IV but no salt (no sizes byte)
            # Remaining bytes are IV (up to 16)
            iv_len = min(16, len(props) - pos)
            salt_len = 0

        # Read salt
        salt = b'\x00' * 16
        if salt_len > 0 and pos + salt_len <= len(props):
            salt = props[pos:pos + salt_len]
            salt = salt + b'\x00' * (16 - len(salt))
            pos += salt_len

        # Read IV
        iv = b'\x00' * 16
        if iv_len > 0 and pos + iv_len <= len(props):
            iv = props[pos:pos + iv_len]
            iv = iv + b'\x00' * (16 - len(iv))

        # John's format puts the IV bytes as "salt" in the hash when there's no real salt
        # and uses empty IV. Let's match that format.
        if salt_len == 0 and iv_len > 0:
            # No salt, only IV - john puts IV data in salt field
            return (num_cycles, iv_len, iv, 0, b'\x00' * 16)

        return (num_cycles, salt_len, salt, iv_len, iv)

    def _get_comp_type(self, codec_id: bytes) -> int:
        """Map codec ID to compression type."""
        mapping = {
            CODEC_LZMA1: COMP_LZMA1,
            CODEC_LZMA2: COMP_LZMA2,
            CODEC_PPMD: COMP_PPMD,
        }
        return mapping.get(codec_id, COMP_NONE)

    def _format_hash(self, comp_type: int, num_cycles: int, salt_len: int, salt: bytes,
                     iv_len: int, iv: bytes, crc: int, data_len: int, unpack_size: int,
                     data: bytes, crc_len: int, comp_props: bytes) -> str:
        """Format hash in john/hashcat format."""
        filename = Path(self.file_path).name

        # Format: $7z$type$cycles$salt_len$salt$iv_len$iv$crc$data_len$unpack_size$data$crc_len$props_len$props
        # Note: john's format puts IV bytes in salt field when there's no real salt

        salt_hex = salt[:salt_len].hex() if salt_len > 0 else ""
        iv_hex = iv[:iv_len].hex() if iv_len > 0 else ""

        parts = [
            f"$7z${comp_type}",
            f"${num_cycles}",
            f"${0 if salt_len == 0 else salt_len}",  # Salt len (0 if using IV as salt)
            f"${salt_hex}",
            f"${16 if salt_len > 0 and iv_len == 0 else iv_len}",  # IV len
            f"${iv_hex}",
            f"${crc}",
            f"${data_len}",
            f"${unpack_size}",
            f"${data.hex()}",
            f"${crc_len}",
        ]

        if comp_props:
            parts.append(f"${len(comp_props)}")
            parts.append(f"${comp_props.hex()}")
        else:
            parts.append("$0")
            parts.append("$0")

        hash_str = "".join(parts)
        return f"{filename}:{hash_str}"


def extract_7z_hash(file_path: str) -> Tuple[bool, str]:
    """Extract hash from 7z file. Returns (success, hash_or_error)."""
    try:
        parser = SevenZipParser(file_path)
        result = parser.extract_hash()
        if result:
            return True, result
        return False, "Could not extract hash"
    except Exception as e:
        return False, str(e)
