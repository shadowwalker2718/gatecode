import bz2
import importlib.util
import io
import lzma
import os
import shutil
import stat
import struct
import struct
import sys
import tempfile
import threading
import time
import zipfile
import zlib  # We may need its compression method
from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC
from Cryptodome.Hash.SHA1 import SHA1Hash
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util import Counter
from pathlib import Path

WZ_AES = 'WZ_AES'
WZ_AES_COMPRESS_TYPE = 99
WZ_AES_V1 = 0x0001
WZ_AES_V2 = 0x0002
WZ_AES_VENDOR_ID = b'AE'

EXTRA_WZ_AES = 0x9901

WZ_SALT_LENGTHS = {
    1: 8,  # 128 bit
    2: 12,  # 192 bit
    3: 16,  # 256 bit
}
WZ_KEY_LENGTHS = {
    1: 16,  # 128 bit
    2: 24,  # 192 bit
    3: 32,  # 256 bit
}
crc32 = zlib.crc32


class BadZipFile(Exception):
    pass


class LargeZipFile(Exception):
    """
    Raised when writing a zipfile, the zipfile requires ZIP64 extensions
    and those extensions are disabled.
    """


error = BadZipfile = BadZipFile  # Pre-3.2 compatibility names

ZIP64_LIMIT = (1 << 31) - 1
ZIP_FILECOUNT_LIMIT = (1 << 16) - 1
ZIP_MAX_COMMENT = (1 << 16) - 1

# constants for Zip file compression methods
ZIP_STORED = 0
ZIP_DEFLATED = 8
ZIP_BZIP2 = 12
ZIP_LZMA = 14
# Other ZIP compression methods not supported

DEFAULT_VERSION = 20
ZIP64_VERSION = 45
BZIP2_VERSION = 46
LZMA_VERSION = 63
# we recognize (but not necessarily support) all features up to that version
MAX_EXTRACT_VERSION = 63

# Extensible data field codes:
# Zip64 extended information extra field
EXTRA_ZIP64 = 0x0001

# Below are some formats and associated data for reading/writing headers using
# the struct module.  The names and structures of headers/records are those used
# in the PKWARE description of the ZIP file format:
#     http://www.pkware.com/documents/casestudies/APPNOTE.TXT
# (URL valid as of January 2008)

# The "end of central directory" structure, magic number, size, and indices
# (section V.I in the format document)
structEndArchive = b"<4s4H2LH"
stringEndArchive = b"PK\005\006"
sizeEndCentDir = struct.calcsize(structEndArchive)

# The "Zip64 end of central directory locator" structure, magic number, and size
structEndArchive64Locator = "<4sLQL"
stringEndArchive64Locator = b"PK\x06\x07"
sizeEndCentDir64Locator = struct.calcsize(structEndArchive64Locator)

# The "Zip64 end of central directory" record, magic number, size, and indices
# (section V.G in the format document)
structEndArchive64 = "<4sQ2H2L4Q"
stringEndArchive64 = b"PK\x06\x06"
sizeEndCentDir64 = struct.calcsize(structEndArchive64)

# The "local file header" structure, magic number, size, and indices
# (section V.A in the format document)
structFileHeader = "<4s2B4HL2L2H"
stringFileHeader = b"PK\003\004"
sizeFileHeader = struct.calcsize(structFileHeader)

_FH_SIGNATURE = 0
_FH_EXTRACT_VERSION = 1
_FH_EXTRACT_SYSTEM = 2
_FH_GENERAL_PURPOSE_FLAG_BITS = 3
_FH_COMPRESSION_METHOD = 4
_FH_LAST_MOD_TIME = 5
_FH_LAST_MOD_DATE = 6
_FH_CRC = 7
_FH_COMPRESSED_SIZE = 8
_FH_UNCOMPRESSED_SIZE = 9
_FH_FILENAME_LENGTH = 10
_FH_EXTRA_FIELD_LENGTH = 11

_MASK_ENCRYPTED = 1 << 0
_MASK_COMPRESS_OPTION_1 = 1 << 1
_MASK_COMPRESS_OPTION_2 = 1 << 2
_MASK_USE_DATA_DESCRIPTOR = 1 << 3
# Bit 4: Reserved for use with compression method 8, for enhanced deflating.
_MASK_RESERVED_BIT_4 = 1 << 4
_MASK_COMPRESSED_PATCH = 1 << 5
_MASK_STRONG_ENCRYPTION = 1 << 6
_MASK_UNUSED_BIT_7 = 1 << 7
_MASK_UNUSED_BIT_8 = 1 << 8
_MASK_UNUSED_BIT_9 = 1 << 9
_MASK_UNUSED_BIT_10 = 1 << 10
_MASK_UTF_FILENAME = 1 << 11
# Bit 12: Reserved by PKWARE for enhanced compression.
_MASK_RESERVED_BIT_12 = 1 << 12
_MASK_ENCRYPTED_CENTRAL_DIR = 1 << 13
# Bit 14, 15: Reserved by PKWARE
_MASK_RESERVED_BIT_14 = 1 << 14
_MASK_RESERVED_BIT_15 = 1 << 15


def _strip_extra(extra, xids):
    # Remove Extra Fields with specified IDs.
    unpack = _EXTRA_FIELD_STRUCT.unpack
    modified = False
    buffer = []
    start = i = 0
    while i + 4 <= len(extra):
        xid, xlen = unpack(extra[i: i + 4])
        j = i + 4 + xlen
        if xid in xids:
            if i != start:
                buffer.append(extra[start: i])
            start = j
            modified = True
        i = j
    if not modified:
        return extra
    return b''.join(buffer)


def _check_zipfile(fp):
    try:
        if EndRecData_(fp):
            return True  # file has correct magic number
    except OSError:
        pass
    return False


def is_zipfile(filename):
    """Quickly see if a file is a ZIP file by checking the magic number.

    The filename argument may be a file or file-like object too.
    """
    result = False
    try:
        if hasattr(filename, "read"):
            result = _check_zipfile(fp=filename)
        else:
            # compat with Path objects were added in python 3.6
            if sys.version_info[0:2] < (3, 6):
                filename = str(filename)
            with open(filename, "rb") as fp:
                result = _check_zipfile(fp)
    except OSError:
        pass
    return result


def _EndRecData64(fpin, offset, endrec):
    """
    Read the ZIP64 end-of-archive records and use that to update endrec
    """
    try:
        fpin.seek(offset - sizeEndCentDir64Locator, 2)
    except OSError:
        # If the seek fails, the file is not large enough to contain a ZIP64
        # end-of-archive record, so just return the end record we were given.
        return endrec

    data = fpin.read(sizeEndCentDir64Locator)
    if len(data) != sizeEndCentDir64Locator:
        return endrec
    sig, diskno, reloff, disks = struct.unpack(structEndArchive64Locator, data)
    if sig != stringEndArchive64Locator:
        return endrec

    if diskno != 0 or disks != 1:
        raise BadZipFile("zipfiles that span multiple disks are not supported")

    # Assume no 'zip64 extensible data'
    fpin.seek(offset - sizeEndCentDir64Locator - sizeEndCentDir64, 2)
    data = fpin.read(sizeEndCentDir64)
    if len(data) != sizeEndCentDir64:
        return endrec
    sig, sz, create_version, read_version, disk_num, disk_dir, \
        dircount, dircount2, dirsize, diroffset = \
        struct.unpack(structEndArchive64, data)
    if sig != stringEndArchive64:
        return endrec

    # Update the original endrec using data from the ZIP64 record
    endrec[ECD_SIGNATURE_] = sig
    endrec[_ECD_DISK_NUMBER] = disk_num
    endrec[_ECD_DISK_START] = disk_dir
    endrec[_ECD_ENTRIES_THIS_DISK] = dircount
    endrec[_ECD_ENTRIES_TOTAL] = dircount2
    endrec[ECD_SIZE_] = dirsize
    endrec[ECD_OFFSET_] = diroffset
    return endrec


def EndRecData_(fpin):
    """Return data from the "End of Central Directory" record, or None.

    The data is a list of the nine items in the ZIP "End of central dir"
    record followed by a tenth item, the file seek offset of this record."""

    # Determine file size
    fpin.seek(0, 2)
    filesize = fpin.tell()

    # Check to see if this is ZIP file with no archive comment (the
    # "end of central directory" structure should be the last item in the
    # file if this is the case).
    try:
        fpin.seek(-sizeEndCentDir, 2)
    except OSError:
        return None
    data = fpin.read()
    if (len(data) == sizeEndCentDir and
            data[0:4] == stringEndArchive and
            data[-2:] == b"\000\000"):
        # the signature is correct and there's no comment, unpack structure
        endrec = struct.unpack(structEndArchive, data)
        endrec = list(endrec)

        # Append a blank comment and record start offset
        endrec.append(b"")
        endrec.append(filesize - sizeEndCentDir)

        # Try to read the "Zip64 end of central directory" structure
        return _EndRecData64(fpin, -sizeEndCentDir, endrec)

    # Either this is not a ZIP file, or it is a ZIP file with an archive
    # comment.  Search the end of the file for the "end of central directory"
    # record signature. The comment is the last item in the ZIP file and may be
    # up to 64K long.  It is assumed that the "end of central directory" magic
    # number does not appear in the comment.
    maxCommentStart = max(filesize - (1 << 16) - sizeEndCentDir, 0)
    fpin.seek(maxCommentStart, 0)
    data = fpin.read()
    start = data.rfind(stringEndArchive)
    if start >= 0:
        # found the magic number; attempt to unpack and interpret
        recData = data[start:start + sizeEndCentDir]
        if len(recData) != sizeEndCentDir:
            # Zip file is corrupted.
            return None
        endrec = list(struct.unpack(structEndArchive, recData))
        commentSize = endrec[_ECD_COMMENT_SIZE]  # as claimed by the zip file
        comment = data[start + sizeEndCentDir:start + sizeEndCentDir + commentSize]
        endrec.append(comment)
        endrec.append(maxCommentStart + start)

        # Try to read the "Zip64 end of central directory" structure
        return _EndRecData64(fpin, maxCommentStart + start - filesize,
                             endrec)

    # Unable to find a valid end of central directory structure
    return None


class ZipInfo(object):
    """Class with attributes describing each file in the ZIP archive."""

    __slots__ = (
        'orig_filename',
        'filename',
        'date_time',
        'compress_type',
        '_compresslevel',
        'comment',
        'extra',
        'create_system',
        'create_version',
        'extract_version',
        'reserved',
        'flag_bits',
        'volume',
        'internal_attr',
        'external_attr',
        'header_offset',
        'CRC',
        'compress_size',
        'file_size',
        '_raw_time',
    )

    def __init__(self, filename="NoName", date_time=(1980, 1, 1, 0, 0, 0)):
        self.orig_filename = filename  # Original file name in archive

        # Terminate the file name at the first null byte.  Null bytes in file
        # names are used as tricks by viruses in archives.
        null_byte = filename.find(chr(0))
        if null_byte >= 0:
            filename = filename[0:null_byte]
        # This is used to ensure paths in generated ZIP files always use
        # forward slashes as the directory separator, as required by the
        # ZIP format specification.
        if os.sep != "/" and os.sep in filename:
            filename = filename.replace(os.sep, "/")

        self.filename = filename  # Normalized file name
        self.date_time = date_time  # year, month, day, hour, min, sec

        if date_time[0] < 1980:
            raise ValueError('ZIP does not support timestamps before 1980')

        # Standard values:
        self.compress_type = ZIP_STORED  # Type of compression for the file
        self._compresslevel = None  # Level for the compressor
        self.comment = b""  # Comment for each file
        self.extra = b""  # ZIP extra data
        if sys.platform == 'win32':
            self.create_system = 0  # System which created ZIP archive
        else:
            # Assume everything else is unix-y
            self.create_system = 3  # System which created ZIP archive
        self.create_version = DEFAULT_VERSION  # Version which created ZIP archive
        self.extract_version = DEFAULT_VERSION  # Version needed to extract archive
        self.reserved = 0  # Must be zero
        self.flag_bits = 0  # ZIP flag bits
        self.volume = 0  # Volume number of file header
        self.internal_attr = 0  # Internal attributes
        self.external_attr = 0  # External file attributes
        # Other attributes are set by class ZipFile:
        # header_offset         Byte offset to the file header
        # CRC                   CRC-32 of the uncompressed file
        # compress_size         Size of the compressed file
        # file_size             Size of the uncompressed file

    def __repr__(self):
        result = ['<%s filename=%r' % (self.__class__.__name__, self.filename)]
        if self.compress_type != ZIP_STORED:
            result.append(' compress_type=%s' %
                          compressor_names.get(self.compress_type,
                                               self.compress_type))
        hi = self.external_attr >> 16
        lo = self.external_attr & 0xFFFF
        if hi:
            result.append(' filemode=%r' % stat.filemode(hi))
        if lo:
            result.append(' external_attr=%#x' % lo)
        isdir = self.is_dir()
        if not isdir or self.file_size:
            result.append(' file_size=%r' % self.file_size)
        if ((not isdir or self.compress_size) and
                (self.compress_type != ZIP_STORED or
                 self.file_size != self.compress_size)):
            result.append(' compress_size=%r' % self.compress_size)
        result.append('>')
        return ''.join(result)

    @property
    def is_encrypted(self):
        return self.flag_bits & _MASK_ENCRYPTED

    @property
    def is_utf_filename(self):
        """Return True if filenames are encoded in UTF-8.

        Bit 11: Language encoding flag (EFS).  If this bit is set, the filename
        and comment fields for this file MUST be encoded using UTF-8.
        """
        return self.flag_bits & _MASK_UTF_FILENAME

    @property
    def is_compressed_patch_data(self):
        # Zip 2.7: compressed patched data
        return self.flag_bits & _MASK_COMPRESSED_PATCH

    @property
    def is_strong_encryption(self):
        return self.flag_bits & _MASK_STRONG_ENCRYPTION

    @property
    def use_datadescripter(self):
        """Returns True if datadescripter is in use.

        If bit 3 of flags is set, the data descripter is must exist.  It is
        byte aligned and immediately follows the last byte of compressed data.

        crc-32                          4 bytes
        compressed size                 4 bytes
        uncompressed size               4 bytes
        """
        return self.flag_bits & _MASK_USE_DATA_DESCRIPTOR

    def encode_datadescripter(self, zip64, crc, compress_size, file_size):
        fmt = '<LLQQ' if zip64 else '<LLLL'
        return struct.pack(fmt, _DD_SIGNATURE, crc, compress_size, file_size)

    def datadescripter(self, zip64):
        return self.encode_datadescripter(
            zip64, self.CRC, self.compress_size, self.file_size)

    def get_dosdate(self):
        dt = self.date_time
        return (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]

    def get_dostime(self):
        dt = self.date_time
        return dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)

    def encode_local_header(self, *, filename, extract_version, reserved,
                            flag_bits, compress_type, dostime, dosdate, crc,
                            compress_size, file_size, extra):
        header = struct.pack(
            structFileHeader,
            stringFileHeader,
            extract_version,
            reserved,
            flag_bits,
            compress_type,
            dostime,
            dosdate,
            crc,
            compress_size,
            file_size,
            len(filename),
            len(extra)
        )
        return header + filename + extra

    def zip64_local_header(self, zip64, file_size, compress_size):
        """If zip64 is required, return encoded extra block and other
        parameters which may alter the local file header.

        The local zip64 entry requires that, if the zip64 block is present, it
        must contain both file_size and compress_size. This is different to the
        central directory zip64 extra block which requires only fields which
        need the extra zip64 size be present in the extra block.
        """
        min_version = 0
        extra = b''
        requires_zip64 = file_size > ZIP64_LIMIT or compress_size > ZIP64_LIMIT
        if zip64 is None:
            zip64 = requires_zip64
        if zip64:
            extra = struct.pack(
                '<HHQQ',
                EXTRA_ZIP64,
                8 * 2,  # QQ
                file_size,
                compress_size)
        if requires_zip64:
            if not zip64:
                raise LargeZipFile("Filesize would require ZIP64 extensions")
            # File is larger than what fits into a 4 byte integer,
            # fall back to the ZIP64 extension
            file_size = 0xffffffff
            compress_size = 0xffffffff
            min_version = ZIP64_VERSION
        return extra, file_size, compress_size, min_version

    def zip64_central_header(self):
        zip64_fields = []
        if self.file_size > ZIP64_LIMIT:
            zip64_fields.append(self.file_size)
            file_size = 0xffffffff
        else:
            file_size = self.file_size

        if self.compress_size > ZIP64_LIMIT:
            zip64_fields.append(self.compress_size)
            compress_size = 0xffffffff
        else:
            compress_size = self.compress_size

        if self.header_offset > ZIP64_LIMIT:
            zip64_fields.append(self.header_offset)
            header_offset = 0xffffffff
        else:
            header_offset = self.header_offset

        # For completeness - We don't support writing disks with multiple parts
        # so the number of disks is always going to be 0. Definitely not
        # more than 65,535.
        # ZIP64_DISK_LIMIT = (1 << 16) - 1
        # if self.disk_start > ZIP64_DISK_LIMIT:
        #     zip64_fields.append(self.disk_start)
        #     disk_num = 0xffff
        # else:
        #     header_offset = self.disk_start

        min_version = 0
        if zip64_fields:
            extra = struct.pack(
                '<HH' + 'Q' * len(zip64_fields),
                EXTRA_ZIP64,
                8 * len(zip64_fields),
                *zip64_fields)
            min_version = ZIP64_VERSION
        else:
            extra = b''
        return extra, file_size, compress_size, header_offset, min_version

    def FileHeader(self, zip64=None):
        """Return the per-file header as a string."""
        dosdate = self.get_dosdate()
        dostime = self.get_dostime()
        if self.use_datadescripter:
            # Set these to zero because we write them after the file data
            CRC = compress_size = file_size = 0
        else:
            CRC = self.CRC
            compress_size = self.compress_size
            file_size = self.file_size

        # Always write ZIP64 back to the start of the extra block for
        # compatability with windows 7.
        min_version = 0
        (extra,
         file_size,
         compress_size,
         zip64_min_version,
         ) = self.zip64_local_header(zip64, file_size, compress_size)
        min_version = min(min_version, zip64_min_version)

        if self.compress_type == ZIP_BZIP2:
            min_version = max(BZIP2_VERSION, min_version)
        elif self.compress_type == ZIP_LZMA:
            min_version = max(LZMA_VERSION, min_version)

        self.extract_version = max(min_version, self.extract_version)
        self.create_version = max(min_version, self.create_version)
        filename, flag_bits = self._encodeFilenameFlags()
        return self.encode_local_header(
            filename=filename,
            extract_version=self.extract_version,
            reserved=self.reserved,
            flag_bits=flag_bits,
            compress_type=self.compress_type,
            dostime=dostime,
            dosdate=dosdate,
            crc=CRC,
            compress_size=compress_size,
            file_size=file_size,
            extra=extra
        )

    def encode_central_directory(self, filename, create_version, create_system,
                                 extract_version, reserved, flag_bits,
                                 compress_type, dostime, dosdate, crc,
                                 compress_size, file_size, disk_start,
                                 internal_attr, external_attr, header_offset,
                                 extra_data, comment):
        try:
            centdir = struct.pack(
                structCentralDir,
                stringCentralDir,
                create_version,
                create_system,
                extract_version,
                reserved,
                flag_bits,
                compress_type,
                dostime,
                dosdate,
                crc,
                compress_size,
                file_size,
                len(filename),
                len(extra_data),
                len(comment),
                disk_start,
                internal_attr,
                external_attr,
                header_offset)
        except DeprecationWarning:
            # Is this for python 3.0 where struct would raise a
            # DeprecationWarning instead of a struct.error when an integer
            # conversion code was passed a non-integer?
            # Is it still needed?
            print((structCentralDir, stringCentralDir, create_version,
                   create_system, extract_version, reserved,
                   flag_bits, compress_type, dostime, dosdate,
                   crc, compress_size, file_size,
                   len(filename), len(extra_data), len(comment),
                   disk_start, internal_attr, external_attr,
                   header_offset), file=sys.stderr)
            raise
        return centdir, filename, extra_data

    def central_directory(self):
        dosdate = self.get_dosdate()
        dostime = self.get_dostime()

        # Always write ZIP64 back to the start of the extra block for
        # compatability with windows 7.
        (extra_data,
         file_size,
         compress_size,
         header_offset,
         min_version,
         ) = self.zip64_central_header()

        if self.compress_type == ZIP_BZIP2:
            min_version = max(BZIP2_VERSION, min_version)
        elif self.compress_type == ZIP_LZMA:
            min_version = max(LZMA_VERSION, min_version)

        extract_version = max(min_version, self.extract_version)
        create_version = max(min_version, self.create_version)
        filename, flag_bits = self._encodeFilenameFlags()
        # Writing multi disk archives is not supported so disks is always 0
        disk_start = 0
        return self.encode_central_directory(
            filename=filename,
            create_version=create_version,
            create_system=self.create_system,
            extract_version=extract_version,
            reserved=self.reserved,
            flag_bits=flag_bits,
            compress_type=self.compress_type,
            dostime=dostime,
            dosdate=dosdate,
            crc=self.CRC,
            compress_size=compress_size,
            file_size=file_size,
            disk_start=disk_start,
            internal_attr=self.internal_attr,
            external_attr=self.external_attr,
            header_offset=header_offset,
            extra_data=extra_data,
            comment=self.comment)

    def _encodeFilenameFlags(self):
        try:
            return self.filename.encode('ascii'), self.flag_bits
        except UnicodeEncodeError:
            return (
                self.filename.encode('utf-8'),
                self.flag_bits | _MASK_UTF_FILENAME
            )

    def decode_extra_zip64(self, ln, extra, is_central_directory=True):

        # offset = len(extra block tag) + len(extra block size)
        offset = 4

        # Unpack the extra block from one of the possiblities given the
        # combinations of a struct 'QQQL' where every field is optional.
        if ln == 0:
            counts = ()
        elif ln in {8, 16, 24}:
            field_cnt = ln / 8
            counts = struct.unpack('<%dQ' % field_cnt, extra[offset:offset + ln])
        elif ln in {4, 12, 20, 28}:
            q_field_cnt = (ln - 4) / 8
            if q_field_cnt == 0:
                struct_str = '<I'
            else:
                struct_str = '<%dQI' % (q_field_cnt,)
            counts = struct.unpack(struct_str, extra[offset:offset + ln])

        else:
            raise BadZipFile(
                "Corrupt extra field %04x (size=%d)" % (EXTRA_ZIP64, ln)
            )

        zip64_field_cnt = 0
        # ZIP64 extension (large files and/or large archives)
        try:
            if self.file_size in (0xffffffffffffffff, 0xffffffff):
                field = "File size"
                self.file_size = counts[zip64_field_cnt]
                zip64_field_cnt += 1

            if self.compress_size == 0xffffffff:
                field = "Compress size"
                self.compress_size = counts[zip64_field_cnt]
                zip64_field_cnt += 1

            if is_central_directory:
                if self.header_offset == 0xffffffff:
                    field = "Header offset"
                    self.header_offset = counts[zip64_field_cnt]
                    zip64_field_cnt += 1

                # For completeness - The spec defines a way for handling a larger
                # number of disks than can fit into 2 bytes. As zipfile currently
                # doesn't support multiple disks we don't do anything with this
                # field.
                # if self.diskno == 0xffff:
                #     field = "Disk number"
                #     self.diskno = counts[zip64_field_cnt]
                #     zip64_field_cnt += 1
        except IndexError:
            raise BadZipFile(
                "Corrupt zip64 extra field. {} not found.".format(field)
            ) from None

    def get_extra_decoders(self):
        return {
            EXTRA_ZIP64: self.decode_extra_zip64,
        }

    def _decodeExtra(self):
        # Try to decode the extra field.
        extra = self.extra
        extra_decoders = self.get_extra_decoders()
        while len(extra) >= 4:
            tp, ln = struct.unpack('<HH', extra[:4])
            if ln + 4 > len(extra):
                raise BadZipFile(
                    "Corrupt extra field %04x (size=%d)" % (tp, ln)
                )
            try:
                extra_decoders[tp](ln, extra)
            except KeyError:
                # We don't support this particular Extra Data field
                pass
            extra = extra[ln + 4:]

    @classmethod
    def from_file(cls, filename, arcname=None, *, strict_timestamps=True):
        """Construct an appropriate ZipInfo for a file on the filesystem.

        filename should be the path to a file or directory on the filesystem.

        arcname is the name which it will have within the archive (by default,
        this will be the same as filename, but without a drive letter and with
        leading path separators removed).
        """

        # os.PathLike and os.fspath were added in python 3.6
        if sys.version_info[0:2] >= (3, 6):
            if isinstance(filename, os.PathLike):
                filename = os.fspath(filename)
        else:
            if isinstance(filename, pathlib.PurePath):
                filename = str(filename)
        st = os.stat(filename)
        isdir = stat.S_ISDIR(st.st_mode)
        mtime = time.localtime(st.st_mtime)
        date_time = mtime[0:6]
        if not strict_timestamps and date_time[0] < 1980:
            date_time = (1980, 1, 1, 0, 0, 0)
        elif not strict_timestamps and date_time[0] > 2107:
            date_time = (2107, 12, 31, 23, 59, 59)
        # Create ZipInfo instance to store file information
        if arcname is None:
            arcname = filename
        arcname = os.path.normpath(os.path.splitdrive(arcname)[1])
        while arcname[0] in (os.sep, os.altsep):
            arcname = arcname[1:]
        if isdir:
            arcname += '/'
        zinfo = cls(arcname, date_time)
        zinfo.external_attr = (st.st_mode & 0xFFFF) << 16  # Unix attributes
        if isdir:
            zinfo.file_size = 0
            zinfo.external_attr |= 0x10  # MS-DOS directory flag
        else:
            zinfo.file_size = st.st_size

        return zinfo

    def is_dir(self):
        """Return True if this archive member is a directory."""
        return self.filename[-1] == '/'


_crctable = None


def _gen_crc(crc):
    for j in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0xEDB88320
        else:
            crc >>= 1
    return crc


class BaseZipDecrypter:

    def decrypt(self, data):
        raise NotImplementedError(
            'BaseZipDecrypter implementations must implement `decrypt`.'
        )


class CRCZipDecrypter(BaseZipDecrypter):
    """PKWARE Encryption Decrypter

    ZIP supports a password-based form of encryption. Even though known
    plaintext attacks have been found against it, it is still useful
    to be able to get data out of such a file.

    Usage:
        zd = CRCZipDecrypter(zinfo, mypwd, encryption_header)
        plain_bytes = zd.decrypt(cypher_bytes)
    """

    encryption_header_length = 12

    def __init__(self, zinfo, pinyin, encryption_header):

        self.key0 = 305419896
        self.key1 = 591751049
        self.key2 = 878082192

        global _crctable
        if _crctable is None:
            _crctable = list(map(_gen_crc, range(256)))
        self.crctable = _crctable

        for p in pinyin:
            self.update_keys(p)

        # The first 12 bytes in the cypher stream is an encryption header
        #  used to strengthen the algorithm. The first 11 bytes are
        #  completely random, while the 12th contains the MSB of the CRC,
        #  or the MSB of the file time depending on the header type
        #  and is used to check the correctness of the password.
        h = self.decrypt(encryption_header[0:12])
        if zinfo.use_datadescripter:
            # compare against the file type from extended local headers
            check_byte = (zinfo._raw_time >> 8) & 0xff
        else:
            # compare against the CRC otherwise
            check_byte = (zinfo.CRC >> 24) & 0xff
        if h[11] != check_byte:
            raise RuntimeError("Bad password for file %r" % zinfo.filename)

    def crc32(self, ch, crc):
        """Compute the CRC32 primitive on one byte."""
        return (crc >> 8) ^ self.crctable[(crc ^ ch) & 0xFF]

    def update_keys(self, c):
        self.key0 = self.crc32(c, self.key0)
        self.key1 = (self.key1 + (self.key0 & 0xFF)) & 0xFFFFFFFF
        self.key1 = (self.key1 * 134775813 + 1) & 0xFFFFFFFF
        self.key2 = self.crc32(self.key1 >> 24, self.key2)

    def decrypt(self, data):
        """Decrypt a bytes object."""
        result = bytearray()
        append = result.append
        for c in data:
            k = self.key2 | 2
            c ^= ((k * (k ^ 1)) >> 8) & 0xFF
            self.update_keys(c)
            append(c)
        return bytes(result)


class LZMACompressor:
    # The LZMA SDK version is not related to the XZ Util's liblzma version that
    # the python library links to. The LZMA SDK is associated with the 7-zip
    # project by Igor Pavlov. If there is a breaking change in how the
    # properties are packed or their contents, these version identifiers can be
    # used to specify the strategy for decompression. While the version of the
    # LZMA SDK changes with each new version of 7zip, I don't believe there has
    # been any breaking changes since the version supplied here (but I haven't
    # spent much time confirming if that is true).
    LZMA_SDK_MAJOR_VERSION = 9
    LZMA_SDK_MINOR_VERSION = 4

    def __init__(self):
        self._comp = None

    def _init(self):
        props = lzma._encode_filter_properties({'id': lzma.FILTER_LZMA1})
        self._comp = lzma.LZMACompressor(lzma.FORMAT_RAW, filters=[
            lzma._decode_filter_properties(lzma.FILTER_LZMA1, props)
        ])
        header = struct.pack(
            '<BBH',
            self.LZMA_SDK_MAJOR_VERSION,
            self.LZMA_SDK_MINOR_VERSION,
            len(props)
        ) + props
        return header

    def compress(self, data):
        if self._comp is None:
            return self._init() + self._comp.compress(data)
        return self._comp.compress(data)

    def flush(self):
        if self._comp is None:
            return self._init() + self._comp.flush()
        return self._comp.flush()


class LZMADecompressor:
    # By itself, this decompressor needs an end of stream marker to know when
    # the compressed stream has finished. If there is no end of stream marker,
    # but the zip file length is known, the file can still be processed by
    # ensuring we only pass data to the length of 'compress_size' to the
    # decompressor.
    #
    # There should be a check to make sure either the end of stream marker flag
    # is set or the 'compress_size' is provided to catch malformed files.
    #
    # https://sourceforge.net/p/lzmautils/discussion/708858/thread/da2a47a8/
    # (2011-12-06)
    # "The raw decoder API works only with streams that have end of
    # payload/stream marker. The raw stream APIs don't support much else than
    # what would be valid inside a .xz file.
    # The .lzma file decoder (lzma_alone_decoder) works with files that have a
    # known size in the header and no end marker. It's handled as a special
    # case internally and is not exported to raw decoder API; maybe it should
    # be."

    def __init__(self):
        self._decomp = None
        self._unconsumed = b''
        self.eof = False

    def decompress(self, data):
        if self._decomp is None:
            self._unconsumed += data
            if len(self._unconsumed) <= 4:
                return b''
            major_version, minor_version, psize = struct.unpack(
                '<BBH', self._unconsumed[:4])
            if len(self._unconsumed) <= 4 + psize:
                return b''

            self._decomp = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[
                lzma._decode_filter_properties(lzma.FILTER_LZMA1,
                                               self._unconsumed[4:4 + psize])
            ])
            data = self._unconsumed[4 + psize:]
            del self._unconsumed

        result = self._decomp.decompress(data)
        self.eof = self._decomp.eof
        return result


compressor_names = {
    0: 'store',
    1: 'shrink',
    2: 'reduce',
    3: 'reduce',
    4: 'reduce',
    5: 'reduce',
    6: 'implode',
    7: 'tokenize',
    8: 'deflate',
    9: 'deflate64',
    10: 'implode',
    12: 'bzip2',
    14: 'lzma',
    18: 'terse',
    19: 'lz77',
    97: 'wavpack',
    98: 'ppmd',
}


def check_compression_(compression):
    if compression == ZIP_STORED:
        pass
    elif compression == ZIP_DEFLATED:
        if not zlib:
            raise RuntimeError(
                "Compression requires the (missing) zlib module")
    elif compression == ZIP_BZIP2:
        if not bz2:
            raise RuntimeError(
                "Compression requires the (missing) bz2 module")
    elif compression == ZIP_LZMA:
        if not lzma:
            raise RuntimeError(
                "Compression requires the (missing) lzma module")
    else:
        raise NotImplementedError("That compression method is not supported")


def _get_compressor(compress_type, compresslevel=None):
    if compress_type == ZIP_DEFLATED:
        if compresslevel is not None:
            return zlib.compressobj(compresslevel, zlib.DEFLATED, -15)
        return zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    elif compress_type == ZIP_BZIP2:
        if compresslevel is not None:
            return bz2.BZ2Compressor(compresslevel)
        return bz2.BZ2Compressor()
    # compresslevel is ignored for ZIP_LZMA
    elif compress_type == ZIP_LZMA:
        return LZMACompressor()
    else:
        return None


class SharedFile_:
    def __init__(self, file, pos, close, lock, writing):
        self._file = file
        self._pos = pos
        self._close = close
        self._lock = lock
        self._writing = writing
        self.seekable = file.seekable
        self.tell = file.tell

    def seek(self, offset, whence=0):
        with self._lock:
            if self._writing():
                raise ValueError("Can't reposition in the ZIP file while "
                                 "there is an open writing handle on it. "
                                 "Close the writing handle before trying to read.")
            self._file.seek(offset, whence)
            self._pos = self._file.tell()
            return self._pos

    def read(self, n=-1):
        with self._lock:
            if self._writing():
                raise ValueError("Can't read from the ZIP file while there "
                                 "is an open writing handle on it. "
                                 "Close the writing handle before trying to read.")
            self._file.seek(self._pos)
            data = self._file.read(n)
            self._pos = self._file.tell()
            return data

    def close(self):
        if self._file is not None:
            fileobj = self._file
            self._file = None
            self._close(fileobj)


# Provide the tell method for unseekable stream
class _Tellable:
    def __init__(self, fp):
        self.fp = fp
        self.offset = 0

    def write(self, data):
        n = self.fp.write(data)
        self.offset += n
        return n

    def tell(self):
        return self.offset

    def flush(self):
        self.fp.flush()

    def close(self):
        self.fp.close()


class ZipExtFile(io.BufferedIOBase):
    """File-like object for reading an archive member.

    Is returned by ZipFile.open().

    Responsible for reading the following parts of a zip file:

        [local file header]
        [encryption header]
        [file data]
        [data descriptor]

    For symmetry, the ZipWriteFile_ class is responsible for writing the same
    sections.
    """

    # Max size supported by decompressor.
    MAX_N = 1 << 31 - 1

    # Read from compressed files in 4k blocks.
    MIN_READ_SIZE = 4096

    # Chunk size to read during seek
    MAX_SEEK_READ = 1 << 24

    def __init__(self, fileobj, mode, zipinfo, close_fileobj=False, pinyin=None):
        self._fileobj = fileobj
        self._zinfo = zipinfo
        self._close_fileobj = close_fileobj
        self._pwd = pinyin

        self.process_local_header()
        self.raise_for_unsupported_flags()

        self._compress_type = zipinfo.compress_type
        self._orig_compress_left = zipinfo.compress_size
        self.newlines = None

        self.mode = mode
        self.name = zipinfo.filename

        if hasattr(zipinfo, 'CRC'):
            self._expected_crc = zipinfo.CRC
            self._orig_start_crc = crc32(b'')
        else:
            self._expected_crc = None
            self._orig_start_crc = None

        self._seekable = False
        try:
            if fileobj.seekable():
                self._seekable = True
        except AttributeError:
            pass

        if self._zinfo.is_encrypted:
            self._decrypter_cls = self.setup_decrypter()
        else:
            self._decrypter_cls = None
        # Compress start is the start of the file data. It is after any
        # encryption header, if the encryption_header is present.
        self._compress_start = fileobj.tell()
        self.read_init()

    def read_init(self):
        self._running_crc = self._orig_start_crc
        # Remaining compressed bytes remaining to be read.
        self._compress_left = self._orig_compress_left
        # Remaining number of uncompressed bytes not returned to the calling
        # application.
        self._left = self._zinfo.file_size
        # Uncompressed data ready to return to the calling application.
        self._readbuffer = b''
        # The current position in _readbuffer for the next byte to return.
        self._offset = 0
        self._eof = False

        self._decrypter = self.get_decrypter()
        self._decompressor = self.get_decompressor(self._compress_type)

    def process_local_header(self):
        """Read the local header and raise for any errors.

        The local header is largely a duplicate of the file's entry in the
        central directory. Where it differs, the local header generally
        contains less information than the entry in the central directory.

        Currently we only use the local header data to check for errors.
        """
        # Skip the file header:
        fheader = self._fileobj.read(sizeFileHeader)
        if len(fheader) != sizeFileHeader:
            raise BadZipFile("Truncated file header")
        fheader = struct.unpack(structFileHeader, fheader)
        if fheader[_FH_SIGNATURE] != stringFileHeader:
            raise BadZipFile("Bad magic number for file header")

        fname = self._fileobj.read(fheader[_FH_FILENAME_LENGTH])
        if fheader[_FH_EXTRA_FIELD_LENGTH]:
            self._fileobj.read(fheader[_FH_EXTRA_FIELD_LENGTH])

        if self._zinfo.is_utf_filename:
            # UTF-8 filename
            fname_str = fname.decode("utf-8")
        else:
            fname_str = fname.decode("cp437")

        if fname_str != self._zinfo.orig_filename:
            raise BadZipFile(
                'File name in directory %r and header %r differ.'
                % (self._zinfo.orig_filename, fname))

    def raise_for_unsupported_flags(self):
        if self._zinfo.is_compressed_patch_data:
            # Zip 2.7: compressed patched data
            raise NotImplementedError("compressed patched data (flag bit 5)")

        if self._zinfo.is_strong_encryption:
            # strong encryption
            raise NotImplementedError("strong encryption (flag bit 6)")

    def get_decompressor(self, compress_type):
        if compress_type == ZIP_STORED:
            return None
        elif compress_type == ZIP_DEFLATED:
            return zlib.decompressobj(-15)
        elif compress_type == ZIP_BZIP2:
            return bz2.BZ2Decompressor()
        elif compress_type == ZIP_LZMA:
            return LZMADecompressor()
        else:
            descr = compressor_names.get(compress_type)
            if descr:
                raise NotImplementedError(
                    "compression type %d (%s)" % (compress_type, descr)
                )
            else:
                raise NotImplementedError(
                    "compression type %d" % (compress_type,)
                )

    def setup_crczipdecrypter(self):
        if not self._pwd:
            raise RuntimeError("File %r is encrypted, password "
                               "required for extraction" % self.name)

        self.encryption_header = self._fileobj.read(
            CRCZipDecrypter.encryption_header_length)
        # Adjust read size for encrypted files since the start of the file
        # may be used for the encryption/password information.
        self._orig_compress_left -= CRCZipDecrypter.encryption_header_length
        return CRCZipDecrypter

    def setup_decrypter(self):
        return self.setup_crczipdecrypter()

    def get_decrypter_kwargs(self):
        return {
            'pinyin': self._pwd,
            'encryption_header': self.encryption_header,
        }

    def get_decrypter(self):
        decrypter = None
        if self._decrypter_cls is not None:
            decrypter = self._decrypter_cls(
                self._zinfo,
                **self.get_decrypter_kwargs()
            )
        return decrypter

    def __repr__(self):
        result = ['<%s.%s' % (self.__class__.__module__,
                              self.__class__.__qualname__)]
        if not self.closed:
            result.append(' name=%r mode=%r' % (self.name, self.mode))
            if self._compress_type != ZIP_STORED:
                result.append(' compress_type=%s' %
                              compressor_names.get(self._compress_type,
                                                   self._compress_type))
        else:
            result.append(' [closed]')
        result.append('>')
        return ''.join(result)

    def readline(self, limit=-1):
        """Read and return a line from the stream.

        If limit is specified, at most limit bytes will be read.
        """

        if limit < 0:
            # Shortcut common case - newline found in buffer.
            i = self._readbuffer.find(b'\n', self._offset) + 1
            if i > 0:
                line = self._readbuffer[self._offset: i]
                self._offset = i
                return line

        return io.BufferedIOBase.readline(self, limit)

    def peek(self, n=1):
        """Returns buffered bytes without advancing the position."""
        if n > len(self._readbuffer) - self._offset:
            chunk = self.read(n)
            if len(chunk) > self._offset:
                self._readbuffer = chunk + self._readbuffer[self._offset:]
                self._offset = 0
            else:
                self._offset -= len(chunk)

        # Return up to 512 bytes to reduce allocation overhead for tight loops.
        return self._readbuffer[self._offset: self._offset + 512]

    def readable(self):
        return True

    def read(self, n=-1):
        """Read and return up to n bytes.

        If the argument is omitted, None, or negative, data is read and
        returned until EOF is reached.
        """
        if n is None or n < 0:
            buf = self._readbuffer[self._offset:]
            self._readbuffer = b''
            self._offset = 0
            while not self._eof:
                buf += self._read1(self.MAX_N)
            return buf

        end = n + self._offset
        if end < len(self._readbuffer):
            buf = self._readbuffer[self._offset:end]
            self._offset = end
            return buf

        n = end - len(self._readbuffer)
        buf = self._readbuffer[self._offset:]
        self._readbuffer = b''
        self._offset = 0
        while n > 0 and not self._eof:
            data = self._read1(n)
            if n < len(data):
                self._readbuffer = data
                self._offset = n
                buf += data[:n]
                break
            buf += data
            n -= len(data)
        return buf

    def _update_crc(self, newdata):
        # Update the CRC using the given data.
        if self._expected_crc is None:
            # No need to compute the CRC if we don't have a reference value
            return
        self._running_crc = crc32(newdata, self._running_crc)

    def check_crc(self):
        if self._expected_crc is None:
            # No need to compute the CRC if we don't have a reference value
            return
        # Check the CRC if we're at the end of the file
        if self._eof and self._running_crc != self._expected_crc:
            raise BadZipFile("Bad CRC-32 for file %r" % self.name)

    def check_integrity(self):
        self.check_crc()

    def read1(self, n):
        """Read up to n bytes with at most one read() system call."""

        if n is None or n < 0:
            buf = self._readbuffer[self._offset:]
            self._readbuffer = b''
            self._offset = 0
            while not self._eof:
                data = self._read1(self.MAX_N)
                if data:
                    buf += data
                    break
            return buf

        end = n + self._offset
        if end < len(self._readbuffer):
            buf = self._readbuffer[self._offset:end]
            self._offset = end
            return buf

        n = end - len(self._readbuffer)
        buf = self._readbuffer[self._offset:]
        self._readbuffer = b''
        self._offset = 0
        if n > 0:
            while not self._eof:
                data = self._read1(n)
                if n < len(data):
                    self._readbuffer = data
                    self._offset = n
                    buf += data[:n]
                    break
                if data:
                    buf += data
                    break
        return buf

    def _read1(self, n):
        # Read up to n compressed bytes with at most one read() system call,
        # decrypt and decompress them.
        if self._eof or n <= 0:
            return b''

        # Read from file.
        if self._compress_type == ZIP_DEFLATED:
            # Handle unconsumed data.
            data = self._decompressor.unconsumed_tail
            if n > len(data):
                data += self._read2(n - len(data))
        else:
            data = self._read2(n)

        if self._compress_type == ZIP_STORED:
            self._eof = self._compress_left <= 0
        elif self._compress_type == ZIP_DEFLATED:
            n = max(n, self.MIN_READ_SIZE)
            data = self._decompressor.decompress(data, n)
            self._eof = (self._decompressor.eof or
                         self._compress_left <= 0 and
                         not self._decompressor.unconsumed_tail)
            if self._eof:
                data += self._decompressor.flush()
        else:
            data = self._decompressor.decompress(data)
            self._eof = self._decompressor.eof or self._compress_left <= 0

        data = data[:self._left]
        self._left -= len(data)
        if self._left <= 0:
            self._eof = True
        self._update_crc(data)
        if self._eof:
            self.check_integrity()
        return data

    def _read2(self, n):
        if self._compress_left <= 0:
            return b''

        n = max(n, self.MIN_READ_SIZE)
        n = min(n, self._compress_left)

        data = self._fileobj.read(n)
        self._compress_left -= len(data)
        if not data:
            raise EOFError

        if self._decrypter is not None:
            data = self._decrypter.decrypt(data)
        return data

    def close(self):
        try:
            if self._close_fileobj:
                self._fileobj.close()
        finally:
            super().close()

    def seekable(self):
        return self._seekable

    def seek(self, offset, whence=0):
        if not self._seekable:
            raise io.UnsupportedOperation("underlying stream is not seekable")
        curr_pos = self.tell()
        if whence == 0:  # Seek from start of file
            new_pos = offset
        elif whence == 1:  # Seek from current position
            new_pos = curr_pos + offset
        elif whence == 2:  # Seek from EOF
            new_pos = self._zinfo.file_size + offset
        else:
            raise ValueError("whence must be os.SEEK_SET (0), "
                             "os.SEEK_CUR (1), or os.SEEK_END (2)")

        if new_pos > self._zinfo.file_size:
            new_pos = self._zinfo.file_size

        if new_pos < 0:
            new_pos = 0

        read_offset = new_pos - curr_pos
        buff_offset = read_offset + self._offset

        if buff_offset >= 0 and buff_offset < len(self._readbuffer):
            # Just move the _offset index if the new position is in the
            # _readbuffer
            self._offset = buff_offset
            read_offset = 0
        elif read_offset < 0:
            # Position is before the current position. Reset the ZipExtFile
            self._fileobj.seek(self._compress_start)
            self.read_init()
            read_offset = new_pos

        while read_offset > 0:
            read_len = min(self.MAX_SEEK_READ, read_offset)
            self.read(read_len)
            read_offset -= read_len

        return self.tell()

    def tell(self):
        if not self._seekable:
            raise io.UnsupportedOperation("underlying stream is not seekable")
        filepos = (
                self._zinfo.file_size - self._left - len(self._readbuffer)
                + self._offset
        )
        return filepos


class ZipWriteFile_(io.BufferedIOBase):
    def __init__(self, zf, zinfo, zip64, encrypter=None):
        self._zinfo = zinfo
        self._zip64 = zip64
        self._zipfile = zf
        self._compressor = _get_compressor(zinfo.compress_type,
                                           zinfo._compresslevel)
        self._encrypter = encrypter
        self._file_size = 0
        self._compress_size = 0
        self._crc = 0

        self.write_local_header()

        if self._encrypter:
            self.write_encryption_header()

    @property
    def _fileobj(self):
        return self._zipfile.fp

    def writable(self):
        return True

    def write_local_header(self):
        header = self._zinfo.FileHeader(self._zip64)
        # From this point onwards, we have likely altered the contents of the
        # file.
        self._zipfile._didModify = True
        self._zipfile._writing = True
        self._fileobj.write(header)

    def write_encryption_header(self):
        buf = self._encrypter.encryption_header()
        self._compress_size += len(buf)
        self._fileobj.write(buf)

    def write(self, data):
        if self.closed:
            raise ValueError('I/O operation on closed file.')
        nbytes = len(data)
        self._file_size += nbytes
        self._crc = crc32(data, self._crc)
        if self._compressor:
            data = self._compressor.compress(data)
        if self._encrypter:
            data = self._encrypter.encrypt(data)
        self._compress_size += len(data)
        self._fileobj.write(data)
        return nbytes

    def close(self):
        if self.closed:
            return
        super().close()
        # Flush any data from the compressor, and update header info
        if self._compressor:
            buf = self._compressor.flush()
        else:
            buf = b''
        if self._encrypter:
            buf = self._encrypter.encrypt(buf)
            buf += self._encrypter.flush()
        self._compress_size += len(buf)
        self._fileobj.write(buf)
        self._zinfo.compress_size = self._compress_size
        self._zinfo.CRC = self._crc
        self._zinfo.file_size = self._file_size

        if not self._zip64:
            if self._file_size > ZIP64_LIMIT:
                raise RuntimeError('File size unexpectedly exceeded ZIP64 '
                                   'limit')
            if self._compress_size > ZIP64_LIMIT:
                raise RuntimeError('Compressed size unexpectedly exceeded '
                                   'ZIP64 limit')

        # Write updated header info
        if self._zinfo.use_datadescripter:
            # Write CRC and file sizes after the file data
            self._fileobj.write(self._zinfo.datadescripter(self._zip64))
            self._zipfile.start_dir = self._fileobj.tell()
        else:
            # Seek backwards and write file header (which will now include
            # correct CRC and file sizes)

            # Preserve current position in file
            self._zipfile.start_dir = self._fileobj.tell()
            self._fileobj.seek(self._zinfo.header_offset)
            self._fileobj.write(self._zinfo.FileHeader(self._zip64))
            self._fileobj.seek(self._zipfile.start_dir)

        self._zipfile._writing = False

        # Successfully written: Add file to our caches
        self._zipfile.filelist.append(self._zinfo)
        self._zipfile.NameToInfo[self._zinfo.filename] = self._zinfo
