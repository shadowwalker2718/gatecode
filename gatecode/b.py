from .c import *

ECD_SIGNATURE_ = 0
_ECD_DISK_NUMBER = 1
_ECD_DISK_START = 2
_ECD_ENTRIES_THIS_DISK = 3
_ECD_ENTRIES_TOTAL = 4
ECD_SIZE_ = 5
ECD_OFFSET_ = 6
_ECD_COMMENT_SIZE = 7
# These last two indices are not part of the structure as defined in the
# spec, but they are used internally by this module as a convenience
ECD_COMMENT_ = 8
ECD_LOCATION_ = 9

# The "central directory" structure, magic number, size, and indices
# of entries in the structure (section V.F in the format document)
structCentralDir = "<4s4B4HL2L5H2L"
stringCentralDir = b"PK\001\002"
sizeCentralDir = struct.calcsize(structCentralDir)

# indexes of entries in the central directory structure
CD_SIGNATURE_ = 0
_CD_CREATE_VERSION = 1
_CD_CREATE_SYSTEM = 2
_CD_EXTRACT_VERSION = 3
_CD_EXTRACT_SYSTEM = 4
_CD_FLAG_BITS = 5
_CD_COMPRESS_TYPE = 6
_CD_TIME = 7
_CD_DATE = 8
_CD_CRC = 9
_CD_COMPRESSED_SIZE = 10
_CD_UNCOMPRESSED_SIZE = 11
_CD_FILENAME_LENGTH = 12
_CD_EXTRA_FIELD_LENGTH = 13
_CD_COMMENT_LENGTH = 14
_CD_DISK_NUMBER_START = 15
_CD_INTERNAL_FILE_ATTRIBUTES = 16
_CD_EXTERNAL_FILE_ATTRIBUTES = 17
_CD_LOCAL_HEADER_OFFSET = 18

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
_CD64_SIGNATURE = 0
_CD64_DIRECTORY_RECSIZE = 1
_CD64_CREATE_VERSION = 2
_CD64_EXTRACT_VERSION = 3
_CD64_DISK_NUMBER = 4
_CD64_DISK_NUMBER_START = 5
_CD64_NUMBER_ENTRIES_THIS_DISK = 6
_CD64_NUMBER_ENTRIES_TOTAL = 7
_CD64_DIRECTORY_SIZE = 8
_CD64_OFFSET_START_CENTDIR = 9
_DD_SIGNATURE = 0x08074b50
_EXTRA_FIELD_STRUCT = struct.Struct('<HH')


class ZipFile:
    fp = None  # Set here since __del__ checks it
    _windows_illegal_name_trans_table = None
    zipinfo_cls = ZipInfo
    zipextfile_cls = ZipExtFile
    zipwritefile_cls = ZipWriteFile_

    def __init__(self, file, mode="r", compression=ZIP_STORED, allowZip64=True,
                 compresslevel=None, *, strict_timestamps=True):
        """Open the ZIP file with mode read 'r', write 'w', exclusive create
        'x', or append 'a'."""
        if mode not in ('r', 'w', 'x', 'a'):
            raise ValueError("ZipFile requires mode 'r', 'w', 'x', or 'a'")

        check_compression_(compression)

        self._allowZip64 = allowZip64
        self._didModify = False
        self.debug = 0  # Level of printing: 0 through 3
        self.NameToInfo = {}  # Find file info given name
        self.filelist = []  # List of ZipInfo instances for archive
        self.compression = compression  # Method of compression
        self.compresslevel = compresslevel
        self.mode = mode
        self.pinyin = None
        self.encryption = None
        self.encryption_kwargs = None
        self._comment = b''
        self._strict_timestamps = strict_timestamps

        # Check if we were passed a file-like object
        # os.PathLike and os.fspath were added in python 3.6
        if sys.version_info[0:2] >= (3, 6):
            if isinstance(file, os.PathLike):
                file = os.fspath(file)
        else:
            if isinstance(file, pathlib.PurePath):
                file = str(file)
        if isinstance(file, str):
            # No, it's a filename
            self._filePassed = 0
            self.filename = file
            modeDict = {'r': 'rb', 'w': 'w+b', 'x': 'x+b', 'a': 'r+b',
                        'r+b': 'w+b', 'w+b': 'wb', 'x+b': 'xb'}
            filemode = modeDict[mode]
            while True:
                try:
                    self.fp = io.open(file, filemode)
                except OSError:
                    if filemode in modeDict:
                        filemode = modeDict[filemode]
                        continue
                    raise
                break
        else:
            self._filePassed = 1
            self.fp = file
            self.filename = getattr(file, 'name', None)
        self._fileRefCnt = 1
        self._lock = threading.RLock()
        self._seekable = True
        self._writing = False

        try:
            if mode == 'r':
                self._RealGetContents()
            elif mode in ('w', 'x'):
                # set the modified flag so central directory gets written
                # even if no files are added to the archive
                self._didModify = True
                try:
                    self.start_dir = self.fp.tell()
                except (AttributeError, OSError):
                    self.fp = _Tellable(self.fp)
                    self.start_dir = 0
                    self._seekable = False
                else:
                    # Some file-like objects can provide tell() but not seek()
                    try:
                        self.fp.seek(self.start_dir)
                    except (AttributeError, OSError):
                        self._seekable = False
            elif mode == 'a':
                try:
                    # See if file is a zip file
                    self._RealGetContents()
                    # seek to start of directory and overwrite
                    self.fp.seek(self.start_dir)
                except BadZipFile:
                    # file is not a zip file, just append
                    self.fp.seek(0, 2)

                    # set the modified flag so central directory gets written
                    # even if no files are added to the archive
                    self._didModify = True
                    self.start_dir = self.fp.tell()
            else:
                raise ValueError("Mode must be 'r', 'w', 'x', or 'a'")
        except Exception as e:
            fp = self.fp
            self.fp = None
            self._fpclose(fp)
            raise e

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def __repr__(self):
        result = ['<%s.%s' % (self.__class__.__module__,
                              self.__class__.__qualname__)]
        if self.fp is not None:
            if self._filePassed:
                result.append(' file=%r' % self.fp)
            elif self.filename is not None:
                result.append(' filename=%r' % self.filename)
            result.append(' mode=%r' % self.mode)
        else:
            result.append(' [closed]')
        result.append('>')
        return ''.join(result)

    def _RealGetContents(self):
        """Read in the table of contents for the ZIP file."""
        fp = self.fp
        try:
            endrec = EndRecData_(fp)
        except OSError:
            raise BadZipFile("File is not a zip file")
        if not endrec:
            raise BadZipFile("File is not a zip file")
        if self.debug > 1:
            print(endrec)
        size_cd = endrec[ECD_SIZE_]  # bytes in central directory
        offset_cd = endrec[ECD_OFFSET_]  # offset of central directory
        self._comment = endrec[ECD_COMMENT_]  # archive comment

        # "concat" is zero, unless zip was concatenated to another file
        concat = endrec[ECD_LOCATION_] - size_cd - offset_cd
        if endrec[ECD_SIGNATURE_] == stringEndArchive64:
            # If Zip64 extension structures are present, account for them
            concat -= (sizeEndCentDir64 + sizeEndCentDir64Locator)

        if self.debug > 2:
            inferred = concat + offset_cd
            print("given, inferred, offset", offset_cd, inferred, concat)
        # self.start_dir:  Position of start of central directory
        self.start_dir = offset_cd + concat
        fp.seek(self.start_dir, 0)
        data = fp.read(size_cd)
        fp = io.BytesIO(data)
        total = 0
        while total < size_cd:
            centdir = fp.read(sizeCentralDir)
            if len(centdir) != sizeCentralDir:
                raise BadZipFile("Truncated central directory")
            centdir = struct.unpack(structCentralDir, centdir)
            if centdir[CD_SIGNATURE_] != stringCentralDir:
                raise BadZipFile("Bad magic number for central directory")
            if self.debug > 2:
                print(centdir)
            filename = fp.read(centdir[_CD_FILENAME_LENGTH])
            flags = centdir[5]
            if flags & _MASK_UTF_FILENAME:
                # UTF-8 file names extension
                filename = filename.decode('utf-8')
            else:
                # Historical ZIP filename encoding
                filename = filename.decode('cp437')
            # Create ZipInfo instance to store file information
            x = self.zipinfo_cls(filename)
            x.extra = fp.read(centdir[_CD_EXTRA_FIELD_LENGTH])
            x.comment = fp.read(centdir[_CD_COMMENT_LENGTH])
            x.header_offset = centdir[_CD_LOCAL_HEADER_OFFSET]
            (x.create_version, x.create_system, x.extract_version, x.reserved,
             x.flag_bits, x.compress_type, t, d,
             x.CRC, x.compress_size, x.file_size) = centdir[1:12]
            if x.extract_version > MAX_EXTRACT_VERSION:
                raise NotImplementedError("zip file version %.1f" %
                                          (x.extract_version / 10))
            x.volume, x.internal_attr, x.external_attr = centdir[15:18]
            # Convert date/time code to (year, month, day, hour, min, sec)
            x._raw_time = t
            x.date_time = ((d >> 9) + 1980, (d >> 5) & 0xF, d & 0x1F,
                           t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2)

            x._decodeExtra()
            x.header_offset = x.header_offset + concat
            self.filelist.append(x)
            self.NameToInfo[x.filename] = x

            # update total bytes read from central directory
            total = (total + sizeCentralDir + centdir[_CD_FILENAME_LENGTH]
                     + centdir[_CD_EXTRA_FIELD_LENGTH]
                     + centdir[_CD_COMMENT_LENGTH])

            if self.debug > 2:
                print("total", total)

    def namelist(self):
        """Return a list of file names in the archive."""
        return [data.filename for data in self.filelist]

    def infolist(self):
        """Return a list of class ZipInfo instances for files in the
        archive."""
        return self.filelist

    def printdir(self, file=None):
        """Print a table of contents for the zip file."""
        print("%-46s %19s %12s" % ("File Name", "Modified    ", "Size"),
              file=file)
        for zinfo in self.filelist:
            date = "%d-%02d-%02d %02d:%02d:%02d" % zinfo.date_time[:6]
            print("%-46s %s %12d" % (zinfo.filename, date, zinfo.file_size),
                  file=file)

    def testzip(self):
        """Read all the files and check the CRC."""
        chunk_size = 2 ** 20
        for zinfo in self.filelist:
            try:
                # Read by chunks, to avoid an OverflowError or a
                # MemoryError with very large embedded files.
                with self.open(zinfo.filename, "r") as f:
                    while f.read(chunk_size):  # Check CRC-32
                        pass
            except BadZipFile:
                return zinfo.filename

    def getinfo(self, name):
        """Return the instance of ZipInfo given 'name'."""
        info = self.NameToInfo.get(name)
        if info is None:
            raise KeyError(
                'There is no item named %r in the archive' % name)

        return info

    def setpassword(self, pinyin):
        """Set default password for encrypted files."""
        if pinyin and not isinstance(pinyin, bytes):
            raise TypeError("pinyin: expected bytes, got %s" % type(pinyin).__name__)
        if pinyin:
            self.pinyin = pinyin
        else:
            self.pinyin = None

    def setencryption(self, encryption, **kwargs):
        self.encryption = encryption
        self.encryption_kwargs = kwargs

    def get_encrypter(self):
        raise NotImplementedError("That encryption method is not supported")

    @property
    def comment(self):
        """The comment text associated with the ZIP file."""
        return self._comment

    @comment.setter
    def comment(self, comment):
        if not isinstance(comment, bytes):
            raise TypeError(
                "comment: expected bytes, got %s" % type(comment).__name__
            )
        # check for valid comment length
        if len(comment) > ZIP_MAX_COMMENT:
            import warnings
            warnings.warn('Archive comment is too long; truncating to %d bytes'
                          % ZIP_MAX_COMMENT, stacklevel=2)
            comment = comment[:ZIP_MAX_COMMENT]
        self._comment = comment
        self._didModify = True

    def read(self, name, pinyin=None):
        """Return file bytes (as a string) for name."""
        with self.open(name, "r", pinyin) as fp:
            return fp.read()

    def open(self, name, mode="r", pinyin=None, *, force_zip64=False):
        from .u import open_
        return open_(self, name, mode, pinyin=pinyin, force_zip64=force_zip64)

    def _open_to_read(self, mode, zinfo, pinyin):
        # Open for reading:
        self._fileRefCnt += 1
        zef_file = SharedFile_(self.fp, zinfo.header_offset,
                               self._fpclose, self._lock, lambda: self._writing)
        try:
            return self.zipextfile_cls(zef_file, mode, zinfo, True, pinyin)
        except Exception as e:
            zef_file.close()
            raise e

    def _open_to_write(self, zinfo, force_zip64=False, pinyin=None):
        if force_zip64 and not self._allowZip64:
            raise ValueError(
                "force_zip64 is True, but allowZip64 was False when opening "
                "the ZIP file."
            )
        if self._writing:
            raise ValueError("Can't write to the ZIP file while there is "
                             "another write handle open on it. "
                             "Close the first handle before opening another.")

        # Sizes and CRC are overwritten with correct data after processing the
        # file
        if not hasattr(zinfo, 'file_size'):
            zinfo.file_size = 0
        zinfo.compress_size = 0
        zinfo.CRC = 0

        zinfo.flag_bits = 0x00
        encrypter = None
        if pinyin is not None or self.encryption is not None:
            zinfo.flag_bits |= _MASK_ENCRYPTED
            encrypter = self.get_encrypter()
            encrypter.update_zipinfo(zinfo)
        if zinfo.compress_type == ZIP_LZMA:
            # Compressed data includes an end-of-stream (EOS) marker
            zinfo.flag_bits |= _MASK_COMPRESS_OPTION_1
        if not self._seekable:
            zinfo.flag_bits |= _MASK_USE_DATA_DESCRIPTOR

        if not zinfo.external_attr:
            zinfo.external_attr = 0o600 << 16  # permissions: ?rw-------

        # Compressed size can be larger than uncompressed size
        zip64 = self._allowZip64 and \
                (force_zip64 or zinfo.file_size * 1.05 > ZIP64_LIMIT)  # noqa: E127

        if self._seekable:
            self.fp.seek(self.start_dir)
        zinfo.header_offset = self.fp.tell()

        self._writecheck(zinfo)
        return self.zipwritefile_cls(self, zinfo, zip64, encrypter)

    def extract(self, member, path=None, pinyin=None):
        """Extract a member from the archive to the current working directory,
           using its full name. Its file information is extracted as accurately
           as possible. `member` may be a filename or a ZipInfo object. You can
           specify a different directory using `path`.
        """
        if path is None:
            path = os.getcwd()
        else:
            # os.fspath were added in python 3.6
            if sys.version_info[0:2] >= (3, 6):
                path = os.fspath(path)
            else:
                path = str(path)

        return self._extract_member(member, path, pinyin)

    def extractall(self, path=None, members=None, pinyin=None):
        """Extract all members from the archive to the current working
           directory. `path` specifies a different directory to extract to.
           `members` is optional and must be a subset of the list returned
           by namelist().
        """
        if members is None:
            members = self.namelist()

        if path is None:
            path = os.getcwd()
        else:
            # os.fspath were added in python 3.6
            if sys.version_info[0:2] >= (3, 6):
                path = os.fspath(path)
            else:
                path = str(path)

        for zipinfo in members:
            self._extract_member(zipinfo, path, pinyin)

    @classmethod
    def _sanitize_windows_name(cls, arcname, pathsep):
        """Replace bad characters and remove trailing dots from parts."""
        table = cls._windows_illegal_name_trans_table
        if not table:
            illegal = ':<>|"?*'
            table = str.maketrans(illegal, '_' * len(illegal))
            cls._windows_illegal_name_trans_table = table
        arcname = arcname.translate(table)
        # remove trailing dots
        arcname = (x.rstrip('.') for x in arcname.split(pathsep))
        # rejoin, removing empty parts.
        arcname = pathsep.join(x for x in arcname if x)
        return arcname

    def _extract_member(self, member, targetpath, pinyin):
        """Extract the ZipInfo object 'member' to a physical
           file on the path targetpath.
        """
        if not isinstance(member, self.zipinfo_cls):
            member = self.getinfo(member)

        # build the destination pathname, replacing
        # forward slashes to platform specific separators.
        arcname = member.filename.replace('/', os.path.sep)

        if os.path.altsep:
            arcname = arcname.replace(os.path.altsep, os.path.sep)
        # interpret absolute pathname as relative, remove drive letter or
        # UNC path, redundant separators, "." and ".." components.
        arcname = os.path.splitdrive(arcname)[1]
        invalid_path_parts = ('', os.path.curdir, os.path.pardir)
        arcname = os.path.sep.join(x for x in arcname.split(os.path.sep)
                                   if x not in invalid_path_parts)
        if os.path.sep == '\\':
            # filter illegal characters on Windows
            arcname = self._sanitize_windows_name(arcname, os.path.sep)

        targetpath = os.path.join(targetpath, arcname)
        targetpath = os.path.normpath(targetpath)

        # Create all upper directories if necessary.
        upperdirs = os.path.dirname(targetpath)
        if upperdirs and not os.path.exists(upperdirs):
            os.makedirs(upperdirs)

        if member.is_dir():
            if not os.path.isdir(targetpath):
                os.mkdir(targetpath)
            return targetpath

        with self.open(member, pinyin=pinyin) as source, \
                open(targetpath, "wb") as target:
            shutil.copyfileobj(source, target)

        return targetpath

    def _writecheck(self, zinfo):
        """Check for errors before writing a file to the archive."""
        if zinfo.filename in self.NameToInfo:
            import warnings
            warnings.warn('Duplicate name: %r' % zinfo.filename, stacklevel=3)
        if self.mode not in ('w', 'x', 'a'):
            raise ValueError("write() requires mode 'w', 'x', or 'a'")
        if not self.fp:
            raise ValueError(
                "Attempt to write ZIP archive that was already closed")
        check_compression_(zinfo.compress_type)
        if not self._allowZip64:
            requires_zip64 = None
            if len(self.filelist) >= ZIP_FILECOUNT_LIMIT:
                requires_zip64 = "Files count"
            elif zinfo.file_size > ZIP64_LIMIT:
                requires_zip64 = "Filesize"
            elif zinfo.header_offset > ZIP64_LIMIT:
                requires_zip64 = "Zipfile size"
            if requires_zip64:
                raise LargeZipFile(requires_zip64 +
                                   " would require ZIP64 extensions")

    def write(self, filename, arcname=None,
              compress_type=None, compresslevel=None):
        """Put the bytes from filename into the archive under the name
        arcname."""
        if not self.fp:
            raise ValueError(
                "Attempt to write to ZIP archive that was already closed")
        if self._writing:
            raise ValueError(
                "Can't write to ZIP archive while an open writing handle exists"
            )

        zinfo = self.zipinfo_cls.from_file(
            filename, arcname, strict_timestamps=self._strict_timestamps)

        if zinfo.is_dir():
            zinfo.compress_size = 0
            zinfo.CRC = 0
        else:
            if compress_type is not None:
                zinfo.compress_type = compress_type
            else:
                zinfo.compress_type = self.compression

            if compresslevel is not None:
                zinfo._compresslevel = compresslevel
            else:
                zinfo._compresslevel = self.compresslevel

        if zinfo.is_dir():
            with self._lock:
                if self._seekable:
                    self.fp.seek(self.start_dir)
                zinfo.header_offset = self.fp.tell()  # Start of header bytes
                if zinfo.compress_type == ZIP_LZMA:
                    # Compressed data includes an end-of-stream (EOS) marker
                    zinfo.flag_bits |= _MASK_COMPRESS_OPTION_1

                self._writecheck(zinfo)
                self._didModify = True

                self.filelist.append(zinfo)
                self.NameToInfo[zinfo.filename] = zinfo
                self.fp.write(zinfo.FileHeader(False))
                self.start_dir = self.fp.tell()
        else:
            with open(filename, "rb") as src, self.open(zinfo, 'w') as dest:
                shutil.copyfileobj(src, dest, 1024 * 8)

    def writestr(self, zinfo_or_arcname, data,
                 compress_type=None, compresslevel=None):
        """Write a file into the archive.  The contents is 'data', which
        may be either a 'str' or a 'bytes' instance; if it is a 'str',
        it is encoded as UTF-8 first.
        'zinfo_or_arcname' is either a ZipInfo instance or
        the name of the file in the archive."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not isinstance(zinfo_or_arcname, self.zipinfo_cls):
            zinfo = self.zipinfo_cls(
                filename=zinfo_or_arcname,
                date_time=time.localtime(time.time())[:6])
            zinfo.compress_type = self.compression
            zinfo._compresslevel = self.compresslevel
            if zinfo.filename[-1] == '/':
                zinfo.external_attr = 0o40775 << 16  # drwxrwxr-x
                zinfo.external_attr |= 0x10  # MS-DOS directory flag
            else:
                zinfo.external_attr = 0o600 << 16  # ?rw-------
        else:
            zinfo = zinfo_or_arcname

        if not self.fp:
            raise ValueError(
                "Attempt to write to ZIP archive that was already closed")
        if self._writing:
            raise ValueError(
                "Can't write to ZIP archive while an open writing handle exists."
            )

        if compress_type is not None:
            zinfo.compress_type = compress_type

        if compresslevel is not None:
            zinfo._compresslevel = compresslevel

        zinfo.file_size = len(data)  # Uncompressed size
        with self._lock:
            with self.open(zinfo, mode='w') as dest:
                dest.write(data)

    def __del__(self):
        """Call the "close()" method in case the user forgot."""
        self.close()

    def close(self):
        """Close the file, and for mode 'w', 'x' and 'a' write the ending
        records."""
        if self.fp is None:
            return

        if self._writing:
            raise ValueError("Can't close the ZIP file while there is "
                             "an open writing handle on it. "
                             "Close the writing handle before closing the zip.")

        try:
            if self.mode in ('w', 'x', 'a') and self._didModify:  # write ending records
                with self._lock:
                    if self._seekable:
                        self.fp.seek(self.start_dir)
                    self._write_end_record()
        finally:
            fp = self.fp
            self.fp = None
            self._fpclose(fp)

    def _write_end_record(self):
        for zinfo in self.filelist:  # write central directory
            centdir, filename, extra_data = zinfo.central_directory()
            self.fp.write(centdir)
            self.fp.write(filename)
            self.fp.write(extra_data)
            self.fp.write(zinfo.comment)

        pos2 = self.fp.tell()
        # Write end-of-zip-archive record
        centDirCount = len(self.filelist)
        centDirSize = pos2 - self.start_dir
        centDirOffset = self.start_dir
        requires_zip64 = None
        if centDirCount > ZIP_FILECOUNT_LIMIT:
            requires_zip64 = "Files count"
        elif centDirOffset > ZIP64_LIMIT:
            requires_zip64 = "Central directory offset"
        elif centDirSize > ZIP64_LIMIT:
            requires_zip64 = "Central directory size"
        if requires_zip64:
            # Need to write the ZIP64 end-of-archive records
            if not self._allowZip64:
                raise LargeZipFile(requires_zip64 +
                                   " would require ZIP64 extensions")
            zip64endrec = struct.pack(
                structEndArchive64, stringEndArchive64,
                44, 45, 45, 0, 0, centDirCount, centDirCount,
                centDirSize, centDirOffset)
            self.fp.write(zip64endrec)

            zip64locrec = struct.pack(
                structEndArchive64Locator,
                stringEndArchive64Locator, 0, pos2, 1)
            self.fp.write(zip64locrec)
            centDirCount = min(centDirCount, 0xFFFF)
            centDirSize = min(centDirSize, 0xFFFFFFFF)
            centDirOffset = min(centDirOffset, 0xFFFFFFFF)

        endrec = struct.pack(structEndArchive, stringEndArchive,
                             0, 0, centDirCount, centDirCount,
                             centDirSize, centDirOffset, len(self._comment))
        self.fp.write(endrec)
        self.fp.write(self._comment)
        self.fp.flush()

    def _fpclose(self, fp):
        assert self._fileRefCnt > 0
        self._fileRefCnt -= 1
        if not self._fileRefCnt and not self._filePassed:
            fp.close()


class AESZipDecrypter(BaseZipDecrypter):
    hmac_size = 10

    def __init__(self, zinfo, pinyin, encryption_header):
        self.filename = zinfo.filename

        key_length = WZ_KEY_LENGTHS[zinfo.wz_aes_strength]
        salt_length = WZ_SALT_LENGTHS[zinfo.wz_aes_strength]

        salt = struct.unpack(
            "<{}s".format(salt_length),
            encryption_header[:salt_length]
        )[0]
        pwd_verify_length = 2
        pwd_verify = encryption_header[salt_length:]
        dkLen = 2 * key_length + pwd_verify_length
        keymaterial = PBKDF2(pinyin, salt, count=1000, dkLen=dkLen)

        encpwdverify = keymaterial[2 * key_length:]
        if encpwdverify != pwd_verify:
            raise RuntimeError("Bad password for file %r" % zinfo.filename)

        enckey = keymaterial[:key_length]
        self.decypter = AES.new(
            enckey,
            AES.MODE_CTR,
            counter=Counter.new(nbits=128, little_endian=True)
        )
        encmac_key = keymaterial[key_length:2 * key_length]
        self.hmac = HMAC.new(encmac_key, digestmod=SHA1Hash())

    @staticmethod
    def encryption_header_length(zinfo):
        # salt_length + pwd_verify_length
        salt_length = WZ_SALT_LENGTHS[zinfo.wz_aes_strength]
        return salt_length + 2

    def decrypt(self, data):
        self.hmac.update(data)
        return self.decypter.decrypt(data)

    def check_hmac(self, hmac_check):
        if self.hmac.digest()[:10] != hmac_check:
            raise BadZipFile("Bad HMAC check for file %r" % self.filename)


class AESZipInfo(ZipInfo):
    """Class with attributes describing each file in the ZIP archive."""

    # __slots__ on subclasses only need to contain the additional slots.
    __slots__ = (
        'wz_aes_version',
        'wz_aes_vendor_id',
        'wz_aes_strength',
        # 'wz_aes_actual_compression_type',
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.wz_aes_version = None
        self.wz_aes_vendor_id = None
        self.wz_aes_strength = None

    def decode_extra_wz_aes(self, ln, extra):
        if ln == 7:
            counts = struct.unpack("<H2sBH", extra[4: ln + 4])
        else:
            raise BadZipFile(
                "Corrupt extra field %04x (size=%d)" % (EXTRA_WZ_AES, ln))

        self.wz_aes_version = counts[0]
        self.wz_aes_vendor_id = counts[1]
        # 0x01  128-bit encryption key
        # 0x02  192-bit encryption key
        # 0x03  256-bit encryption key
        self.wz_aes_strength = counts[2]

        # the compression method is the one that would otherwise have been
        # stored in the local and central headers for the file. For example, if
        # the file is imploded, this field will contain the compression code 6.
        # This is needed because a compression method of 99 is used to indicate
        # the presence of an AES-encrypted file
        self.compress_type = counts[3]
        # self.wz_aes_actual_compression_type = counts[3]

    def get_extra_decoders(self):
        extra_decoders = super().get_extra_decoders()
        extra_decoders[EXTRA_WZ_AES] = self.decode_extra_wz_aes
        return extra_decoders

    def encode_extra(self, crc, compress_type):
        wz_aes_extra = b''
        if self.wz_aes_vendor_id is not None:
            compress_type = WZ_AES_COMPRESS_TYPE
            aes_version = self.wz_aes_version
            if aes_version is None:
                if self.file_size < 20 | self.compress_type == ZIP_BZIP2:
                    # The only difference between version 1 and 2 is the
                    # handling of the CRC values. For version 2 the CRC value
                    # is not used and must be set to 0.
                    # For small files, the CRC files can leak the contents of
                    # the encrypted data.
                    # For bzip2, the compression already has integrity checks
                    # so CRC is not required.
                    aes_version = WZ_AES_V2
                else:
                    aes_version = WZ_AES_V1

            if aes_version == WZ_AES_V2:
                crc = 0

            wz_aes_extra = struct.pack(
                "<3H2sBH",
                EXTRA_WZ_AES,
                7,  # extra block body length: H2sBH
                aes_version,
                self.wz_aes_vendor_id,
                self.wz_aes_strength,
                self.compress_type,
            )
        return wz_aes_extra, crc, compress_type

    def encode_local_header(self, *, crc, compress_type, extra, **kwargs):
        wz_aes_extra, crc, compress_type = self.encode_extra(
            crc, compress_type)
        return super().encode_local_header(
            crc=crc,
            compress_type=compress_type,
            extra=extra + wz_aes_extra,
            **kwargs
        )

    def encode_central_directory(self, *, crc, compress_type, extra_data,
                                 **kwargs):
        wz_aes_extra, crc, compress_type = self.encode_extra(
            crc, compress_type)
        return super().encode_central_directory(
            crc=crc,
            compress_type=compress_type,
            extra_data=extra_data + wz_aes_extra,
            **kwargs)


class AESZipExtFile(ZipExtFile):

    def setup_aeszipdecrypter(self):
        if not self._pwd:
            raise RuntimeError(
                'File %r is encrypted with %s encryption and requires a '
                'password.' % (self.name, WZ_AES)
            )
        encryption_header_length = AESZipDecrypter.encryption_header_length(
            self._zinfo)
        self.encryption_header = self._fileobj.read(encryption_header_length)
        # Adjust read size for encrypted files since the start of the file
        # may be used for the encryption/password information.
        self._orig_compress_left -= encryption_header_length
        # Also remove the hmac length from the end of the file.
        self._orig_compress_left -= AESZipDecrypter.hmac_size

        return AESZipDecrypter

    def setup_decrypter(self):
        if self._zinfo.wz_aes_version is not None:
            return self.setup_aeszipdecrypter()
        return super().setup_decrypter()

    def check_wz_aes(self):
        if self._zinfo.compress_type == ZIP_LZMA:
            # LZMA may have an end of stream marker or padding. Make sure we
            # read that to get the proper HMAC of the compressed byte stream.
            while self._compress_left > 0:
                data = self._read2(self.MIN_READ_SIZE)
                # but we don't want to find any more data here.
                data = self._decompressor.decompress(data)
                if data:
                    raise BadZipFile(
                        "More data found than indicated by uncompressed size for "
                        "'{}'".format(self.filename)
                    )

        hmac_check = self._fileobj.read(self._decrypter.hmac_size)
        self._decrypter.check_hmac(hmac_check)

    def check_integrity(self):
        if self._zinfo.wz_aes_version is not None:
            self.check_wz_aes()
            if self._expected_crc is not None and self._expected_crc != 0:
                # Not part of the spec but still check the CRC if it is
                # supplied when WZ_AES_V2 is specified (no CRC check and CRC
                # should be 0).
                self.check_crc()
            elif self._zinfo.wz_aes_version != WZ_AES_V2:
                # CRC value should be 0 for AES vendor version 2.
                self.check_crc()
        else:
            super().check_integrity()
