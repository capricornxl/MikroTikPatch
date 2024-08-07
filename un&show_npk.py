import subprocess
import struct, zlib
import hashlib
from datetime import datetime
from dataclasses import dataclass
from enum import IntEnum


class NpkPartID(IntEnum):
    PART_INFO = 0x01  # Package information: name, ver, etc.
    PART_DESCRIPTION = 0x02  # Package description
    DEPENDENCIES = 0x03  # Package Dependencies
    FILE_CONTAINER = 0x04  # Files container zlib 1.2.3
    INSTALL_SCRIPT = 0x07  # Install script
    UNINSTALL_SCRIPT = 0x08  # Uninstall script
    SIGNATURE = 0x09  # Package signature
    ARCHITECTURE = 0x10  # Package architecture (e.g. i386)
    PKG_CONFLICTS = 0x11  # Package conflicts
    PKG_INFO = 0x12
    PART_FEATURES = 0x13
    PKG_FEATURES = 0x14
    SQUASHFS = 0x15  # SquashFS
    ZERO_PADDING = 0X16
    GIT_COMMIT = 0x17  # Git commit
    CHANNEL = 0x18  # Release type (e.g. stable, testing, etc.)
    HEADER = 0x19


@dataclass
class NpkPartItem:
    id: NpkPartID
    offset: int
    data: bytes | object


class NpkInfo:
    _format = '<16s4sI8s'

    def __init__(self, name: str, version: str, build_time=datetime.now(), unknow=b'\x00' * 8):
        self._name = name[:16].encode().ljust(16, b'\x00')
        self._version = self.encode_version(version)
        self._build_time = int(build_time.timestamp())
        self._unknow = unknow

    def serialize(self) -> bytes:
        return struct.pack(self._format, self._name, self._version, self._build_time, self._unknow)

    @staticmethod
    def unserialize_from(data: bytes) -> 'NpkInfo':
        assert len(data) == struct.calcsize(NpkInfo._format), 'Invalid data length'
        _name, _version, _build_time, unknow = struct.unpack_from(NpkInfo._format, data)
        return NpkInfo(_name.decode(), NpkInfo.decode_version(_version), datetime.fromtimestamp(_build_time), unknow)

    def __len__(self) -> int:
        return struct.calcsize(self._format)

    @property
    def name(self) -> str:
        return self._name.decode().strip('\x00')

    @name.setter
    def name(self, value: str):
        self._name = value[:16].encode().ljust(16, b'\x00')

    @staticmethod
    def decode_version(value: bytes):
        revision, build, minor, major = struct.unpack_from('4B', value)
        if build == 97:
            build = 'alpha'
        elif build == 98:
            build = 'beta'
        elif build == 99:
            build = 'rc'
        elif build == 102:
            if revision & 0x80:
                build = 'test'
                revision &= 0x7f
            else:
                build = 'final'
        else:
            build = 'unknown'
        return f'{major}.{minor}.{revision}.{build}'

    @staticmethod
    def encode_version(value: str):
        s = value.split('.')
        if 4 != len(s) and s[3] in ['alpha', 'beta', 'rc', 'final', 'test']:
            raise ValueError('Invalid version string')
        major = int(s[0])
        minor = int(s[1])
        revision = int(s[2])
        if s[3] == 'alpha':
            build = 97
        elif s[3] == 'beta':
            build = 98
        elif s[3] == 'rc':
            build = 99
        elif s[3] == 'final':
            build = 102
            revision &= 0x7f
        else:  # 'test'
            build = 102
            revision |= 0x80
        return struct.pack('4B', revision, build, minor, major)

    @property
    def version(self) -> str:
        return self.decode_version(self._version)

    @version.setter
    def version(self, value: str = '7.15.1.final'):
        self._version = self.encode_version(value)

    @property
    def build_time(self):
        return datetime.fromtimestamp(self._build_time)

    @build_time.setter
    def build_time(self, value: datetime):
        self._build_time = int(value.timestamp())


class NpkNameInfo(NpkInfo):
    _format = '<16s4sI12s'

    def __init__(self, name: str, version: str, build_time=datetime.now(), unknow=b'\x00' * 12):
        super().__init__(name, version, build_time, unknow)
        self._name = name[:16].encode().ljust(16, b'\x00')
        self._version = self.encode_version(version)
        self._build_time = int(build_time.timestamp())
        self._unknow = unknow

    def serialize(self) -> bytes:
        return struct.pack(self._format, self._name, self._version, self._build_time, self._unknow)

    @staticmethod
    def unserialize_from(data: bytes) -> 'NpkNameInfo':
        assert len(data) == struct.calcsize(NpkNameInfo._format), 'Invalid data length'
        _name, _version, _build_time, _unknow = struct.unpack_from(NpkNameInfo._format, data)
        return NpkNameInfo(_name.decode(), NpkNameInfo.decode_version(_version), datetime.fromtimestamp(_build_time),
                           _unknow)


class NpkFileContainer:
    _format = '<BB6sIBBBBIIIH'

    @dataclass
    class NpkFileItem:
        perm: int
        type: int
        usr_or_grp: int
        modify_time: int
        revision: int
        rc: int
        minor: int
        major: int
        create_time: int
        unknow: int
        name: bytes
        data: bytes

    def __init__(self, items: list['NpkFileContainer.NpkFileItem'] = None):
        self._items = items

    def serialize(self) -> bytes:
        compressed_data = b''
        compressor = zlib.compressobj()
        for item in self._items:
            data = struct.pack(self._format, item.perm, item.type, item.usr_or_grp, item.modify_time, item.revision,
                               item.rc, item.minor, item.major, item.create_time, item.unknow, len(item.data),
                               len(item.name))
            data += item.name + item.data
            compressed_data += compressor.compress(data)
        return compressed_data + compressor.flush()

    @staticmethod
    def unserialize_from(data: bytes):
        items: list['NpkFileContainer.NpkFileItem'] = []
        decompressed_data = zlib.decompress(data)
        while len(decompressed_data):
            offset = struct.calcsize(NpkFileContainer._format)
            perm, type, usr_or_grp, modify_time, revision, rc, minor, major, create_time, unknow, data_size, name_size = struct.unpack_from(
                NpkFileContainer._format, decompressed_data)
            name = decompressed_data[offset:offset + name_size]
            data = decompressed_data[offset + name_size:offset + name_size + data_size]
            items.append(NpkFileContainer.NpkFileItem(perm, type, usr_or_grp, modify_time, revision, rc, minor, major,
                                                      create_time, unknow, name, data))
            decompressed_data = decompressed_data[offset + name_size + data_size:]
        return NpkFileContainer(items)

    def __len__(self) -> int:
        return len(self.serialize())

    def __getitem__(self, index: int) -> 'NpkFileContainer.NpkFileItem':
        return self._items[index]

    def __iter__(self):
        for item in self._items:
            yield item


class Package:
    def __init__(self) -> None:
        self._parts: list[NpkPartItem] = []

    def __iter__(self):
        for part in self._parts:
            yield part

    def __getitem__(self, id: NpkPartID):
        for part in self._parts:
            if part.id == id:
                return part
        part = NpkPartItem(id, 0, b'')
        self._parts.append(part)
        return part


class NovaPackage(Package):
    NPK_MAGIC = 0xbad0f11e

    def __init__(self, data: bytes = b''):
        super().__init__()
        self._packages: list[Package] = []
        offset = 0
        self._has_pkg = False
        while offset < len(data):
            part_id, part_size = struct.unpack_from('<HI', data, offset)
            offset += 6
            part_data = data[offset:offset + part_size]
            offset += part_size
            if part_id == NpkPartID.PKG_FEATURES:
                self._has_pkg = True
                self._parts.append(NpkPartItem(NpkPartID(part_id), offset, part_data))
                continue
            if self._has_pkg:
                if part_id == NpkPartID.PART_INFO:
                    self._packages.append(Package())
                    self._packages[-1]._parts.append(
                        NpkPartItem(NpkPartID(part_id), offset, NpkNameInfo.unserialize_from(part_data)))
                else:
                    self._packages[-1]._parts.append(NpkPartItem(NpkPartID(part_id), offset, part_data))
            else:
                if part_id == NpkPartID.PART_INFO:
                    self._parts.append(NpkPartItem(NpkPartID(part_id), offset, NpkNameInfo.unserialize_from(part_data)))
                elif part_id == NpkPartID.PKG_INFO:
                    self._parts.append(NpkPartItem(NpkPartID(part_id), offset, NpkInfo.unserialize_from(part_data)))
                else:
                    self._parts.append(NpkPartItem(NpkPartID(part_id), offset, part_data))


def run_shell_command(command):
    process = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.stdout, process.stderr


def printBytes(val):
    for i in range(len(val) // 16):
        print(''.join('{:02x} '.format(x) for x in val[i*16:i*16+16]))


class MyNovaPackage(NovaPackage):
    NPK_MAGIC = 0xbad0f11e

    def __init__(self, data: bytes = b''):
        super().__init__(data)

    def display_info(self):
        all_info = {}
        for part in self._parts:
            info = [f"\n(Id: {part.id}), size = {len(part.data)}, offset = {part.offset}"]
            if part.id == NpkPartID.PART_INFO:
                name_info = part.data
                info.append("\t=>Part Info:")
                info.append(f"\t\tName: {name_info.name}")
                info.append(f"\t\tVersion: {name_info.version}")
                info.append(f"\t\tBuild Time: {name_info.build_time}")
            elif part.id == NpkPartID.FILE_CONTAINER:
                info.append(f"\t=>Files container:")
                file_container = NpkFileContainer.unserialize_from(part.data)
                for item in file_container:
                    info.append(f"\t\t{item.name.decode()}")
            elif part.id == NpkPartID.SQUASHFS:
                squashfs_file = '.squashfs-root.sfs'
                extract_dir = '.squashfs-root'
                run_shell_command(f'rm -rf {extract_dir} {squashfs_file}')
                info.append(f"\t=>Squashfs Dir:")
                open(squashfs_file, 'wb').write(part.data)
                stdout, stderr = run_shell_command(f"unsquashfs -d {extract_dir} {squashfs_file}")
                if stderr.decode().strip():
                    print(stderr.decode())
                stdout, stderr = run_shell_command(f"ls {extract_dir}/")
                info.append("\t\t" + "\n\t\t".join([f"/{line}" for line in stdout.decode().strip().split("\n")]))
            elif part.id == NpkPartID.PART_DESCRIPTION:
                info.append(f"\t=>Part Description: {part.data.decode()}")
            elif part.id == NpkPartID.DEPENDENCIES:
                info.append(f"\t=>Dependencies: {part.data.decode() if part.data.decode() else None}")
            elif part.id == NpkPartID.INSTALL_SCRIPT:
                info.append(f"\t=>Install Script: {part.data.decode()}")
            elif part.id == NpkPartID.UNINSTALL_SCRIPT:
                info.append(f"\t=>Uninstall Script: {part.data.decode()}")
            elif part.id == NpkPartID.PKG_CONFLICTS:
                info.append(f"\t=>Package Conflicts: {part.data.decode()}")
            elif part.id == NpkPartID.PKG_INFO:
                pkg_info = part.data
                info.append(f"\t=>Package Info:")
                info.append(f"\t\tName: {pkg_info.name}")
                info.append(f"\t\tVersion: {pkg_info.version}")
                info.append(f"\t\tBuild Time: {pkg_info.build_time}")
            elif part.id == NpkPartID.PART_FEATURES:
                info.append(f"\t=>Part Features: {part.data.decode()}")
            elif part.id == NpkPartID.ARCHITECTURE:
                info.append(f"\t=>Architecture: {part.data.decode()}")
            elif part.id == NpkPartID.PKG_FEATURES:
                info.append(f"\t=>Package Features: {part.data.decode()}")
            elif part.id == NpkPartID.GIT_COMMIT:
                info.append(f"\t=>Git Commit: {part.data.decode()}")
            elif part.id == NpkPartID.CHANNEL:
                info.append(f"\t=>Channel: {part.data.decode()}")
            elif part.id == NpkPartID.HEADER:
                info.append(f"\t=>Header: {part.data.decode() if part.data.decode() else None}")
            elif part.id == NpkPartID.SIGNATURE:
                info.append("\t=>Signature:")
                try:
                    signature = part.data.decode('utf-8')
                    info.append(f"\t\tSignature Str: {signature.upper()}")
                except UnicodeDecodeError:
                    signature = part.data.hex()
                    info.append(f"\t\tSignature Hex: {signature.upper()}")
            elif part.id == NpkPartID.ZERO_PADDING:
                info.append(f"\t=>Zero Padding: No display required")

            all_info.update({int(part.id): info})
        sort_keys = sorted(all_info.keys())
        new_list = []
        for key in sort_keys:
            new_list.extend(all_info.get(key))
        return "\n".join(new_list)

    @staticmethod
    def load(file):
        with open(file, 'rb') as f:
            data = f.read()
        assert int.from_bytes(data[:4], 'little') == NovaPackage.NPK_MAGIC, 'Invalid Nova Package Magic'
        assert int.from_bytes(data[4:8], 'little') == len(data) - 8, 'Invalid Nova Package Size'
        return MyNovaPackage(data[8:])


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='nova package show and unpackage')
    subparsers = parser.add_subparsers(dest="command")
    show_parser = subparsers.add_parser('show', help='Show npk file')
    show_parser.add_argument('input', type=str, help='Input file')
    unpkg_parser = subparsers.add_parser('unpkg', help='Unpackage npk file')
    unpkg_parser.add_argument('input', type=str, help='From npk file')
    unpkg_parser.add_argument('output', type=str, help='Output file')
    args = parser.parse_args()

    if args.command == 'show':
        npk = MyNovaPackage.load(args.input)
        print(f'Show [{args.input}], it take a while...')
        print(npk.display_info())
    elif args.command == 'unpkg':
        print(f'Creating {args.output} from {args.input}, it take a while...')
        option_npk = MyNovaPackage.load(args.input)
        print(f'Unpackage {args.output}')
    else:
        parser.print_help()
