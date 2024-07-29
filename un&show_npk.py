
import subprocess,lzma
from npk import NovaPackage, NpkPartID, NpkFileContainer, NpkPartItem


def run_shell_command(command):
    process = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.stdout, process.stderr


class MyNovaPackage(NovaPackage):
    NPK_MAGIC = 0xbad0f11e
    def __init__(self, data: bytes = b''):
        super().__init__(data)

    def display_info(self):
        info = []
        for part in self._parts:
            if part.id == NpkPartID.NAME_INFO:
                name_info = part.data
                info.append(f"\tName: {name_info.name}")
                info.append(f"\tVersion: {name_info.version}")
                info.append(f"\tBuild Time: {name_info.build_time}")

            elif part.id == NpkPartID.FILE_CONTAINER:
                info.append(f"\tFiles container:")
                file_container = NpkFileContainer.unserialize_from(part.data)
                for item in file_container:
                    info.append(f"\t\t{item.name.decode()}")

            elif part.id == NpkPartID.SQUASHFS:
                squashfs_file = '.squashfs-root.sfs'
                extract_dir = '.squashfs-root'
                info.append(f"\tFiles SquashFS:")
                open(squashfs_file, 'wb').write(part.data)
                _, stderr = run_shell_command(f"unsquashfs -d {extract_dir} {squashfs_file}")
                print(stderr.decode())

            elif part.id == NpkPartID.DESCRIPTION:
                info.append(f"\tDescription: {part.data.decode()}")
            elif part.id == NpkPartID.DEPENDENCIES:
                info.append(f"\tDependencies: {part.data.decode()}")
            elif part.id == NpkPartID.INSTALL_SCRIPT:
                info.append(f"\tInstall Script: {part.data.decode()}")
            elif part.id == NpkPartID.UNINSTALL_SCRIPT:
                info.append(f"\tUninstall Script: {part.data.decode()}")
            elif part.id == NpkPartID.PKG_CONFLICTS:
                info.append(f"\tPackage Conflicts: {part.data.decode()}")
            elif part.id == NpkPartID.PKG_INFO:
                info.append(f"\tPackage Info: {part.data.decode()}")
            elif part.id == NpkPartID.FEATURES:
                info.append(f"\tFeatures: {part.data.decode()}")
            elif part.id == NpkPartID.PKG_FEATURES:
                info.append(f"\tPackage Features: {part.data.decode()}")
            elif part.id == NpkPartID.GIT_COMMIT:
                info.append(f"\tGit Commit: {part.data.decode()}")
            elif part.id == NpkPartID.CHANNEL:
                info.append(f"\tChannel: {part.data.decode()}")
            elif part.id == NpkPartID.HEADER:
                info.append(f"\tHeader: {part.data.decode()}")


        return "\n".join(info)

    @staticmethod
    def load(file):
        with open(file, 'rb') as f:
            data = f.read()
        assert int.from_bytes(data[:4], 'little') == NovaPackage.NPK_MAGIC, 'Invalid Nova Package Magic'
        assert int.from_bytes(data[4:8], 'little') == len(data) - 8, 'Invalid Nova Package Size'
        return MyNovaPackage(data[8:])


if __name__=='__main__':
    import argparse,os
    parser = argparse.ArgumentParser(description='nova package creator and editor')
    subparsers = parser.add_subparsers(dest="command")
    verify_parser = subparsers.add_parser('show',help='Show npk file')
    verify_parser.add_argument('input',type=str, help='Input file')
    create_option_parser = subparsers.add_parser('unpkg',help='Unpackage npk file')
    create_option_parser.add_argument('input',type=str,help='From npk file')
    create_option_parser.add_argument('output',type=str,help='Output file')
    args = parser.parse_args()

    if args.command == 'show':
        npk = MyNovaPackage.load(args.input)
        print(f'Show [{args.input}]')
        print(npk.display_info())
    elif args.command =='unpkg':
        print(f'Creating {args.output} from {args.input}')
        option_npk = MyNovaPackage.load(args.input)
        print(f'Unpackage {args.output}')
    else:
        parser.print_help()