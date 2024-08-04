#!/usr/bin/python
#
# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
import tarfile
__metaclass__ = type


DOCUMENTATION = '''
---
module: docker_container_copy_out

short_description: Copy a file from a Docker container to the managed node.

version_added: 3.4.0

description:
  - Copy a file from a Docker container to the managed node.
  - Similar to C(docker cp).

attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
    details:
      - Additional data will need to be transferred to compute diffs.
      - The module uses R(the MAX_FILE_SIZE_FOR_DIFF ansible-core configuration,MAX_FILE_SIZE_FOR_DIFF)
        to determine for how large files diffs should be computed.

options:
  container:
    description:
      - The name of the container to copy files from.
    type: str
    required: true
  path:
    description:
      - Path to a file on the managed node.
    type: path
  container_path:
    description:
      - Path to a file inside the Docker container.
      - Must be an absolute path.
    type: str
    required: true
  follow:
    description:
      - This flag indicates that if O(container_path) is a symlink in the container, it should be followed.
      - Note that if O(container_path) is a directory or a symlink to a directory, this does not apply recursively.
      - In this way, behavior is similar to C(docker cp).
    type: bool
    default: false
  local_follow:
    description:
      - That flag indicates that if O(path) is a symlink on the managed filesystem, it should be followed.
      - Note that if O(managed_path) is a directory or a symlink to a directory, this does not apply recursively.
      - In this way, behavior is similar to C(docker cp).
    type: bool
    default: true
  archive_mode:
    description:
      - This flag indicates that the file should be copied out of the container in archive mode.
      - If set to V(true), the module will copy the file out of the container in archive mode.
      - If set to V(false), the module will copy the file out of the container in regular mode.
      - If this option is not specified, the module will default to V(false).
    type: bool
    default: false
    notes:
        - By default, files copied to the local machine are created with the UID:GID of the user which invoked command.
        - However, if you specify C(true) for O(archive_mode), this attempts to set the ownership to the user and primary group at the source.
        - If you specify O(archive_mode), will likely need to specify O(become) as c(true) because only root user can change ownership.
  owner_id:
    description:
      - The owner ID to use when writing the file to disk.
      - If not provided, the module will default to the current user's UID, unless O(archive_mode) is C(true).
    type: int
  group_id:
    description:
      - The group ID to use when writing the file to disk.
      - If not provided, the module will default to the current user's GID, unless O(archive_mode) is C(true).
    type: int
  mode:
    description:
      - The file mode to use when writing the file to disk.
      - For those used to /usr/bin/chmod remember that modes are actually octal numbers.
      - You must give Ansible enough information to parse them correctly.
      - For consistent results, quote octal numbers (for example, '644' or '1777') so Ansible receives a string and can do its own conversion from string into number.
      - Adding a leading zero (for example, 0755) works sometimes, but can fail in loops and some other circumstances.
      - Giving Ansible a number without following either of these rules will end up with a decimal number which will have unexpected results.
    type: any
  force:
    description:
      - If set to V(true), force writing the file (without performing any idempotency checks).
      - If set to V(false), only write the file if it does not exist on the target. If a filesystem object exists at
        the destination, the module will not do any change.
      - If this option is not specified, the module will be idempotent. To verify idempotency, it will try to get information
        on the filesystem object in the container, and if everything seems to match will download the file from the container
        to compare it to the file to upload.
    type: bool

extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

author:
  - "Andrew Dawes (@AndrewJDawes)"

requirements:
  - "Docker API >= 1.25"
'''

EXAMPLES = '''
- name: Copy a file out of a container
    community.docker.docker_container_copy_out:
        container: mydata
        path: /tmp/test_out.txt
        container_path: /tmp/test.txt

- name: Copy a file out of a container with owner, group, and mode set
  community.docker.docker_container_copy_out:
    container: mydata
    path: /tmp/test_out.txt
    container_path: /tmp/test.txt
    owner_id: 0  # root
    group_id: 0  # root
    mode: 0o755  # readable and executable by all users, writable by root
'''

RETURN = '''
changed:
    description:
        - Indicates whether the file was copied.
    type: bool
failed:
    description:
        - Indicates whether the module failed.
    type: bool
container_path:
    description:
        - The path of the file in the container.
    type: str
managed_path:
    description:
        - The path of the file on the managed node.
    type: path
mode:
    description:
        - The file mode of the copied file.
    type: int
owner_id:
    description:
        - The owner ID of the copied file.
    type: int
group_id:
    description:
        - The group ID of the copied file.
    type: int
'''

import base64
import io
import os
import stat
import traceback

from ansible.module_utils._text import to_bytes, to_native, to_text

from ansible_collections.community.docker.plugins.module_utils._api.errors import APIError, DockerException, NotFound

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException,
)

from ansible_collections.community.docker.plugins.module_utils.copy import (
    DockerFileCopyError,
    DockerFileNotFound,
    DockerUnexpectedError,
    _stream_generator_to_fileobj,
    fetch_file,
    fetch_file_ex,
    stat_data_mode_is_symlink,
    stat_file,
    stat_file_ex,
    stat_file_resolve_symlinks,
)

from ansible_collections.community.docker.plugins.module_utils._scramble import generate_insecure_key, scramble

import datetime

from inspect import currentframe

def get_current_line_number():
    cf = currentframe()
    return cf.f_back.f_lineno

def log(module, msg):
    # Get a timestamp
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    timestamped_msg = f'{timestamp}: docker_container_copy_out: {msg}'
    module.log(timestamped_msg)

# https://pkg.go.dev/io/fs#FileMode
CONTAINER_MODE_BIT_DIR = 1
CONTAINER_MODE_BIT_TEMPORARY = 4
CONTAINER_MODE_BIT_SYMLINK = 5
CONTAINER_MODE_BIT_DEVICE = 6
CONTAINER_MODE_BIT_NAMED_PIPE = 7
CONTAINER_MODE_BIT_SOCKET = 8
CONTAINER_MODE_BIT_CHAR_DEVICE = 11
CONTAINER_MODE_BIT_IRREGULAR = 13

def container_mode_is(mode, container_mode_bit):
    if not isinstance(mode, int):
        raise ValueError(f'mode must be instance of int')
    if not isinstance(container_mode_bit, int):
        raise ValueError(f'container_mode_bit must be instance of int')
    return mode & (1 << (32 - container_mode_bit)) != 0

def container_mode_is_regular(mode):
    return not (
        container_mode_is_dir(mode)
        or container_mode_is_temporary(mode)
        or container_mode_is_symlink(mode)
        or container_mode_is_device(mode)
        or container_mode_is_named_pipe(mode)
        or container_mode_is_socket(mode)
        or container_mode_is_char_device(mode)
        or container_mode_is_irregular(mode)
    )

def container_mode_is_dir(mode):
    return container_mode_is(mode, CONTAINER_MODE_BIT_DIR)

def container_mode_is_temporary(mode):
    return container_mode_is(mode, CONTAINER_MODE_BIT_TEMPORARY)

def container_mode_is_symlink(mode):
    return container_mode_is(mode, CONTAINER_MODE_BIT_SYMLINK)

def container_mode_is_device(mode):
    return container_mode_is(mode, CONTAINER_MODE_BIT_DEVICE)

def container_mode_is_named_pipe(mode):
    return container_mode_is(mode, CONTAINER_MODE_BIT_NAMED_PIPE)

def container_mode_is_socket(mode):
    return container_mode_is(mode, CONTAINER_MODE_BIT_SOCKET)

def container_mode_is_char_device(mode):
    return container_mode_is(mode, CONTAINER_MODE_BIT_CHAR_DEVICE)

def container_mode_is_irregular(mode):
    return container_mode_is(mode, CONTAINER_MODE_BIT_IRREGULAR)


def are_fileobjs_equal(f1, f2):
    '''Given two (buffered) file objects, compare their contents.'''
    blocksize = 65536
    b1buf = b''
    b2buf = b''
    while True:
        if f1 and len(b1buf) < blocksize:
            f1b = f1.read(blocksize)
            if not f1b:
                # f1 is EOF, so stop reading from it
                f1 = None
            b1buf += f1b
        if f2 and len(b2buf) < blocksize:
            f2b = f2.read(blocksize)
            if not f2b:
                # f2 is EOF, so stop reading from it
                f2 = None
            b2buf += f2b
        if not b1buf or not b2buf:
            # At least one of f1 and f2 is EOF and all its data has
            # been processed. If both are EOF and their data has been
            # processed, the files are equal, otherwise not.
            return not b1buf and not b2buf
        # Compare the next chunk of data, and remove it from the buffers
        buflen = min(len(b1buf), len(b2buf))
        if b1buf[:buflen] != b2buf[:buflen]:
            return False
        b1buf = b1buf[buflen:]
        b2buf = b2buf[buflen:]


def stat_container_file(client, container, in_path):
    """Fetch information on a file from a Docker container.

    :param client: Docker client
    :type client: APIClient
    :param container: Container ID
    :type container: str
    :param in_path: Path to the file in the container
    :type in_path: str
    :returns A dictionary with fields ``name`` (string), ``size`` (integer), ``mode`` (integer, see https://pkg.go.dev/io/fs#FileMode),
    :rtype: dict
    :raises DockerFileNotFound: If the file does not exist in the container
    :raises DockerUnexpectedError: If the header cannot be loaded as JSON
    """
    # Example response: https://docs.docker.com/engine/api/v1.24/#retrieving-information-about-files-and-folders-in-a-container
    # {
    # "name": "root",
    # "size": 4096,
    # "mode": 2147484096,
    # "mtime": "2014-02-27T20:51:23Z",
    # "linkTarget": ""
    # }
    stat_data = stat_file_ex(
        client,
        container,
        in_path
    )
    # Assert that size, mode, and linkTarget are present
    for key in ('size', 'mode', 'linkTarget'):
        if key not in stat_data:
            raise DockerUnexpectedError('File stat data is missing key "{0}"'.format(key))
    return stat_data

def stat_managed_file(managed_path):
    return os.lstat(managed_path)

def stat_container_file_resolve_symlinks(client, container, in_path):
    return stat_file_resolve_symlinks(client, container, in_path)

def stat_managed_file_resolve_symlinks(managed_path):
    return os.stat(managed_path)

def managed_stat_data_mode_is_symlink(mode):
    return stat.S_ISLNK(mode)

def tarinfo_and_stat_result_are_same_filetype(tarinfo, stat_result):

    if not isinstance(tarinfo, tarfile.TarInfo):
        raise ValueError(f'tarinfo must be instance of tarfile.TarInfo')
    if not isinstance(stat_result, os.stat_result):
        raise ValueError(f'stat_result must be instance of os.stat_result')

    if tarinfo.isreg() and stat.S_ISREG(stat_result.st_mode):
        return True
    if tarinfo.isdir() and stat.S_ISDIR(stat_result.st_mode):
        return True
    if tarinfo.issym() and stat.S_ISLNK(stat_result.st_mode):
        return True
    if tarinfo.islnk() and stat_result.st_nlink > 1:
        return True
    if tarinfo.ischr() and stat.S_ISCHR(stat_result.st_mode):
        return True
    if tarinfo.isblk() and stat.S_ISBLK(stat_result.st_mode):
        return True
    if tarinfo.isfifo() and stat.S_ISFIFO(stat_result.st_mode):
        return True

    return False

def tarinfo_to_rsync_itemized_filetype(tarinfo):
    if not isinstance(tarinfo, tarfile.TarInfo):
        raise ValueError(f'tarinfo must be instance of tarfile.TarInfo')
    # f for a file, a d for a directory, an L for a symlink, a D for a device, and a S for a special file (e.g. named sockets and fifos).
    # https://download.samba.org/pub/rsync/rsync.1#opt--itemize-changes
    if tarinfo.isreg():
        return 'f'
    if tarinfo.isdir():
        return 'd'
    if tarinfo.issym():
        return 'L'
    if tarinfo.islnk():
        # hard link not allowed for directory
        return 'f'
    if tarinfo.isblk():
        return 'D'
    if tarinfo.isfifo():
        return 's'

def is_idempotent(client, container, managed_path, container_path, follow_links, local_follow_links, archive_mode, owner_id, group_id, mode,
                       force=False, diff=None, max_file_size_for_diff=1, dst_override_member_path=None):
    # itemize: https://download.samba.org/pub/rsync/rsync.1#opt--itemize-changes:~:text=The%20%22%25i%22%20escape%20has%20a%20cryptic%20output%20that%20is%2011%20letters%20long.%20The%20general%20format%20is%20like%20the%20string%20YXcstpoguax%2C%20where%20Y%20is%20replaced%20by%20the%20type%20of%20update%20being%20done%2C%20X%20is%20replaced%20by%20the%20file%2Dtype%2C%20and%20the%20other%20letters%20represent%20attributes%20that%20may%20be%20output%20if%20they%20are%20being%20modified.
    is_idempotent = True
    src_stat_copy_dir_files_only = container_path.endswith(f'{os.path.sep}.')
    # Stat the container file (needed to determine if symlink and should follow)
    # Throws an error if container file doesn't exist
    src_stat = stat_container_file(
        client,
        container,
        in_path=container_path,
    )
    src_is_followed_symlink = (container_mode_is_symlink(src_stat['mode']) and follow_links)
    src_path = src_stat['linkTarget'] if src_is_followed_symlink else container_path
    # Stat the local file
    dst_stat = None
    try:
        # Does NOT resolve symlinks
        dst_stat = stat_managed_file(managed_path)
    except FileNotFoundError:
        is_idempotent = False
        if diff is None:
            return is_idempotent

    dst_is_followed_symlink = (managed_stat_data_mode_is_symlink(dst_stat.st_mode) and local_follow_links) if dst_stat is not None else False
    dst_path = os.readlink(managed_path) if dst_is_followed_symlink else managed_path
    # If follow_links, then we want to get the real path of the file in the container
    src_stat_follow_links = None
    if src_is_followed_symlink:
        # Will throw error if file does not exist
        src_stat_follow_links = stat_container_file_resolve_symlinks(client, container, in_path=container_path)
    # If follow_links, then we want to get the real path of the file on managed node
    dst_stat_follow_links = None
    if dst_is_followed_symlink:
        try:
            dst_stat_follow_links = stat_managed_file_resolve_symlinks(managed_path)
        except FileNotFoundError:
            pass

    src_stat_ultimate = src_stat_follow_links if src_is_followed_symlink is not False else src_stat
    dst_stat_ultimate = dst_stat_follow_links if dst_is_followed_symlink is not False else dst_stat
    tar_will_create_folder = dst_stat_ultimate is not None and stat.S_ISDIR(dst_stat_ultimate.st_mode) and not src_stat_copy_dir_files_only and not container_mode_is_regular(src_stat['mode'])
    # Compare the stats
    # src_stat_ultimate: {'name': 'testdir', 'size': 4096, 'mode': 2147484141, 'mtime': '2024-07-20T18:28:59.4733528Z', 'linkTarget': ''}, dst_stat_ultimate: os.stat_result(st_mode=16893, st_ino=1142, st_dev=64768, st_nlink=3, st_uid=0, st_gid=1001, st_size=4096, st_atime=1721349833, st_mtime=1721349750, st_ctime=1721350455)
    if src_stat_ultimate is None:
        raise DockerFileNotFound(
                    'File {container_path} does not exist in container {container}'
                    .format(container_path=container_path, container=container)
                )
    if dst_stat_ultimate is None:
        is_idempotent = False
        if diff is None:
            return is_idempotent

    if tar_will_create_folder:
        # Get the path itself (where the archive is being extracted) to have the correct owner, group, and mode
        group_id_to_use = group_id if group_id is not None else os.getgid()
        user_id_to_use = owner_id if owner_id is not None else os.getuid()
        mode_to_use = mode
        src_stat_ultimate_mode = src_stat_ultimate['mode']
        # | File Type | Setuid | Setgid | Sticky | Owner RWX | Group RWX | Others RWX |
        # | 4 bits    | 1 bit  | 1 bit  | 1 bit  | 3 bits    | 3 bits    | 3 bits     |
        # Unfortunately, cannot detect file type from the stat results
        # Docker Engine API returned for directory: 0b10000000000000000000000111101101
        # Docker Engine API returned for regular file: 0b110100100
        # Type
        # if (src_stat_ultimate['mode'] & 0xF000) != (dst_stat_ultimate.st_mode & 0xF000):
        #     return False
        # Size
        # if src_stat_ultimate['size'] != dst_stat_ultimate.st_size:
        #     src_size = src_stat_ultimate['size']
        #     return False
        # User
        if user_id_to_use != dst_stat_ultimate.st_uid:
            is_idempotent = False
            if diff is None:
                return is_idempotent
        # Group
        if group_id_to_use != dst_stat_ultimate.st_gid:
            is_idempotent = False
            if diff is None:
                return is_idempotent
        # Permissions
        # Extract and compare just the 12 bits used in octal perms: oct(0b111111111111) = '0o7777'
        # | Setuid | Setgid | Sticky | Owner RWX | Group RWX | Others RWX |
        # | 1 bit  | 1 bit  | 1 bit  | 3 bits    | 3 bits    | 3 bits     |
        if mode_to_use is not None and (dst_stat_ultimate.st_mode & 0o7777) != mode_to_use:
            is_idempotent = False
            if diff is None:
                return is_idempotent


    # Get the tar content of container_path
    try:
        stream = client.get_raw_stream(
            '/containers/{0}/archive'.format(container),
            params={'path': src_path},
            headers={'Accept-Encoding': 'identity'},
        )
    except NotFound:
        raise DockerFileNotFound('File {0} does not exist in container {1}'.format(src_path, container))

    with tarfile.open(fileobj=_stream_generator_to_fileobj(stream), mode='r|') as tar:
        for member in tar:
            is_member_idempotent = True
            # Build an "itemized" list with 11 elements where element 1 (0 based index) refers to filetype: itemized = list('.%s.......??' % ftype)
            # rsync: https://download.samba.org/pub/rsync/rsync.1#opt--itemize-changes
            # For examples: https://stackoverflow.com/questions/4493525/what-does-f-mean-in-rsync-logs
            # itemized[2] = checksum change
            # itemized[3] = size change
            # itemized[4] = timestamp change
            # itemized[5] = permissions change
            # itemized[6] = ownership change
            # itemized[6] = also group change?
            itemized = list('.........??')
            # Derive path that file will be written to when expanded
            dst_member_path = os.path.join(dst_path, dst_override_member_path) if dst_override_member_path is not None else os.path.join(dst_path, member.path)
            # Stat the managed path
            dst_member_stat = None
            try:
                dst_member_stat = stat_managed_file(dst_member_path)
            except FileNotFoundError:
                is_member_idempotent = False
                if diff is None:
                    return is_member_idempotent
            if dst_member_stat is not None:
                # Check force settings first
                if force is not False:
                    group_id_to_use = group_id if group_id is not None else member.gid if archive_mode else os.getgid()
                    user_id_to_use = owner_id if owner_id is not None else member.uid if archive_mode else os.getuid()
                    mode_to_use = mode if mode is not None else member.mode
                    # Type
                    if not tarinfo_and_stat_result_are_same_filetype(member, dst_member_stat):
                        is_member_idempotent = False
                        # map member filetype to one of: https://download.samba.org/pub/rsync/rsync.1#opt--itemize-changes:~:text=The%20file%2Dtypes%20that%20replace%20the%20X%20are%3A%20f%20for%20a%20file%2C%20a%20d%20for%20a%20directory%2C%20an%20L%20for%20a%20symlink%2C%20a%20D%20for%20a%20device%2C%20and%20a%20S%20for%20a%20special%20file%20(e.g.%20named%20sockets%20and%20fifos).
                        itemized[1] = tarinfo_to_rsync_itemized_filetype(member)
                        if diff is None:
                            return is_member_idempotent
                    # User
                    if user_id_to_use != dst_member_stat.st_uid:
                        is_member_idempotent = False
                        itemized[6] = 'o'
                        if diff is None:
                            return is_member_idempotent
                    # Group
                    if group_id_to_use != dst_member_stat.st_gid:
                        is_member_idempotent = False
                        itemized[7] = 'g'
                        if diff is None:
                            return is_member_idempotent
                    # Permissions
                    if mode_to_use != (dst_member_stat.st_mode & 0o7777):
                        is_member_idempotent = False
                        itemized[5] = 'p'
                        if diff is None:
                            return is_member_idempotent
                    # Size, Content - only compare if regular file
                    if stat.S_ISREG(dst_member_stat.st_mode) and member.isreg():
                        # Size
                        if member.size != dst_member_stat.st_size:
                            is_member_idempotent = False
                            itemized[3] = 's'
                            if diff is None:
                                return is_member_idempotent
                        # Content
                        is_content_equal = True
                        member_io = tar.extractfile(member)
                        with open(dst_member_path, 'rb') as dst_member_io:
                            is_content_equal = are_fileobjs_equal(member_io, dst_member_io)
                        if not is_content_equal:
                            is_member_idempotent = False
                            itemized[2] = 'c'
                            if diff is None:
                                return is_member_idempotent
            if is_member_idempotent is False:
                is_idempotent = False
                itemized[0] = '>'
                itemized[1] = tarinfo_to_rsync_itemized_filetype(member)
            if isinstance(diff, list):
                # diff.append('%s %s' % (''.join(itemized), dst_member_path))
                diff.append('%s %s' % (''.join(itemized), member.path))

    return is_idempotent


def copy(client, container, managed_path, container_path, follow_links, local_follow_links, archive_mode, owner_id, group_id, mode,
                       force=False, diff=None, max_file_size_for_diff=1,dst_override_member_path=None):
    if not isinstance(container_path, str):
        raise ValueError('container_path must be instance of str')
    # Q: If src is a directory but dst is a directory whose parent exists but the child does not, will it create the new directory (basically a rename, only for a dir)? A: Yes, it works.
    # Stat the container file (needed to determine if symlink and should follow)
    # Throws an error if container file doesn't exist
    src_stat_copy_dir_files_only = container_path.endswith(f'{os.path.sep}.')
    src_stat = stat_container_file(
        client,
        container,
        in_path=container_path,
    )
    src_is_followed_symlink = (container_mode_is_symlink(src_stat['mode']) and follow_links)
    src_path = src_stat['linkTarget'] if src_is_followed_symlink else container_path
    # Stat the local file
    dst_stat = None
    try:
        dst_stat = stat_managed_file(managed_path)
    except FileNotFoundError:
        pass
    dst_is_followed_symlink = (managed_stat_data_mode_is_symlink(dst_stat.st_mode) and local_follow_links) if dst_stat is not None else False
    dst_path = os.readlink(managed_path) if dst_is_followed_symlink else managed_path
    # If follow_links, then we want to get the real path of the file in the container
    src_stat_follow_links = None
    if src_is_followed_symlink:
        # Will throw error if file does not exist
        src_stat_follow_links = stat_container_file_resolve_symlinks(client, container, in_path=container_path)
    # If follow_links, then we want to get the real path of the file on managed node
    dst_stat_follow_links = None
    if dst_is_followed_symlink:
        try:
            dst_stat_follow_links = stat_managed_file_resolve_symlinks(managed_path)
        except FileNotFoundError:
            pass
    src_stat_ultimate = src_stat_follow_links if src_is_followed_symlink is not False else src_stat
    dst_stat_ultimate = dst_stat_follow_links if dst_is_followed_symlink is not False else dst_stat
    tar_will_create_folder = dst_stat_ultimate is not None and stat.S_ISDIR(dst_stat_ultimate.st_mode) and not src_stat_copy_dir_files_only and not container_mode_is_regular(src_stat['mode'])
    # Get the tar content of container_path
    try:
        stream = client.get_raw_stream(
            '/containers/{0}/archive'.format(container),
            params={'path': src_path},
            headers={'Accept-Encoding': 'identity'},
        )
    except NotFound:
        raise DockerFileNotFound('File {0} does not exist in container {1}'.format(src_path, container))

    def tar_filter(member, path):
        if not isinstance(member, tarfile.TarInfo):
            raise ValueError('member is not a TarInfo object')
        # Derive path that file will be written to when expanded
        dst_member_path = os.path.join(dst_path, dst_override_member_path) if dst_override_member_path is not None else os.path.join(dst_path, member.path)
        # Stat the managed path
        dst_member_stat = None
        try:
            dst_member_stat = stat_managed_file(dst_member_path)
        except FileNotFoundError:
            pass
        # Check force settings first
        if dst_member_stat is not None and force is False:
            return None
        group_id_to_use = group_id if group_id is not None else member.gid if archive_mode else os.getgid()
        user_id_to_use = owner_id if owner_id is not None else member.uid if archive_mode else os.getuid()
        mode_to_use = mode if mode is not None else member.mode
        member.gid = group_id_to_use
        member.uid = user_id_to_use
        member.mode = mode_to_use
        member.path = os.path.join(dst_path, dst_override_member_path) if dst_override_member_path is not None else member.path
        # This is returning the correct values, but looks like unless `become: True` specified, will silently fail and not change UID/GID.
        # Added validation at front of module to ensure we are super user.
        return member

    with tarfile.open(fileobj=_stream_generator_to_fileobj(stream), mode='r|') as tar:
        # Foreach member
        tar.extractall(path=dst_path, numeric_owner=True, filter=tar_filter)

    if tar_will_create_folder:
        # Get the path itself (where the archive is being extracted) to have the correct owner, group, and mode
        group_id_to_use = group_id if group_id is not None else os.getgid()
        user_id_to_use = owner_id if owner_id is not None else os.getuid()
        mode_to_use = mode
        os.chown(managed_path, user_id_to_use, group_id_to_use)
        if mode_to_use is not None:
            os.chmod(managed_path, mode_to_use)

def determine_paths(client, container, managed_path, container_path, follow_links, local_follow_links, archive_mode,
                            owner_id, group_id, mode, force=False, diff=False, max_file_size_for_diff=1):
    paths = {
        'src_stat_path': container_path,
        'dst_expand_path': managed_path,
        'dst_override_member_path': None,
    }
    if not isinstance(container_path, str):
        raise ValueError('container_path must be instance of str')
    if not isinstance(managed_path, str):
        raise ValueError('managed_path must be instance of str')
    # Throws an error if container file doesn't exist
    src_stat = stat_container_file(
        client,
        container,
        in_path=container_path,
    )
    src_is_followed_symlink = (container_mode_is_symlink(src_stat['mode']) and follow_links)
    src_path = src_stat['linkTarget'] if src_is_followed_symlink else container_path
    if not isinstance(src_path, str):
        raise ValueError('src_path must be instance of str')
    # Stat the local file
    dst_stat = None
    try:
        dst_stat = stat_managed_file(managed_path)
    except FileNotFoundError:
        pass
    dst_is_followed_symlink = (managed_stat_data_mode_is_symlink(dst_stat.st_mode) and local_follow_links) if dst_stat is not None else False
    dst_path = os.readlink(managed_path) if dst_is_followed_symlink else managed_path
    # If follow_links, then we want to get the real path of the file in the container
    src_stat_follow_links = None
    if src_is_followed_symlink:
        # Will throw error if file does not exist
        src_stat_follow_links = stat_container_file_resolve_symlinks(client, container, in_path=container_path)
    # If follow_links, then we want to get the real path of the file on managed node
    dst_stat_follow_links = None
    if dst_is_followed_symlink:
        try:
            dst_stat_follow_links = stat_managed_file_resolve_symlinks(managed_path)
        except FileNotFoundError:
            pass

    src_stat_ultimate = src_stat_follow_links if src_is_followed_symlink is not False else src_stat
    dst_stat_ultimate = dst_stat_follow_links if dst_is_followed_symlink is not False else dst_stat
    # IF SRC_PATH is a directory (IF SRC_PATH specifies a directory OR a followed symlink to a directory)
    if container_mode_is_dir(src_stat_ultimate['mode']):
        # DEST_PATH exists
        if dst_stat_ultimate is not None:
            # DEST_PATH exists and is a directory
            if stat.S_ISDIR(dst_stat_ultimate.st_mode):
                # SRC_PATH does end with /. (that is: slash followed by dot)
                # TODO - Figure out a better way to pass this argument around.
                # However, be it noted that this is all we need to drive the behavior expected - we just need to set the dest expand path here.
                if container_path.endswith(f'{os.path.sep}.'):
                    # the content of the source directory is copied into this directory
                    paths['dst_expand_path'] = os.path.dirname(dst_path)
                # SRC_PATH does not end with /. (that is: slash followed by dot)
                else:
                    # the source directory is copied into this directory
                    paths['dst_expand_path'] = dst_path
            # DEST_PATH exists and is a file (not a directory)
            else:
                # Error condition: cannot copy a directory to a file
                raise FileExistsError('Cannot copy a directory to a file')
        # DEST_PATH does not exist
        else:
            # DEST_PATH is created as a directory and the contents of the source directory are copied into this directory
            paths['dst_expand_path'] = dst_path
            paths['src_stat_path'] = f'{src_path.rstrip(os.path.sep)}{os.path.sep}.'
    # ELSE SRC_PATH is NOT a directory (aka, specifies a regular file OR a no-follow symlink (even if symlink points to dir) OR a followed symlink to a regular file)
    else:
        # DEST_PATH ends with "/"
        if managed_path.endswith(os.path.sep):
            # DEST_PATH does not exist and ends with /
            if dst_stat_ultimate is None:
                # Error condition: the destination directory must exist.
                raise FileNotFoundError(f'No such directory: {managed_path}')
            if not stat.S_ISDIR(dst_stat_ultimate.st_mode):
                # Error condition: the destination directory must exist.
                raise ValueError(f'Not a directory: {managed_path}')
            # the file is saved to a file created at DEST_PATH
            paths['dst_expand_path'] = os.path.dirname(dst_path)
        # DEST_PATH does not end with "/"
        else:
            # ...and is a directory OR a followed symlink to a directory
            if dst_stat_ultimate is not None and stat.S_ISDIR(dst_stat_ultimate.st_mode):
                # the file is copied into this directory using the basename from SRC_PATH
                paths['dst_expand_path'] = dst_path
            # ...and is a file (not a directory)
            else:
                # the destination is overwritten with the source file's contents
                paths['dst_expand_path'] = os.path.dirname(dst_path)
                # but we support changing the name of the file inside destination directory
                paths['dst_override_member_path'] = os.path.basename(dst_path)
    return paths


def copy_file_out_of_container(client, container, managed_path, container_path, container_path_normalized, container_path_ends_in_dot, follow_links, local_follow_links, archive_mode,
                             owner_id, group_id, mode, force=False, diff=None, max_file_size_for_diff=1):

    paths = determine_paths(
        client,
        container,
        managed_path,
        container_path, # Requires knowledge of whether a "dot" was used
        follow_links,
        local_follow_links,
        archive_mode,
        owner_id,
        group_id,
        mode,
        force=False,
        diff=diff,
        max_file_size_for_diff=max_file_size_for_diff
    )

    idempotent = is_idempotent(
        client,
        container,
        paths['dst_expand_path'],
        paths['src_stat_path'], # Does not work with normalized path. Needs the help of the dot.
        dst_override_member_path=paths['dst_override_member_path'],
        follow_links=follow_links,
        local_follow_links=local_follow_links,
        archive_mode=archive_mode,
        owner_id=owner_id,
        group_id=group_id,
        mode=mode,
        force=force,
        diff=diff,
        max_file_size_for_diff=max_file_size_for_diff,
    )
    changed = not idempotent

    if (changed or force) and not client.module.check_mode:
        copy(
            client,
            container,
            paths['dst_expand_path'],
            paths['src_stat_path'], # Does not work with normalized path. Needs the help of the dot.
            dst_override_member_path=paths['dst_override_member_path'],
            follow_links=follow_links,
            local_follow_links=local_follow_links,
            archive_mode=archive_mode,
            owner_id=owner_id,
            group_id=group_id,
            mode=mode,
            force=force,
            diff=diff,
            max_file_size_for_diff=max_file_size_for_diff,
        )
    result = dict(
        changed=changed,
        container_path=container_path,
        managed_path=managed_path,
        mode=mode,
        owner_id=owner_id,
        group_id=group_id,
    )
    if isinstance(diff, list):
        result['diff'] = {
            'prepared': "\n".join(diff)
        }
    client.module.exit_json(**result)

def mode_to_int_literal(mode):
    return_mode = None
    if mode is None:
        return return_mode
    try:
        return_mode = int(str(mode), 8)
    except ValueError:
        raise ValueError('"{0}" is not a valid mode'.format(mode))
    try:
        if return_mode != stat.S_IMODE(return_mode):
            raise ValueError('"{0}" is not a valid mode'.format(mode))
    except OverflowError:
        raise ValueError('"{0}" is not a valid mode'.format(mode))
    return return_mode

def normalize_container_path_to_abspath(path):
    if not isinstance(path, str):
        raise ValueError('Path "{0}" is not a valid path'.format(path))
    if not path.startswith(os.path.sep):
        path = os.path.join(os.path.sep, path)
    path = os.path.normpath(path)
    return path

def main():
    argument_spec = dict(
        container=dict(type='str', required=True),
        path=dict(type='path'),
        container_path=dict(type='str', required=True),
        follow=dict(type='bool', default=False),
        local_follow=dict(type='bool', default=True),
        archive_mode=dict(type='bool', default=False),
        owner_id=dict(type='int'),
        group_id=dict(type='int'),
        mode=dict(type='str'),
        force=dict(type='bool'),
        # Undocumented parameters for use by the action plugin
        _max_file_size_for_diff=dict(type='int'),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        min_docker_api_version='1.20',
        supports_check_mode=True,
        # I don't think we need these to both be supplied at this point
        # required_together=[('owner_id', 'group_id')],
        # Make archive_mode and owner_id/group_id mutually exclusive
        mutually_exclusive=[('archive_mode', 'owner_id'),('archive_mode', 'group_id')]
    )

    container = client.module.params['container']
    managed_path = client.module.params['path']
    container_path = client.module.params['container_path']
    follow = client.module.params['follow']
    local_follow = client.module.params['local_follow']
    archive_mode = client.module.params['archive_mode']
    owner_id = client.module.params['owner_id']
    group_id = client.module.params['group_id']
    mode = client.module.params['mode']
    force = client.module.params['force']
    max_file_size_for_diff = client.module.params['_max_file_size_for_diff'] or 1

    # Check whether user is super user if archive_mode, owner_id, or group_id are specified.
    if (archive_mode is True or owner_id is not None or group_id is not None) and not os.environ.get("SUDO_UID"):
        client.fail(f'The archive_mode, owner_id, and group_id parameters require running this module as a super user')

    # TODO: Delegate this logic to only the function that needs to know (determine_paths)
    container_path_ends_in_dot = container_path.endswith(f'{os.path.sep}.')
    container_path_normalized = container_path
    try:
        container_path_normalized = normalize_container_path_to_abspath(container_path)
    except ValueError as exc:
        client.fail(to_native(exc))

    try:
        mode = mode_to_int_literal(mode)
    except ValueError as exc:
        client.fail(to_native(exc))

    try:
        copy_file_out_of_container(
            client,
            container,
            managed_path,
            container_path,
            container_path_normalized,
            container_path_ends_in_dot,
            follow_links=follow,
            local_follow_links=local_follow,
            archive_mode=archive_mode,
            owner_id=owner_id,
            group_id=group_id,
            mode=mode,
            force=force,
            diff= list() if client.module._diff is not None else None,
            max_file_size_for_diff=max_file_size_for_diff,
        )
    except NotFound as exc:
        client.fail('Could not find container "{1}" or resource in it ({0})'.format(exc, container))
    except APIError as exc:
        client.fail('An unexpected Docker error occurred for container "{1}": {0}'.format(exc, container), exception=traceback.format_exc())
    except DockerException as exc:
        client.fail('An unexpected Docker error occurred for container "{1}": {0}'.format(exc, container), exception=traceback.format_exc())
    except RequestException as exc:
        client.fail(
            'An unexpected requests error occurred for container "{1}" when trying to talk to the Docker daemon: {0}'.format(exc, container),
            exception=traceback.format_exc())
    except DockerUnexpectedError as exc:
        client.fail('Unexpected error: {exc}'.format(exc=to_native(exc)), exception=traceback.format_exc())
    except DockerFileCopyError as exc:
        client.fail(to_native(exc))
    except OSError as exc:
        client.fail('Unexpected error: {exc}'.format(exc=to_native(exc)), exception=traceback.format_exc())



if __name__ == '__main__':
    main()
