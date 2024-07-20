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

def log(module, msg):
    # Get a timestamp
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    timestamped_msg = f'{timestamp}: docker_container_copy_out: {msg}'
    module.log(timestamped_msg)

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


def are_fileobjs_equal_read_first(f1, f2):
    '''Given two (buffered) file objects, compare their contents.

    Returns a tuple (is_equal, content_of_f1), where the first element indicates
    whether the two file objects have the same content, and the second element is
    the content of the first file object.'''
    blocksize = 65536
    b1buf = b''
    b2buf = b''
    is_equal = True
    content = []
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
            is_equal = not b1buf and not b2buf
            break
        # Compare the next chunk of data, and remove it from the buffers
        buflen = min(len(b1buf), len(b2buf))
        if b1buf[:buflen] != b2buf[:buflen]:
            is_equal = False
            break
        content.append(b1buf[:buflen])
        b1buf = b1buf[buflen:]
        b2buf = b2buf[buflen:]

    content.append(b1buf)
    if f1:
        content.append(f1.read())

    return is_equal, b''.join(content)


def is_container_file_not_regular_file(container_stat):
    for bit in (
        # https://pkg.go.dev/io/fs#FileMode
        32 - 1,  # ModeDir
        32 - 4,  # ModeTemporary
        32 - 5,  # ModeSymlink
        32 - 6,  # ModeDevice
        32 - 7,  # ModeNamedPipe
        32 - 8,  # ModeSocket
        32 - 11,  # ModeCharDevice
        32 - 13,  # ModeIrregular
    ):
        if container_stat['mode'] & (1 << bit) != 0:
            return True
    return False

def add_other_diff(diff, in_path, member):
    if diff is None:
        return
    diff['before_header'] = in_path
    if member.isdir():
        diff['before'] = '(directory)'
    elif member.issym() or member.islnk():
        diff['before'] = member.linkname
    elif member.ischr():
        diff['before'] = '(character device)'
    elif member.isblk():
        diff['before'] = '(block device)'
    elif member.isfifo():
        diff['before'] = '(fifo)'
    elif member.isdev():
        diff['before'] = '(device)'
    elif member.isfile():
        raise DockerUnexpectedError('should not be a regular file')
    else:
        diff['before'] = '(unknown filesystem object)'


def retrieve_diff(client, container, container_path, follow_links, diff, max_file_size_for_diff, regular_stat=None, link_target=None):
    if diff is None:
        return
    if regular_stat is not None:
        # First handle all filesystem object types that are not regular files
        if regular_stat['mode'] & (1 << (32 - 1)) != 0:
            diff['before_header'] = container_path
            diff['before'] = '(directory)'
            return
        elif regular_stat['mode'] & (1 << (32 - 4)) != 0:
            diff['before_header'] = container_path
            diff['before'] = '(temporary file)'
            return
        elif regular_stat['mode'] & (1 << (32 - 5)) != 0:
            diff['before_header'] = container_path
            diff['before'] = link_target
            return
        elif regular_stat['mode'] & (1 << (32 - 6)) != 0:
            diff['before_header'] = container_path
            diff['before'] = '(device)'
            return
        elif regular_stat['mode'] & (1 << (32 - 7)) != 0:
            diff['before_header'] = container_path
            diff['before'] = '(named pipe)'
            return
        elif regular_stat['mode'] & (1 << (32 - 8)) != 0:
            diff['before_header'] = container_path
            diff['before'] = '(socket)'
            return
        elif regular_stat['mode'] & (1 << (32 - 11)) != 0:
            diff['before_header'] = container_path
            diff['before'] = '(character device)'
            return
        elif regular_stat['mode'] & (1 << (32 - 13)) != 0:
            diff['before_header'] = container_path
            diff['before'] = '(unknown filesystem object)'
            return
        # Check whether file is too large
        if regular_stat['size'] > max_file_size_for_diff > 0:
            diff['dst_larger'] = max_file_size_for_diff
            return

    # We need to get hold of the content
    def process_none(in_path):
        diff['before'] = ''

    def process_regular(in_path, tar, member):
        add_diff_dst_from_regular_member(diff, max_file_size_for_diff, in_path, tar, member)

    def process_symlink(in_path, member):
        diff['before_header'] = in_path
        diff['before'] = member.linkname

    def process_other(in_path, member):
        add_other_diff(diff, in_path, member)

    fetch_file_ex(
        client,
        container,
        in_path=container_path,
        process_none=process_none,
        process_regular=process_regular,
        process_symlink=process_symlink,
        process_other=process_other,
        follow_links=follow_links,
    )


def is_binary(content):
    if b'\x00' in content:
        return True
    # TODO: better detection
    # (ansible-core also just checks for 0x00, and even just sticks to the first 8k, so this isn't too bad...)
    return False


def are_fileobjs_equal_with_diff_of_first(f1, f2, size, diff, max_file_size_for_diff, container_path):
    if diff is None:
        return are_fileobjs_equal(f1, f2)
    if size > max_file_size_for_diff > 0:
        diff['dst_larger'] = max_file_size_for_diff
        return are_fileobjs_equal(f1, f2)
    is_equal, content = are_fileobjs_equal_read_first(f1, f2)
    if is_binary(content):
        diff['dst_binary'] = 1
    else:
        diff['before_header'] = container_path
        diff['before'] = to_text(content)
    return is_equal


def add_diff_dst_from_regular_member(diff, max_file_size_for_diff, container_path, tar, member):
    if diff is None:
        return
    if member.size > max_file_size_for_diff > 0:
        diff['dst_larger'] = max_file_size_for_diff
        return

    tar_f = tar.extractfile(member)  # in Python 2, this *cannot* be used in `with`...
    content = tar_f.read()
    if is_binary(content):
        diff['dst_binary'] = 1
    else:
        diff['before_header'] = container_path
        diff['before'] = to_text(content)


def copy_dst_to_src(diff):
    if diff is None:
        return
    for f, t in [
        ('dst_size', 'src_size'),
        ('dst_binary', 'src_binary'),
        ('before_header', 'after_header'),
        ('before', 'after'),
    ]:
        if f in diff:
            diff[t] = diff[f]
        elif t in diff:
            diff.pop(t)


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

def container_stat_data_mode_is_symlink(mode):
    return stat_data_mode_is_symlink(mode)

def managed_stat_data_mode_is_symlink(mode):
    return stat.S_ISLNK(mode)

def container_stat_data_mode_to_managed_stat_data_mode(mode):
    return mode
    # return mode >> 17

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

def is_idempotent(client, container, managed_path, container_path, follow_links, local_follow_links, archive_mode, owner_id, group_id, mode,
                       force=False, diff=None, max_file_size_for_diff=1):
    # TODO: Debug why after copying same file 2x, the 2nd time is still showing changed: true
    # Always execute if force is True
    if force is True:
        return False
    # Stat the container file (needed to determine if symlink and should follow)
    # Throws an error if container file doesn't exist
    src_stat = stat_container_file(
        client,
        container,
        in_path=container_path,
    )
    src_is_followed_symlink = (container_stat_data_mode_is_symlink(src_stat['mode']) and follow_links)
    src_path = src_stat['linkTarget'] if src_is_followed_symlink else container_path
    # Stat the local file
    dst_stat = None
    try:
        dst_stat = stat_managed_file(managed_path)
    except FileNotFoundError:
        return False

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
        dst_stat_follow_links = stat_managed_file_resolve_symlinks(managed_path)

    src_stat_to_compare = src_stat_follow_links if src_stat_follow_links is not None else src_stat
    dst_stat_to_compare = dst_stat_follow_links if dst_stat_follow_links is not None else dst_stat

    # Compare the stats
    # src_stat_to_compare: {'name': 'testdir', 'size': 4096, 'mode': 2147484141, 'mtime': '2024-07-20T18:28:59.4733528Z', 'linkTarget': ''}, dst_stat_to_compare: os.stat_result(st_mode=16893, st_ino=1142, st_dev=64768, st_nlink=3, st_uid=0, st_gid=1001, st_size=4096, st_atime=1721349833, st_mtime=1721349750, st_ctime=1721350455)
    if src_stat_to_compare is None:
        raise DockerFileNotFound(
                    'File {container_path} does not exist in container {container}'
                    .format(container_path=container_path, container=container)
                )
    if dst_stat_to_compare is None:
        return False

    # Get the path itself (where the archive is being extracted) to have the correct owner, group, and mode
    group_id_to_use = group_id if group_id is not None else os.getgid()
    user_id_to_use = owner_id if owner_id is not None else os.getuid()
    mode_to_use = mode
    # | File Type | Setuid | Setgid | Sticky | Owner RWX | Group RWX | Others RWX |
    # | 4 bits    | 1 bit  | 1 bit  | 1 bit  | 3 bits    | 3 bits    | 3 bits     |
    # Unfortunately, cannot detect file type from the stat results
    # Docker Engine API returned for directory: 0b10000000000000000000000111101101
    # Docker Engine API returned for regular file: 0b110100100
    # Type
    # if (src_stat_to_compare['mode'] & 0xF000) != (dst_stat_to_compare.st_mode & 0xF000):
    #     return False
    # Size
    if src_stat_to_compare['size'] != dst_stat_to_compare.st_size:
        return False
    # User
    if group_id_to_use != dst_stat_to_compare.st_gid:
        return False
    # Group
    if user_id_to_use != dst_stat_to_compare.st_uid:
        return False
    # Permissions
    # Extract and compare just the 12 bits used in octal perms: oct(0b111111111111) = '0o7777'
    # | Setuid | Setgid | Sticky | Owner RWX | Group RWX | Others RWX |
    # | 1 bit  | 1 bit  | 1 bit  | 3 bits    | 3 bits    | 3 bits     |
    if mode_to_use is not None and (dst_stat_to_compare.st_mode & 0o7777) != mode_to_use:
        return False

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
            # TODO If check mode, return None so that the file is not extracted
            log(client.module, f'TarInfo path: {member.path}, name: {member.name}, size: {member.size}, mode: {member.mode}, UID: {member.uid}, GID: {member.gid}')
            # Derive path that file will be written to when expanded
            dst_member_path = os.path.join(dst_path, member.path)
            # Stat the managed path
            dst_member_stat = None
            try:
                dst_member_stat = stat_managed_file(dst_member_path)
            except FileNotFoundError:
                return False
            # Check force settings first
            if dst_member_stat is not None and force is False:
                # Could still be idempotent
                continue
            group_id_to_use = group_id if group_id is not None else member.gid if archive_mode else os.getgid()
            user_id_to_use = owner_id if owner_id is not None else member.uid if archive_mode else os.getuid()
            mode_to_use = mode if mode is not None else member.mode
            # Type
            if not tarinfo_and_stat_result_are_same_filetype(member, dst_member_stat):
                return False
            # Size
            if member.size != dst_member_stat.st_size:
                return False
            # User
            if user_id_to_use != dst_member_stat.st_uid:
                return False
            # Group
            if group_id_to_use != dst_member_stat.st_gid:
                return False
            # Permissions
            if mode_to_use != (dst_member_stat.st_mode & 0o7777):
                return False
            # TODO: Compare Content

    return True


def copy(client, container, managed_path, container_path, follow_links, local_follow_links, archive_mode, owner_id, group_id, mode,
                       force=False, diff=None, max_file_size_for_diff=1):

    # TODO Support idempotence. Can we run this atomically to determine if ANY changes needed to be made. Instead of extract_all, may need to use extract.
    # TODO Support diff mode
    # TODO Support check mode
    # Stat the container file (needed to determine if symlink and should follow)
    # Throws an error if container file doesn't exist
    src_stat = stat_container_file(
        client,
        container,
        in_path=container_path,
    )
    src_is_followed_symlink = (container_stat_data_mode_is_symlink(src_stat['mode']) and follow_links)
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
        dst_stat_follow_links = stat_managed_file_resolve_symlinks(managed_path)

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
        # TODO If check mode, return None so that the file is not extracted
        log(client.module, f'TarInfo path: {member.path}, name: {member.name}, size: {member.size}, mode: {member.mode}, UID: {member.uid}, GID: {member.gid}')
        # Derive path that file will be written to when expanded
        dst_member_path = os.path.join(dst_path, member.path)
        # Stat the managed path
        dst_member_stat = None
        try:
            dst_member_stat = stat_managed_file(dst_member_path)
        except FileNotFoundError:
            pass
        # if dst_member_stat:
        #     log(client.module, f'container mode: {bin(member.mode)}, managed mode: {bin(dst_member_stat.st_mode)}')
        # log(client.module, f'Destination member path BEFORE: {dst_member_path}, stat: {dst_member_stat}')
        # Check force settings first
        if dst_member_stat is not None and force is False:
            return None
        group_id_to_use = group_id if group_id is not None else member.gid if archive_mode else os.getgid()
        user_id_to_use = owner_id if owner_id is not None else member.uid if archive_mode else os.getuid()
        mode_to_use = mode if mode is not None else member.mode
        # log(client.module, f'group_id_to_use: {group_id_to_use}, user_id_to_use: {user_id_to_use}, member.gid: {member.gid}, member.uid: {member.uid}, mode_to_use: {oct(mode_to_use)}, member.mode: {oct(member.mode)}')
        member.gid = group_id_to_use
        member.uid = user_id_to_use
        member.mode = mode_to_use
        return member

    with tarfile.open(fileobj=_stream_generator_to_fileobj(stream), mode='r|') as tar:
        # Foreach member
        tar.extractall(path=dst_path, numeric_owner=True, filter=tar_filter)

    # Get the path itself (where the archive is being extracted) to have the correct owner, group, and mode
    group_id_to_use = group_id if group_id is not None else os.getgid()
    user_id_to_use = owner_id if owner_id is not None else os.getuid()
    mode_to_use = mode

    os.chown(managed_path, user_id_to_use, group_id_to_use)
    if mode_to_use is not None:
        os.chmod(managed_path, mode_to_use)




def is_file_idempotent(client, container, managed_path, container_path, follow_links, local_follow_links, archive_mode, owner_id, group_id, mode,
                       force=False, diff=None, max_file_size_for_diff=1):
    return False
    # return container_path, mode, False

    # TODO - get some basic stat data about the file in the container so we can check idempotence.
    # Throws an error if container file doesn't exist
    src_stat = stat_container_file(
        client,
        container,
        in_path=container_path,
    )

    # If follow_links, then we want to get the real path of the file in the container
    src_stat_follow_links = None
    if follow_links:
        # Will throw error if file does not exist
        src_stat_follow_links = stat_container_file_resolve_symlinks(client, container, in_path=container_path)
    # Stat the local file
    dst_stat = None
    try:
        dst_stat = stat_managed_file(managed_path)
    except FileNotFoundError:
        pass
    # If follow_links, then we want to get the real path of the file on managed node
    dst_stat_follow_links = None
    if local_follow_links:
        dst_stat_follow_links = stat_managed_file_resolve_symlinks(managed_path)
    log(client.module, f'src_stat: {src_stat} | dst_stat: {dst_stat} | src_stat_follow_links: {src_stat_follow_links} | dst_stat_follow_links: {dst_stat_follow_links}')
    # 1. If force == True, we are forcing. File is not idempotent. Shouldn't we provide the diff if asked for?
    if force == True:
        return False

    # 1. If force == False, check to see if a file already exists on managed node. If it does, we are "idempotent" (we will make no changes). Else, we will make changes because we are "not idempotent" (file needs to exist!). Shouldn't we provide the diff if asked for? But will not be changed.
    if force == False:
        if dst_stat is not None:
            return True
    # 1. If forcing == None (default), then we need to diff the files to see if they are the same to determine idempotence.
    src_is_symlink = container_stat_data_mode_is_symlink(src_stat['mode'])
    dst_is_symlink = managed_stat_data_mode_is_symlink(dst_stat.st_mode)
    # Are either of the files symlinks?
    if src_is_symlink or dst_is_symlink:
        # Are they treated as symlinks?
        src_is_treated_as_symlink = (container_stat_data_mode_is_symlink(src_stat['mode']) and not follow_links)
        dst_is_treated_as_symlink = (managed_stat_data_mode_is_symlink(dst_stat.st_mode) and not local_follow_links)
        # Is one treated as a symlink and the other not? Then not idempotent.
        if src_is_treated_as_symlink != dst_is_treated_as_symlink:
            return False
        # Both are treated as symlinks
        if src_is_treated_as_symlink and dst_is_treated_as_symlink:
            # OK, so they're both treated as symlinks... Do they:
            # Point to the same target?
            src_symlink_target = src_stat['linkTarget']
            dst_symlink_target = os.readlink(managed_path)
            if src_symlink_target != dst_symlink_target:
                return False
            # Standard checks on stat
            # Have the same file type (obviously)
            # Get the file type for src: https://docs.docker.com/engine/api/v1.24/#31-containers
            # Get the leftmost 12 bits of the mode
            src_file_type = src_stat['mode'] & 0xFFF
            # Get the file type for dst: https://docs.python.org/3/library/os.html#os.stat
            dst_file_type = stat.S_IFMT(dst_stat.st_mode)
            if src_file_type != dst_file_type:
                return False
            try:
                stream = client.get_raw_stream(
                    '/containers/{0}/archive', container,
                    params={'path': container_path},
                    headers={'Accept-Encoding': 'identity'},
                )
            except NotFound:
                raise DockerFileNotFound('File {0} does not exist in container {1}'.format(container_path, container))
            with tarfile.open(fileobj=_stream_generator_to_fileobj(stream), mode='r|') as tar:
                for member in tar:
                    # Stat the file on the managed node
                    try:
                        managed_member = os.lstat(member.path)
                    except FileNotFoundError:
                        return False
                    # Check things like user/group ID and mode against the managed file
                    if any([
                        managed_member.st_mode != member.mode,
                        managed_member.st_uid != member.uid,
                        managed_member.st_gid != member.gid,
                        managed_member.st_size != member.size,
                    ]):
                        return False
                    # Have the same UID, GID
                    # Have the same mode?
                    # If type is dir, perform recursive. (won't apply here because type is symlinks)
                    # etc.
        # Neither is treated as a symlink? (following both)
            # Compare the targets
                # Standard checks on stat
                    # Have the same file type
                    # Have the same UID, GID
                    # Have the same mode?
                    # If type is dir, perform recursive.
                    # etc.
                # Standard checks on content (recursive if dir)
    return False
    # Neither file is a symlink
        # Compare the files
            # Standard checks on stat
                # Have the same file type
                # Have the same UID, GID
                # Have the same mode?
                # If type is dir, perform recursive.
                # etc.
            # Standard checks on content (recursive if dir)


    # Are the files the same type (mode)?


    # 1. If they are the same, then we can skip the copy.
    # 1. If they are different, then we need to copy the file from the container to the managed node.


    # Calculate the diff "after" if requested
    # if diff is not None:
    #     if file_stat.st_size > max_file_size_for_diff > 0:
    #         diff['src_larger'] = max_file_size_for_diff
    #     elif stat.S_ISLNK(file_stat.st_mode):
    #         diff['after_header'] = managed_path
    #         diff['after'] = os.readlink(managed_path)
    #     else:
    #         with open(managed_path, 'rb') as f:
    #             content = f.read()
    #         if is_binary(content):
    #             diff['src_binary'] = 1
    #         else:
    #             diff['after_header'] = managed_path
    #             diff['after'] = to_text(content)
    # Retrieve information of local file

    # Resolve symlinks in the container (if requested), and get information on container's file
    real_container_path, regular_stat, link_target = stat_file(
        client,
        container,
        in_path=container_path,
        follow_links=follow_links,
    )

    # Follow links in the Docker container?
    if follow_links:
        container_path = real_container_path

    # If the file wasn't found in container, error
    if regular_stat is None:
        raise DockerFileNotFound(
            'File {in_path} does not exist in container {container}'
            .format(in_path=container_path, container=container)
        )

    # When forcing and we're not following links in the container, go!
    if force and not follow_links:
        retrieve_diff(client, container, container_path, follow_links, diff, max_file_size_for_diff)
        return container_path, mode, False

    # Retrieve information of local file
    try:
        file_stat = os.stat(managed_path) if local_follow_links else os.lstat(managed_path)
    except OSError as exc:
        if exc.errno == 2:
            if diff is not None:
                diff['before_header'] = container_path
                diff['before'] = ''
            return container_path, mode, False

    if mode is None:
        mode = stat.S_IMODE(file_stat.st_mode)
    if not stat.S_ISLNK(file_stat.st_mode) and not stat.S_ISREG(file_stat.st_mode):
        raise DockerFileCopyError('Local path {managed_path} is not a symbolic link or file')

    if diff is not None:
        if file_stat.st_size > max_file_size_for_diff > 0:
            diff['src_larger'] = max_file_size_for_diff
        elif stat.S_ISLNK(file_stat.st_mode):
            diff['after_header'] = managed_path
            diff['after'] = os.readlink(managed_path)
        else:
            with open(managed_path, 'rb') as f:
                content = f.read()
            if is_binary(content):
                diff['src_binary'] = 1
            else:
                diff['after_header'] = managed_path
                diff['after'] = to_text(content)

    # When forcing, go!
    if force:
        retrieve_diff(client, container, container_path, follow_links, diff, max_file_size_for_diff, regular_stat, link_target)
        return container_path, mode, False

    # If force is set to False, and the destination exists, assume there's nothing to do
    if force is False:
        retrieve_diff(client, container, container_path, follow_links, diff, max_file_size_for_diff, regular_stat, link_target)
        copy_dst_to_src(diff)
        return container_path, mode, True

    # Basic idempotency checks
    if stat.S_ISLNK(file_stat.st_mode):
        if link_target is None:
            retrieve_diff(client, container, container_path, follow_links, diff, max_file_size_for_diff, regular_stat, link_target)
            return container_path, mode, False
        local_link_target = os.readlink(managed_path)
        retrieve_diff(client, container, container_path, follow_links, diff, max_file_size_for_diff, regular_stat, link_target)
        return container_path, mode, local_link_target == link_target
    if link_target is not None:
        retrieve_diff(client, container, container_path, follow_links, diff, max_file_size_for_diff, regular_stat, link_target)
        return container_path, mode, False
    if is_container_file_not_regular_file(regular_stat):
        retrieve_diff(client, container, container_path, follow_links, diff, max_file_size_for_diff, regular_stat, link_target)
        return container_path, mode, False
    if file_stat.st_size != regular_stat['size']:
        retrieve_diff(client, container, container_path, follow_links, diff, max_file_size_for_diff, regular_stat, link_target)
        return container_path, mode, False
    if mode != file_stat.st_mode & 0xFFF:
        retrieve_diff(client, container, container_path, follow_links, diff, max_file_size_for_diff, regular_stat, link_target)
        return container_path, mode, False

    # Fetch file from container
    def process_none(in_path):
        return container_path, mode, False

    def process_regular(in_path, tar, member):
        # Check things like user/group ID and mode
        if any([
            # member.mode & 0xFFF != mode,
            file_stat.st_mode & 0xFFF != mode,
            # member.uid != owner_id,
            file_stat.st_uid != owner_id,
            # member.gid != group_id,
            file_stat.st_gid != group_id,
            not stat.S_ISREG(file_stat.st_mode),
            member.size != file_stat.st_size,
        ]):
            add_diff_dst_from_regular_member(diff, max_file_size_for_diff, in_path, tar, member)
            return container_path, mode, False

        tar_f = tar.extractfile(member)  # in Python 2, this *cannot* be used in `with`...
        with open(managed_path, 'rb') as local_f:
            is_equal = are_fileobjs_equal_with_diff_of_first(tar_f, local_f, member.size, diff, max_file_size_for_diff, in_path)
        return container_path, mode, is_equal

    def process_symlink(in_path, member):
        if diff is not None:
            diff['before_header'] = in_path
            diff['before'] = member.linkname

        # Check things like user/group ID and mode
        if member.mode & 0xFFF != mode:
            return container_path, mode, False
        if member.uid != owner_id:
            return container_path, mode, False
        if member.gid != group_id:
            return container_path, mode, False

        if not stat.S_ISLNK(file_stat.st_mode):
            return container_path, mode, False

        local_link_target = os.readlink(managed_path)
        return container_path, mode, member.linkname == local_link_target

    def process_other(in_path, member):
        add_other_diff(diff, in_path, member)

        return container_path, mode, False


    return fetch_file_ex(
        client,
        container,
        in_path=container_path,
        process_none=process_none,
        process_regular=process_regular,
        process_symlink=process_symlink,
        process_other=process_other,
        follow_links=follow_links,
    )

def copy_file_out_of_container(client, container, managed_path, container_path, follow_links, local_follow_links, archive_mode,
                             owner_id, group_id, mode, force=False, diff=False, max_file_size_for_diff=1):
    if diff:
        diff = {}
    else:
        diff = None
    idempotent = is_idempotent(
        client,
        container,
        managed_path,
        container_path,
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

    if changed and not client.module.check_mode:
        copy(
            client,
            container,
            managed_path,
            container_path,
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
    if diff:
        result['diff'] = diff
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
        # TODO Make archive_mode and owner_id/group_id mutually exclusive?
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

    try:
        container_path = normalize_container_path_to_abspath(container_path)
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
            follow_links=follow,
            local_follow_links=local_follow,
            archive_mode=archive_mode,
            owner_id=owner_id,
            group_id=group_id,
            mode=mode,
            force=force,
            diff=client.module._diff,
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
