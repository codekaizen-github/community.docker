#!/usr/bin/python
#
# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
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
      - This flag indicates that filesystem links in the Docker container, if they exist, should be followed.
    type: bool
    default: false
  local_follow:
    description:
      - This flag indicates that filesystem links in the source tree (where the module is executed), if they exist, should be followed.
    type: bool
    default: true
  owner_id:
    description:
      - The owner ID to use when writing the file to disk.
      - If provided, O(group_id) must also be provided.
      - If not provided, the module will default to the current user's UID.
    type: int
  group_id:
    description:
      - The group ID to use when writing the file to disk.
      - If provided, O(owner_id) must also be provided.
      - If not provided, the module defaults to the current user's GID.
    type: int
  mode:
    description:
      - The file mode to use when writing the file to disk.
      - Please note that the mode is always interpreted as an octal number.
      - If not provided, the module will default to 0o644.
    type: int
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
  - "Felix Fontein (@felixfontein)"

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
    fetch_file,
    fetch_file_ex,
    stat_file,
)

from ansible_collections.community.docker.plugins.module_utils._scramble import generate_insecure_key, scramble


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

    def process_other(in_path, tar, member):
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


def is_file_idempotent(client, container, managed_path, container_path, follow_links, local_follow_links, owner_id, group_id, mode,
                       force=False, diff=None, max_file_size_for_diff=1):

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

    def process_other(in_path, tar, member):
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

def copy_file_out_of_container(client, container, managed_path, container_path, follow_links, local_follow_links,
                             owner_id, group_id, mode, force=False, diff=False, max_file_size_for_diff=1):
    if diff:
        diff = {}
    else:
        diff = None

    container_path, mode, idempotent = is_file_idempotent(
        client,
        container,
        managed_path,
        container_path,
        follow_links,
        local_follow_links,
        owner_id,
        group_id,
        mode,
        force=force,
        diff=diff,
        max_file_size_for_diff=max_file_size_for_diff,
    )
    changed = not idempotent

    if changed and not client.module.check_mode:
        fetch_file(
            client,
            container,
            container_path,
            managed_path,
            follow_links=follow_links,
        )
        # Change the file mode, owner, and group
        os.chmod(managed_path, mode)
        os.chown(managed_path, owner_id, group_id)

    # TODO: Calculate and return checksums of the file. If check mode, use the src file to calculate the checksums. Else, use the dest file.
    # md5sum = None
    # checksum = None
    # if os.path.isfile(src):
    #     try:
    #         checksum = client.module.sha1(src)
    #     except (OSError, IOError) as e:
    #         client.module.warn("Unable to calculate src checksum, assuming change: %s" % to_native(e))
    #     try:
    #         # Backwards compat only.  This will be None in FIPS mode
    #         md5sum = client.module.md5(src)
    #     except ValueError:
    #         pass

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

def main():
    argument_spec = dict(
        container=dict(type='str', required=True),
        path=dict(type='path'),
        container_path=dict(type='str', required=True),
        follow=dict(type='bool', default=False),
        local_follow=dict(type='bool', default=True),
        owner_id=dict(type='int'),
        group_id=dict(type='int'),
        mode=dict(type='int'),
        force=dict(type='bool'),
        content=dict(type='str', no_log=True),
        content_is_b64=dict(type='bool', default=False),

        # Undocumented parameters for use by the action plugin
        _max_file_size_for_diff=dict(type='int'),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        min_docker_api_version='1.20',
        supports_check_mode=True,
        mutually_exclusive=[('path', 'content')],
        required_together=[('owner_id', 'group_id')],
        required_by={
            'content': ['mode'],
        },
    )

    container = client.module.params['container']
    managed_path = client.module.params['path']
    container_path = client.module.params['container_path']
    follow = client.module.params['follow']
    local_follow = client.module.params['local_follow']
    owner_id = client.module.params['owner_id']
    group_id = client.module.params['group_id']
    mode = client.module.params['mode']
    force = client.module.params['force']
    content = client.module.params['content']
    max_file_size_for_diff = client.module.params['_max_file_size_for_diff'] or 1

    if content is not None:
        if client.module.params['content_is_b64']:
            try:
                content = base64.b64decode(content)
            except Exception as e:  # depending on Python version and error, multiple different exceptions can be raised
                client.fail('Cannot Base64 decode the content option: {0}'.format(e))
        else:
            content = to_bytes(content)

    if not container_path.startswith(os.path.sep):
        container_path = os.path.join(os.path.sep, container_path)
    container_path = os.path.normpath(container_path)

    if mode is None:
        mode = 0o644

    if group_id is None:
        group_id = os.getgid()

    if owner_id is None:
        owner_id = os.getuid()

    try:
        # TODO: Use fetch_file() method from plugins/module_utils/copy.py
        copy_file_out_of_container(
            client,
            container,
            managed_path,
            container_path,
            follow_links=follow,
            local_follow_links=local_follow,
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
