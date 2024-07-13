# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for docker_network."""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest

from ansible_collections.community.docker.plugins.modules.docker_container_copy_out import mode_to_int_literal, normalize_container_path_to_abspath


@pytest.mark.parametrize("mode,expected", [
    ('0777', 0o777),
    ('777', 0o777),
    ('0775', 0o775),
    ('775', 0o775),
    ('0755', 0o755),
    ('755', 0o755),
    ('0700', 0o700),
    ('700', 0o700),
    ('0707', 0o707),
    ('707', 0o707),
    ('0000', 0o000),
    ('000', 0o000),
    ('0007', 0o007),
    ('007', 0o007),
    ('0005', 0o005),
    ('005', 0o005),
    ('0001', 0o001),
    ('001', 0o001),
    ('0004', 0o004),
    ('004', 0o004),
    ('0006', 0o006),
    ('006', 0o006),
    ('0002', 0o002),
    ('002', 0o002),
    ('0003', 0o003),
    ('003', 0o003),
    ('0007', 0o007),
    ('007', 0o007),
    ('0004', 0o004),
    ('004', 0o004),
    ('0006', 0o006),
    ('006', 0o006),
    ('0002', 0o002),
    ('002', 0o002),
    ('0003', 0o003),
    ('003', 0o003),
    ('0007', 0o007),
    ('007', 0o007),
    ('0004', 0o004),
    ('004', 0o004),
    ('0006', 0o006),
    ('006', 0o006),
    ('0002', 0o002),
    ('002', 0o002),
    ('0003', 0o003),
    ('003', 0o003),
    ('0007', 0o007),
    ('007', 0o007),
    ('0004', 0o004),
    ('004', 0o004),
    ('0006', 0o006),
    ('006', 0o006),
    ('0002', 0o002)
])
def test_mode_to_int_literal_positives(mode, expected):
    assert mode_to_int_literal(mode) == expected


@pytest.mark.parametrize("mode", [
    ('0778'),
    ('778'),
    ('0708'),
    ('708'),
    ('0008'),
    ('008'),
    ('0009'),
    ('009'),
    ('0008'),
    ('008'),
    ('0009'),
    ('009'),
    ('1234123412341324'),
    (0o77731),
    (432424434)
])
def test_mode_to_int_literal_negatives(mode):
    with pytest.raises(ValueError) as e:
        mode_to_int_literal(mode)
    assert '"{0}" is not a valid mode'.format(mode) == str(e.value)

@pytest.mark.parametrize("path,expected", [
    ('', '/'),
    ('tmp', '/tmp'),
    ('tmp/test', '/tmp/test'),
    ('tmp/../test', '/test'),
    ('tmp/../../test', '/test'),
    ('/tmp//test', '/tmp/test'),
    ('//tmp/test', '//tmp/test'), # this is the behavior of os.path.normpath
    ('tmp//test//', '/tmp/test'),
])
def test_normalize_container_path_to_abspath_positives(path, expected):
    assert normalize_container_path_to_abspath(path) == expected

@pytest.mark.parametrize("path", [
    (123),
    ([1, 2, 3]),
])
def test_normalize_container_path_to_abspath_negatives(path):
    with pytest.raises(ValueError) as e:
        normalize_container_path_to_abspath(path)
    assert 'Path "{0}" is not a valid path'.format(path) == str(e.value)
