#!/usr/bin/env bash
# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

set -o pipefail -eux

declare -a args
IFS='/:' read -ra args <<< "$1"

platform="${args[0]}"
version="${args[1]}"
pyver=default

# check for explicit python version like 8.3@3.8
declare -a splitversion
IFS='@' read -ra splitversion <<< "$version"

if [ "${#splitversion[@]}" -gt 1 ]; then
    version="${splitversion[0]}"
    pyver="${splitversion[1]}"
fi

if [ "${#args[@]}" -gt 2 ]; then
    target="azp/${args[2]}/"
else
    target="azp/"
fi

if [[ "${version}" =~ -pypi-latest$ ]]; then
    version="${version/-pypi-latest}"
    echo 'force_docker_sdk_for_python_pypi: true' >> tests/integration/integration_config.yml
fi
if [[ "${version}" =~ -dev-latest$ ]]; then
    version="${version/-dev-latest}"
    echo 'force_docker_sdk_for_python_dev: true' >> tests/integration/integration_config.yml
fi

stage="${S:-prod}"
provider="${P:-default}"

if [ "${platform}" == "rhel" ] && [[ "${version}" =~ ^8\. ]]; then
    echo "pynacl >= 1.4.0, < 1.5.0; python_version == '3.6'" >> tests/utils/constraints.txt
fi

# shellcheck disable=SC2086
ansible-test integration --color -v --retry-on-error "${target}" ${COVERAGE:+"$COVERAGE"} ${CHANGED:+"$CHANGED"} ${UNSTABLE:+"$UNSTABLE"} \
    --python "${pyver}" --remote "${platform}/${version}" --remote-terminate always --remote-stage "${stage}" --remote-provider "${provider}"
