#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import pytest

import cpfs_nfs_common

DNS = 'cpfs-123456.cn-beijing.cpfs.aliyuncs.com'


def test_resolve_success_multiple_ips(mocker):
    dns_output = '"192.168.1.1 10"\n"192.168.1.2 20"\n'
    mock1 = mocker.patch('subprocess.check_output', return_value=dns_output.encode('utf-8'))

    ips, weights = cpfs_nfs_common._resolve_cpfs_dns(DNS)

    assert ips == ['192.168.1.1', '192.168.1.2']
    assert weights == [10, 20]
    mock1.assert_called_once_with("dig -t TXT +short +tcp cpfs-123456.cn-beijing.cpfs.aliyuncs.com.", shell=True)


def test_resolve_success_single_ip(mocker):
    dns_output = '"192.168.1.1 10"\n'
    mocker.patch('subprocess.check_output', return_value=dns_output.encode('utf-8'))
    warning_mock = mocker.patch('logging.warning')

    ips, weights = cpfs_nfs_common._resolve_cpfs_dns(DNS)

    assert ips == ['192.168.1.1']
    assert weights == [10]
    warning_mock.assert_any_call('Only one server ip found: \n%s', dns_output)


def test_resolve_dns_already_ends_with_dot(mocker):
    dns_with_dot = DNS + '.'
    dns_output = '"192.168.1.1 10"\n"192.168.1.2 20"\n'
    mock_check_output = mocker.patch('subprocess.check_output', return_value=dns_output.encode('utf-8'))

    ips, weights = cpfs_nfs_common._resolve_cpfs_dns(dns_with_dot)

    # Should not double the dot
    expected_cmd = cpfs_nfs_common.RESOLVE_DNS_CMD.format(dns_with_dot)
    mock_check_output.assert_called_with(expected_cmd, shell=True)
    assert ips == ['192.168.1.1', '192.168.1.2']
    assert weights == [10, 20]


def test_resolve_dns_appends_dot(mocker):
    dns_output = '"192.168.1.1 10"\n"192.168.1.2 20"\n'
    mock_check_output = mocker.patch('subprocess.check_output', return_value=dns_output.encode('utf-8'))

    ips, weights = cpfs_nfs_common._resolve_cpfs_dns(DNS)

    expected_cmd = cpfs_nfs_common.RESOLVE_DNS_CMD.format(DNS + '.')
    mock_check_output.assert_called_with(expected_cmd, shell=True)


def test_resolve_fallback_to_host_on_failure(mocker):
    dns_output = '"192.168.1.1 10"\n"192.168.1.2 20"\n'
    mock_check_output = mocker.patch(
        'subprocess.check_output',
        side_effect=[Exception('dig failed'), Exception('dig failed'), Exception('dig failed'),
                     dns_output.encode('utf-8')]
    )
    mocker.patch('time.sleep')

    ips, weights = cpfs_nfs_common._resolve_cpfs_dns(DNS)

    assert ips == ['192.168.1.1', '192.168.1.2']
    assert weights == [10, 20]
    assert mock_check_output.call_count == 4
    mock_check_output.assert_called_with(
        'host -t TXT cpfs-123456.cn-beijing.cpfs.aliyuncs.com.|grep \'^cpfs-123456.cn-beijing.cpfs.aliyuncs.com.\'', shell=True)
    # Second call should use the alternative command
    dns_with_dot = DNS + '.'
    expected_alt_cmd = cpfs_nfs_common.RESOLVE_DNS_CMD_ALTERNATIVE.format(dns_with_dot)
    mock_check_output.assert_called_with(expected_alt_cmd, shell=True)


def test_resolve_all_retries_fail(mocker):
    mock_check_output = mocker.patch(
        'subprocess.check_output',
        side_effect=Exception('resolve failed')
    )
    mocker.patch('time.sleep')

    with pytest.raises(SystemExit) as ex:
        cpfs_nfs_common._resolve_cpfs_dns(DNS)

    assert ex.value.code != 0
    assert mock_check_output.call_count == cpfs_nfs_common.RESOLVE_DNS_RETRY


def test_resolve_invalid_weight_ip_format(mocker):
    # weight_ip has only one part instead of two (ip + weight)
    dns_output = '"192.168.1.1"\n'
    mocker.patch('subprocess.check_output', return_value=dns_output.encode('utf-8'))

    with pytest.raises(SystemExit) as ex:
        cpfs_nfs_common._resolve_cpfs_dns(DNS)

    assert ex.value.code != 0


def test_resolve_retries_before_final_failure(mocker):
    mock_check_output = mocker.patch(
        'subprocess.check_output',
        side_effect=Exception('resolve failed')
    )
    sleep_mock = mocker.patch('time.sleep')

    with pytest.raises(SystemExit):
        cpfs_nfs_common._resolve_cpfs_dns(DNS)

    # time.sleep should be called for all retries except the last one
    # First failure (i=RESOLVE_DNS_RETRY=5): switches to host, sleeps
    # i=4: sleeps
    # i=3: sleeps
    # i=2: sleeps
    # i=1: fatal_error, no sleep
    assert sleep_mock.call_count == cpfs_nfs_common.RESOLVE_DNS_RETRY - 1


def test_resolve_success_on_retry(mocker):
    dns_output = '"10.0.0.1 5"\n"10.0.0.2 15"\n'
    mock_check_output = mocker.patch(
        'subprocess.check_output',
        side_effect=[
            Exception('dig failed'),
            Exception('host failed'),
            dns_output.encode('utf-8'),
        ]
    )
    mocker.patch('time.sleep')

    ips, weights = cpfs_nfs_common._resolve_cpfs_dns(DNS)

    assert ips == ['10.0.0.1', '10.0.0.2']
    assert weights == [5, 15]
    assert mock_check_output.call_count == 3
