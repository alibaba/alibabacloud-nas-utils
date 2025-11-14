import json
import logging
import os
from datetime import datetime, timedelta

import pytest

import mount_alinas
import watchdog

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

DT_PATTERN = watchdog.CERT_DATETIME_FORMAT
FS_ID = "fs-deadbeef"
COMMON_NAME = "fs-deadbeef.alinas.us-east-1.aliyuncs.com"
PID = 1234
STATE_FILE = "stunnel-config.fs-deadbeef.mount.dir.12345"
MOUNT_NAME = "fs-deadbeef.mount.dir.12345"
REGION = "us-east-1"
AP_ID = "fsap-0123456789abcdef0"
BAD_AP_ID_INCORRECT_START = "bad-fsap-0123456789abc"
BAD_AP_ID_TOO_SHORT = "fsap-0123456789abcdef"
BAD_AP_ID_BAD_CHAR = "fsap-0123456789abcdefg"
CREDENTIALS_SOURCE = "default"
ACCESS_KEY_ID_VAL = "FAKE_ALIYUN_ACCESS_KEY_ID"
SECRET_ACCESS_KEY_VAL = "FAKE_ALIYUN_SECRET_ACCESS_KEY"
SESSION_TOKEN_VAL = "FAKE_SESSION_TOKEN"
FIXED_DT = datetime(2000, 1, 1, 12, 0, 0)
CLIENT_INFO = {"source": "test", "alinas_utils_version": watchdog.VERSION}
CREDENTIALS = {
    "AccessKeyId": ACCESS_KEY_ID_VAL,
    "AccessKeySecret": SECRET_ACCESS_KEY_VAL,
    "SecurityToken": SESSION_TOKEN_VAL,
}
PUBLIC_KEY_BODY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArnlTGLBaUvhqaZuhwZdu\n"
    "YPkjCPESMszibpIyMQPzCv9R5f8UvgOkmBQx1flCJ0K7tsJf82k6LAdIiF38dkrq\n"
    "YlBfH1WGYU/plBd1LOeuTx+hsLY6k7VFiwtNVH4afg/axjCF0d3sZmNqlVbvOEf6\n"
    "FKcNnr2s/Kjsn1jgiuCxvul6NpQr7rrtANDTw31jY7ADcbSvAv2DWVlMfCH/3JFJ\n"
    "b9t9L1RAx3cUsX974VKOgnoAtb2dahq2KWErWaG2hYd4JdooiZ40qJnT+8lNSDBR\n"
    "0kT9sjBEXVi0C4QMAKWH8LuGbGgo8WT7Upyc9eZl1Oj4EXJaznLXk0fPb1nc8MpV\n"
    "YukEK8vJ2pqPECgyRhDo7xxUfhHJjoBqmWZ/5peajIvIEairZF9ujkFem9OtJiDr\n"
    "ij4eBHcwIvIY/0FNOIcsbcqJ7/vngnP81Iw6JjW7Y/ocY9JIg3Lj6ZCf4IkPTriN\n"
    "QgGM2RbXdMdoKSGvAiqX6DOe862Ub9mr3JwyjF3pDWS9AgMBAAE=\n"
    "-----END PUBLIC KEY-----"
)


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch("mount_alinas.get_target_region", return_value=REGION)
    mocker.patch("mount_alinas.get_alinas_security_credentials", return_value=CREDENTIALS)
    mocker.patch("watchdog.get_alinas_security_credentials", return_value=CREDENTIALS)


def _get_config(certificate_renewal_interval=60, client_info=None):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_alinas.CONFIG_SECTION)
    config.set(mount_alinas.CONFIG_SECTION, "state_file_dir_mode", "0755")
    config.set(
        mount_alinas.CONFIG_SECTION,
        "dns_name_format",
        "{fs_id}.alinas.{region}.aliyuncs.com",
    )
    config.add_section(watchdog.WATCHDOG_CONFIG_SECTION)
    config.set(
        watchdog.WATCHDOG_CONFIG_SECTION,
        "tls_cert_renewal_interval_min",
        str(certificate_renewal_interval),
    )
    if client_info:
        config.add_section(watchdog.CLIENT_INFO_SECTION)
        for key, value in client_info.items():
            config.set(watchdog.CLIENT_INFO_SECTION, key, value)
    return watchdog.SafeConfig(config, None, None)

def _get_mock_private_key_path(mocker, tmpdir):
    pk_path = os.path.join(str(tmpdir), "privateKey.pem")
    mocker.patch("mount_alinas.get_private_key_path", return_value=pk_path)
    mocker.patch("watchdog.get_private_key_path", return_value=pk_path)
    return pk_path


def _create_certificate_and_state(
    tls_dict,
    temp_dir,
    pk_path,
    timestamp,
    security_credentials=None,
    credentials_source=None,
    ap_id=None,
    remove_cert=False,
    client_info=None,
):
    config = _get_config()
    good_ap_id = AP_ID if ap_id else None
    mount_alinas.create_certificate(
        config,
        MOUNT_NAME,
        COMMON_NAME,
        REGION,
        FS_ID,
        security_credentials,
        good_ap_id,
        client_info,
        base_path=str(temp_dir),
    )

    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))

    public_key_present = (
        os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
        if security_credentials
        else not os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    )
    assert public_key_present

    state = {
        "pid": PID,
        "commonName": COMMON_NAME,
        "certificate": os.path.join(tls_dict["mount_dir"], "certificate.pem"),
        "certificateCreationTime": timestamp,
        "mountStateDir": MOUNT_NAME,
        "region": REGION,
        "fsId": FS_ID,
        "privateKey": pk_path,
    }

    if credentials_source:
        state["credentialsMethod"] = credentials_source

    if ap_id:
        state["accessPoint"] = ap_id

    with open(os.path.join(temp_dir, STATE_FILE), "w+") as f:
        f.write(json.dumps(state))

    if remove_cert:
        os.remove(os.path.join(tls_dict["mount_dir"], "certificate.pem"))
        assert not os.path.exists(
            os.path.join(tls_dict["mount_dir"], "certificate.pem")
        )

    return state


def _create_ca_conf_helper(
    mocker, tmpdir, current_time, ram=True, ap=True, client_info=True
):
    config = _get_config()
    tls_dict = mount_alinas.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    mount_alinas.create_required_directory(config, tls_dict["mount_dir"])
    tls_dict["certificate_path"] = os.path.join(tls_dict["mount_dir"], "config.conf")
    tls_dict["private_key"] = os.path.join(tls_dict["mount_dir"], "privateKey.pem")
    tls_dict["public_key"] = os.path.join(tls_dict["mount_dir"], "publicKey.pem")

    if ram:
        with open(tls_dict["public_key"], "w") as f:
            f.write(PUBLIC_KEY_BODY)

    mocker.patch("watchdog.get_alinas_security_credentials", return_value=CREDENTIALS)
    credentials = "dummy:lookup" if ram else None
    ap_id = AP_ID if ap else None
    client_info = CLIENT_INFO if client_info else None
    full_config_body = watchdog.create_ca_conf(
        config,
        tls_dict["certificate_path"],
        COMMON_NAME,
        tls_dict["mount_dir"],
        tls_dict["private_key"],
        current_time,
        REGION,
        FS_ID,
        credentials,
        ap_id,
        client_info,
    )
    assert os.path.exists(tls_dict["certificate_path"])

    return tls_dict, full_config_body


def _test_refresh_certificate_helper(
    mocker,
    tmpdir,
    caplog,
    minutes_back,
    renewal_interval=60,
    with_ram=True,
    with_ap=True,
):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config(certificate_renewal_interval=renewal_interval)
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    minutes_back = (FIXED_DT - timedelta(minutes=minutes_back)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))

    if not with_ram and with_ap:
        state = _create_certificate_and_state(
            tls_dict, str(tmpdir), pk_path, minutes_back, ap_id=AP_ID
        )
    elif with_ram and not with_ap:
        state = _create_certificate_and_state(
            tls_dict,
            str(tmpdir),
            pk_path,
            minutes_back,
            security_credentials=CREDENTIALS,
            credentials_source=CREDENTIALS_SOURCE,
        )
    else:
        state = _create_certificate_and_state(
            tls_dict,
            str(tmpdir),
            pk_path,
            minutes_back,
            security_credentials=CREDENTIALS,
            credentials_source=CREDENTIALS_SOURCE,
            ap_id=AP_ID,
        )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    with open(os.path.join(str(tmpdir), STATE_FILE), "r") as state_json:
        state = json.load(state_json)

    if not with_ram and with_ap:
        assert state["accessPoint"] == AP_ID
        assert not state.get("credentialsMethod")
        assert not os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    elif with_ram and not with_ap:
        assert "accessPoint" not in state
        # assert state["credentialsMethod"] == CREDENTIALS_SOURCE
        assert os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    else:
        assert state["accessPoint"] == AP_ID
        assert state["credentialsMethod"] == CREDENTIALS_SOURCE
        assert os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) > datetime.strptime(minutes_back, DT_PATTERN)
    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))

    return caplog


def test_do_not_refresh_self_signed_certificate(mocker, tmpdir):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    current_time_formatted = FIXED_DT.strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict, str(tmpdir), pk_path, current_time_formatted, ap_id=AP_ID
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    with open(os.path.join(str(tmpdir), STATE_FILE), "r") as state_json:
        state = json.load(state_json)

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) == datetime.strptime(current_time_formatted, DT_PATTERN)
    assert state["accessPoint"] == AP_ID
    assert not state.get("credentialsMethod")
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))


"""
def test_do_not_refresh_self_signed_certificate_bad_ap_id_incorrect_start(
    mocker, tmpdir, caplog
):
    caplog.set_level(logging.ERROR)
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict,
        str(tmpdir),
        pk_path,
        four_hours_back,
        ap_id=BAD_AP_ID_INCORRECT_START,
        remove_cert=True,
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) == datetime.strptime(four_hours_back, DT_PATTERN)
    assert not state["accessPoint"] == AP_ID
    assert (
        'Access Point ID "%s" has been changed in the state file to a malformed format'
        % BAD_AP_ID_INCORRECT_START
        in caplog.text
    )


def test_do_not_refresh_self_signed_certificate_bad_ap_id_too_short(
    mocker, tmpdir, caplog
):
    caplog.set_level(logging.ERROR)
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict,
        str(tmpdir),
        pk_path,
        four_hours_back,
        ap_id=BAD_AP_ID_TOO_SHORT,
        remove_cert=True,
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) == datetime.strptime(four_hours_back, DT_PATTERN)
    assert not state["accessPoint"] == AP_ID
    assert (
        'Access Point ID "%s" has been changed in the state file to a malformed format'
        % BAD_AP_ID_TOO_SHORT
        in caplog.text
    )


def test_do_not_refresh_self_signed_certificate_bad_ap_id_bad_char(
    mocker, tmpdir, caplog
):
    caplog.set_level(logging.ERROR)
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict,
        str(tmpdir),
        pk_path,
        four_hours_back,
        ap_id=BAD_AP_ID_BAD_CHAR,
        remove_cert=True,
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) == datetime.strptime(four_hours_back, DT_PATTERN)
    assert not state["accessPoint"] == AP_ID
    assert (
        'Access Point ID "%s" has been changed in the state file to a malformed format'
        % BAD_AP_ID_BAD_CHAR
        in caplog.text
    )
"""


def test_recreate_missing_self_signed_certificate(mocker, tmpdir):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict, str(tmpdir), pk_path, four_hours_back, ap_id=AP_ID, remove_cert=True
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) > datetime.strptime(four_hours_back, DT_PATTERN)

    assert state["accessPoint"] == AP_ID
    assert not state.get("credentialsMethod")
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))


def test_refresh_self_signed_certificate_without_ram_with_ap_id(mocker, caplog, tmpdir):
    _test_refresh_certificate_helper(mocker, tmpdir, caplog, 240, with_ram=False)


def test_refresh_self_signed_certificate_with_ram_without_ap_id(mocker, caplog, tmpdir):
    _test_refresh_certificate_helper(mocker, tmpdir, caplog, 240, with_ap=False)


def test_refresh_self_signed_certificate_with_ram_with_ap_id(mocker, caplog, tmpdir):
    _test_refresh_certificate_helper(mocker, tmpdir, caplog, 240)


def test_refresh_self_signed_certificate_custom_renewal_interval(
    mocker, caplog, tmpdir
):
    _test_refresh_certificate_helper(mocker, tmpdir, caplog, 45, renewal_interval=30)


def test_refresh_self_signed_certificate_invalid_refresh_interval(
    mocker, caplog, tmpdir
):
    caplog.set_level(logging.WARNING)
    caplog = _test_refresh_certificate_helper(
        mocker, tmpdir, caplog, 240, renewal_interval="not_an_int"
    )

    assert (
        'Bad tls_cert_renewal_interval_min value, "not_an_int", in config file "/etc/aliyun/alinas/alinas-utils.conf". Defaulting'
        " to 15 minutes." in caplog.text
    )


def test_refresh_self_signed_certificate_too_low_refresh_interval(
    mocker, caplog, tmpdir
):
    caplog.set_level(logging.WARNING)
    caplog = _test_refresh_certificate_helper(
        mocker, tmpdir, caplog, 240, renewal_interval=0
    )

    assert (
        'tls_cert_renewal_interval_min value in config file "/etc/aliyun/alinas/alinas-utils.conf" is lower than 1 minute. '
        "Defaulting to 15 minutes." in caplog.text
    )


def test_refresh_self_signed_certificate_send_sighup(mocker, tmpdir, caplog):
    caplog.set_level(logging.INFO)
    process_group = "fake_pg"

    mocker.patch("watchdog.is_pid_running", return_value=True)
    mocker.patch("os.getpgid", return_value=process_group)
    mocker.patch("os.killpg")

    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (datetime.utcnow() - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict, str(tmpdir), pk_path, four_hours_back, ap_id=AP_ID
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    assert (
        "SIGHUP signal to stunnel. PID: %d, group ID: %s" % (PID, process_group)
        in caplog.text
    )


def test_refresh_self_signed_certificate_pid_not_running(mocker, tmpdir, caplog):
    caplog.set_level(logging.WARN)

    mocker.patch("watchdog.is_pid_running", return_value=False)

    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (datetime.utcnow() - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict, str(tmpdir), pk_path, four_hours_back, False, ap_id=AP_ID
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    assert "TLS tunnel is not running for" in caplog.text


def test_create_canonical_request_without_token(mocker):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    public_key_hash = "fake_public_key_hash"
    canonical_request_out = watchdog.create_canonical_request(
        public_key_hash, FIXED_DT, ACCESS_KEY_ID_VAL, REGION, FS_ID
    )

    assert (
        "GET\n/\nAction=Connect&PublicKeyHash=fake_public_key_hash&X-Alinas-Algorithm=ALIYUN4-HMAC-SHA256&X-Alinas-Credential="
        "FAKE_ALIYUN_ACCESS_KEY_ID%2F20000101%2Fus-east-1%2Faliyun-alinas%2Faliyun4_request&X-Alinas-Date=20000101T120000Z&"
        "X-Alinas-Expires=86400&X-Alinas-SignedHeaders=host\nhost:fs-deadbeef\nhost\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        == canonical_request_out
    )


def test_create_canonical_request_with_token(mocker):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    public_key_hash = "fake_public_key_hash"
    canonical_request_out = watchdog.create_canonical_request(
        public_key_hash, FIXED_DT, ACCESS_KEY_ID_VAL, REGION, FS_ID, SESSION_TOKEN_VAL
    )

    assert (
        "GET\n/\nAction=Connect&PublicKeyHash=fake_public_key_hash&X-Alinas-Algorithm=ALIYUN4-HMAC-SHA256&X-Alinas-Credential="
        "FAKE_ALIYUN_ACCESS_KEY_ID%2F20000101%2Fus-east-1%2Faliyun-alinas%2Faliyun4_request&X-Alinas-Date=20000101T120000Z&"
        "X-Alinas-Expires=86400&X-Alinas-Security-Token=FAKE_SESSION_TOKEN&X-Alinas-SignedHeaders=host\nhost:fs-deadbeef\nhost"
        "\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        == canonical_request_out
    )


def test_get_public_key_sha1(tmpdir):
    fake_public_key_filename = "fake_public_key.pem"
    fake_public_key_path = os.path.join(str(tmpdir), fake_public_key_filename)
    tmpdir.join(fake_public_key_filename).write(PUBLIC_KEY_BODY)

    sha1_result = watchdog.get_public_key_sha1(fake_public_key_path)

    assert sha1_result == "f1b13cdf5a5478fc9cc16502040f126e58dfa389"


def test_create_string_to_sign(mocker):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    canonical_request = "canonical_request"

    string_to_sign_output = watchdog.create_string_to_sign(
        canonical_request, FIXED_DT, REGION
    )

    assert (
        "ALIYUN4-HMAC-SHA256\n20000101T120000Z\n20000101/us-east-1/aliyun-alinas/aliyun4_request\n"
        "572b1e335109068b81e4def81524c5fe5d0e385143b5656cbf2f7c88e5c1a51e"
        == string_to_sign_output
    )


def test_calculate_signature(mocker):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    string_to_sign = "string_to_sign"

    signature_output = watchdog.calculate_signature(
        string_to_sign, FIXED_DT, SECRET_ACCESS_KEY_VAL, REGION
    )

    assert (
        "60b4ec4908d07ce494ff8853509bc85bf12b6f93f897aab58f5482cf5759044c"
        == signature_output
    )


def test_recreate_certificate_primary_assets_created(mocker, tmpdir):
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    watchdog.recreate_certificate(
        config,
        MOUNT_NAME,
        COMMON_NAME,
        FS_ID,
        None,
        AP_ID,
        REGION,
        base_path=str(tmpdir),
    )
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))


def _test_recreate_certificate_with_valid_client_source_config(
    mocker, tmpdir, client_source
):
    config = _get_config(client_info={"source": client_source})
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    tmp_config_path = os.path.join(str(tmpdir), MOUNT_NAME, "tmpConfig")
    current_time = mount_alinas.get_utc_now()
    watchdog.recreate_certificate(
        config,
        MOUNT_NAME,
        COMMON_NAME,
        FS_ID,
        CREDENTIALS,
        AP_ID,
        REGION,
        base_path=str(tmpdir),
    )

    expected_client_info = {
        "source": client_source,
        "alinas_utils_version": watchdog.VERSION,
    }

    with open(os.path.join(tls_dict["mount_dir"], "config.conf")) as f:
        conf_body = f.read()
        assert conf_body == watchdog.create_ca_conf(
            config,
            tmp_config_path,
            COMMON_NAME,
            tls_dict["mount_dir"],
            pk_path,
            current_time,
            REGION,
            FS_ID,
            CREDENTIALS,
            AP_ID,
            expected_client_info,
        )
    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))


def test_recreate_certificate_with_valid_client_source(mocker, tmpdir):
    _test_recreate_certificate_with_valid_client_source_config(mocker, tmpdir, "TEST")


def _test_recreate_certificate_with_invalid_client_source_config(
    mocker, tmpdir, client_source
):
    config = (
        _get_config(client_info={"source": client_source})
        if client_source
        else _get_config()
    )
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    tmp_config_path = os.path.join(str(tmpdir), MOUNT_NAME, "tmpConfig")
    current_time = mount_alinas.get_utc_now()
    watchdog.recreate_certificate(
        config,
        MOUNT_NAME,
        COMMON_NAME,
        FS_ID,
        CREDENTIALS,
        AP_ID,
        REGION,
        base_path=str(tmpdir),
    )

    # Any invalid or not given client source should be marked as unknown
    expected_client_info = {"source": "unknown", "alinas_utils_version": watchdog.VERSION}

    with open(os.path.join(tls_dict["mount_dir"], "config.conf")) as f:
        conf_body = f.read()
        assert conf_body == watchdog.create_ca_conf(
            config,
            tmp_config_path,
            COMMON_NAME,
            tls_dict["mount_dir"],
            pk_path,
            current_time,
            REGION,
            FS_ID,
            CREDENTIALS,
            AP_ID,
            expected_client_info,
        )
    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))


def test_certificate_with_ram_with_ap_with_none_client_source_config(mocker, tmpdir):
    _test_recreate_certificate_with_invalid_client_source_config(mocker, tmpdir, None)


def test_certificate_with_ram_with_ap_with_empty_client_source_config(mocker, tmpdir):
    _test_recreate_certificate_with_invalid_client_source_config(mocker, tmpdir, "")


def test_certificate_with_ram_with_ap_with_long_client_source_config(mocker, tmpdir):
    _test_recreate_certificate_with_invalid_client_source_config(
        mocker, tmpdir, "a" * 101
    )


def test_create_ca_supporting_dirs(tmpdir):
    config = _get_config()
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    watchdog.ca_dirs_check(config, tls_dict["database_dir"], tls_dict["certs_dir"])
    assert os.path.exists(tls_dict["database_dir"])
    assert os.path.exists(tls_dict["certs_dir"])


def test_create_ca_supporting_files(tmpdir):
    config = _get_config()
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    index = tls_dict["index"]
    index_attr = tls_dict["index_attr"]
    serial = tls_dict["serial"]
    rand = tls_dict["rand"]

    watchdog.ca_dirs_check(config, tls_dict["database_dir"], tls_dict["certs_dir"])
    watchdog.ca_supporting_files_check(index, index_attr, serial, rand)
    with open(index_attr, "r") as index_attr_file:
        index_attr_content = index_attr_file.read()
    with open(serial, "r") as serial_file:
        serial_content = serial_file.read()

    assert os.path.exists(index)
    assert os.path.exists(index_attr)
    assert os.path.exists(serial)
    assert os.path.exists(rand)

    assert "unique_subject = no" == index_attr_content
    assert "00" == serial_content


def test_create_ca_conf_with_awsprofile_no_credentials_found(mocker, caplog, tmpdir):
    config = _get_config()
    mocker.patch("watchdog.get_alinas_security_credentials", return_value=None)
    watchdog.create_ca_conf(
        config,
        None,
        None,
        str(tmpdir),
        None,
        None,
        None,
        None,
        CREDENTIALS_SOURCE,
        None,
    )
    assert (
        "Failed to retrieve aliyun security credentials using lookup method: %s"
        % CREDENTIALS_SOURCE
        in [rec.message for rec in caplog.records][0]
    )


def test_create_ca_conf_without_client_info(mocker, tmpdir):
    current_time = mount_alinas.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(
        mocker, tmpdir, current_time, ram=True, ap=True, client_info=False
    )

    ca_extension_body = (
        "[ v3_ca ]\n"
        "subjectKeyIdentifier = hash\n"
        "1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:alinas_client_auth\n"
        "1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s"
    ) % (AP_ID, FS_ID)
    alinas_client_auth_body = watchdog.alinas_client_auth_builder(
        tls_dict["public_key"],
        CREDENTIALS["AccessKeyId"],
        CREDENTIALS["AccessKeySecret"],
        current_time,
        REGION,
        FS_ID,
        CREDENTIALS["SecurityToken"],
    )
    alinas_client_info_body = ""
    matching_config_body = watchdog.CA_CONFIG_BODY % (
        tls_dict["mount_dir"],
        tls_dict["private_key"],
        COMMON_NAME,
        ca_extension_body,
        alinas_client_auth_body,
        alinas_client_info_body,
    )

    assert full_config_body == matching_config_body


def test_create_ca_conf_with_all(mocker, tmpdir):
    current_time = mount_alinas.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(
        mocker, tmpdir, current_time, ram=True, ap=True, client_info=True
    )

    ca_extension_body = (
        "[ v3_ca ]\n"
        "subjectKeyIdentifier = hash\n"
        "1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:alinas_client_auth\n"
        "1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:alinas_client_info"
    ) % (AP_ID, FS_ID)
    alinas_client_auth_body = watchdog.alinas_client_auth_builder(
        tls_dict["public_key"],
        CREDENTIALS["AccessKeyId"],
        CREDENTIALS["AccessKeySecret"],
        current_time,
        REGION,
        FS_ID,
        CREDENTIALS["SecurityToken"],
    )
    alinas_client_info_body = watchdog.alinas_client_info_builder(CLIENT_INFO, REGION)
    matching_config_body = watchdog.CA_CONFIG_BODY % (
        tls_dict["mount_dir"],
        tls_dict["private_key"],
        COMMON_NAME,
        ca_extension_body,
        alinas_client_auth_body,
        alinas_client_info_body,
    )

    assert full_config_body == matching_config_body


def test_create_ca_conf_with_ram_no_accesspoint(mocker, tmpdir):
    current_time = mount_alinas.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(
        mocker, tmpdir, current_time, ram=True, ap=False, client_info=True
    )

    ca_extension_body = (
        "[ v3_ca ]\n"
        "subjectKeyIdentifier = hash\n"
        "1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:alinas_client_auth\n"
        "1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:alinas_client_info"
    ) % (FS_ID)
    alinas_client_auth_body = watchdog.alinas_client_auth_builder(
        tls_dict["public_key"],
        CREDENTIALS["AccessKeyId"],
        CREDENTIALS["AccessKeySecret"],
        current_time,
        REGION,
        FS_ID,
        CREDENTIALS["SecurityToken"],
    )
    alinas_client_info_body = watchdog.alinas_client_info_builder(CLIENT_INFO, REGION)
    matching_config_body = watchdog.CA_CONFIG_BODY % (
        tls_dict["mount_dir"],
        tls_dict["private_key"],
        COMMON_NAME,
        ca_extension_body,
        alinas_client_auth_body,
        alinas_client_info_body,
    )

    assert full_config_body == matching_config_body


def test_create_ca_conf_with_accesspoint_no_ram(mocker, tmpdir):
    current_time = mount_alinas.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(
        mocker, tmpdir, current_time, ram=False, ap=True, client_info=True
    )

    ca_extension_body = (
        "[ v3_ca ]\n"
        "subjectKeyIdentifier = hash\n"
        "1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:alinas_client_info"
    ) % (AP_ID, FS_ID)
    alinas_client_auth_body = ""
    alinas_client_info_body = watchdog.alinas_client_info_builder(CLIENT_INFO, REGION)
    matching_config_body = watchdog.CA_CONFIG_BODY % (
        tls_dict["mount_dir"],
        tls_dict["private_key"],
        COMMON_NAME,
        ca_extension_body,
        alinas_client_auth_body,
        alinas_client_info_body,
    )

    assert full_config_body == matching_config_body