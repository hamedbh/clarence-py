import os
import subprocess
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import engine

import clarence


@pytest.fixture
def temp_pass_store():
    with tempfile.TemporaryDirectory() as temp_dir:
        gpg_home = Path(temp_dir) / "gnupg"
        gpg_home.mkdir(mode=0o700)
        pass_store = Path(temp_dir) / "pass-store"
        pass_store.mkdir()
        old_env = {}
        old_env["PASSWORD_STORE_DIR"] = os.environ.get("PASSWORD_STORE_DIR")
        old_env["GNUPGHOME"] = os.environ.get("GNUPGHOME")
        os.environ["PASSWORD_STORE_DIR"] = str(pass_store)
        os.environ["GNUPGHOME"] = str(gpg_home)
        gpg_config = """
        %echo Generating test key
        Key-Type: RSA
        Key-Length: 2048
        Name-Real: Test User
        Name-Email: test@example.com
        Expire-Date: 0
        %no-protection
        %commit
        %echo done
        """
        subprocess.run(
            ["gpg", "--batch", "--gen-key"],
            input=gpg_config,
            text=True,
            check=True,
        )
        subprocess.run(["pass", "init", "test@example.com"], check=True)
        subprocess.run(
            ["pass", "insert", "-e", "test/secret1"],
            input="password123",
            text=True,
            check=True,
        )
        subprocess.run(
            ["pass", "insert", "-e", "api/gitlab"],
            input="gitlab_token_456",
            text=True,
            check=True,
        )
        yield pass_store

        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_get_secret(temp_pass_store):
    assert clarence.get_secret("test/secret1").reveal() == "password123"
    assert clarence.get_secret("api/gitlab").reveal() == "gitlab_token_456"


def test_f_strings(temp_pass_store):
    secret1 = clarence.get_secret("test/secret1")
    gitlab = clarence.get_secret("api/gitlab")
    assert f"{secret1}" == "p*********3"
    assert f"{gitlab}" == "g**************6"
    assert f"{secret1.reveal()}" == "password123"
    assert f"{gitlab.reveal()}" == "gitlab_token_456"

    # Test format specifiers
    assert f"{secret1:>15}" == "    p*********3"
    assert f"{secret1:<15}" == "p*********3    "
    assert f"{secret1:^15}" == "  p*********3  "
    assert f"{secret1:0>15}" == "0000p*********3"
    assert f"{secret1.reveal():>15}" == "    password123"


def test_plus_strings(temp_pass_store):
    secret1 = clarence.get_secret("test/secret1")
    gitlab = clarence.get_secret("api/gitlab")
    assert "something" + secret1 == "somethingpassword123"
    assert "something" + gitlab == "somethinggitlab_token_456"


def test_list_secrets(temp_pass_store):
    result = clarence.list_secrets()
    assert isinstance(result, clarence.SecretsList)

    output = str(result)
    assert "test" in output
    assert "api" in output

    repr_output = repr(result)
    assert "test" in repr_output
    assert "api" in repr_output

    assert str(result) == repr(result)


def test_sqlalchemy(temp_pass_store):
    secret1 = clarence.get_secret("test/secret1")
    engine_type = "mssql+pymssql"
    username = "1234567"
    host = "example.com"
    database = "testingdb"

    engine_url = engine.URL.create(
        engine_type,
        username=username,
        password=secret1.reveal(),
        host=host,
        database=database,
    )
    assert (
        engine_url.render_as_string()
        == f"{engine_type}://{username}:***@{host}/{database}"
    )
    assert (
        engine_url.render_as_string(hide_password=False)
        == f"{engine_type}://{username}:password123@{host}/{database}"
    )


def test_secret_obscure_edge_cases():
    # Test empty string
    empty_secret = clarence.Secret("")
    assert str(empty_secret) == "***"
    assert repr(empty_secret) == "***"

    # Test single character
    single_secret = clarence.Secret("a")
    assert str(single_secret) == "*****"
    assert repr(single_secret) == "*****"

    # Test two characters
    two_secret = clarence.Secret("ab")
    assert str(two_secret) == "*****"
    assert repr(two_secret) == "*****"

    # Test three characters
    three_secret = clarence.Secret("abc")
    assert str(three_secret) == "*****"
    assert repr(three_secret) == "*****"

    # Test four characters
    four_secret = clarence.Secret("abcd")
    assert str(four_secret) == "*****"
    assert repr(four_secret) == "*****"

    # Test five characters (boundary case)
    five_secret = clarence.Secret("abcde")
    assert str(five_secret) == "a***e"
    assert repr(five_secret) == "a***e"

    # Test longer string
    long_secret = clarence.Secret("password123")
    assert str(long_secret) == "p*********3"
    assert repr(long_secret) == "p*********3"
