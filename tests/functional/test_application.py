#  Copyright 2026 SURF.
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
from urllib.parse import quote_plus

import pytest
from flask.testing import FlaskClient


def test_root_not_found(client: FlaskClient) -> None:
    """Verify that the root endpoint returns 404."""
    response = client.get("/")
    assert response.status_code == 404


def test_validate_without_dn_header(client: FlaskClient) -> None:
    """Verify that the /validate endpoint returns 403 without DN header."""
    response = client.get("/validate")
    assert response.status_code == 403
    assert response.data == b"Forbidden"


def test_validate_with_valid_dn_header(client: FlaskClient) -> None:
    """Verify that the /validate endpoint returns 200 with correct DN header."""
    headers = {
        "ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=Z",
    }
    response = client.get("/validate", headers=headers)
    assert response.status_code == 200
    assert response.data == b"OK"


def test_validate_with_second_valid_dn_header(client: FlaskClient) -> None:
    """Verify that the second allowed DN also returns 200."""
    headers = {
        "ssl-client-subject-dn": "CN=CertB,OU=Dept X,O=Company Y,C=Z",
    }
    response = client.get("/validate", headers=headers)
    assert response.status_code == 200
    assert response.data == b"OK"


def test_validate_with_invalid_dn_header(client: FlaskClient) -> None:
    """Verify that the /validate endpoint returns 403 with incorrect DN header."""
    headers = {
        "ssl-client-subject-dn": "CN=CertA,OU=Dept X,O=Company Y,C=ZZZZZZZZZZ",
    }
    response = client.get("/validate", headers=headers)
    assert response.status_code == 403
    assert response.data == b"Forbidden"


def test_validate_with_empty_dn_header(client: FlaskClient) -> None:
    """Verify that an empty DN header returns 403."""
    headers = {
        "ssl-client-subject-dn": "",
    }
    response = client.get("/validate", headers=headers)
    assert response.status_code == 403


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_validate_rejects_non_get_methods(client: FlaskClient, method: str) -> None:
    """Verify that the /validate endpoint only accepts GET requests."""
    response = getattr(client, method)("/validate")
    assert response.status_code == 405


# ---------------------------------------------------------------------------
# PEM header (X-Forwarded-Tls-Client-Cert)
# ---------------------------------------------------------------------------


def test_validate_pem_header_allowed(client: FlaskClient, pem_header_value: str, test_cert_dn: str) -> None:
    """PEM header with DN in allow-list returns 200."""
    from nsi_auth import state

    state.allowed_client_subject_dn = [test_cert_dn]
    response = client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert": pem_header_value})
    assert response.status_code == 200
    assert response.data == b"OK"


def test_validate_pem_header_not_in_allowlist(client: FlaskClient, pem_header_value: str) -> None:
    """PEM header with DN not in allow-list returns 403."""
    from nsi_auth import state

    state.allowed_client_subject_dn = ["CN=SomeoneElse,C=NL"]
    response = client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert": pem_header_value})
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Traefik Info header (X-Forwarded-Tls-Client-Cert-Info)
# ---------------------------------------------------------------------------


def test_validate_traefik_info_header_allowed(client: FlaskClient) -> None:
    """URL-encoded Subject= info header with DN in allow-list returns 200."""
    from nsi_auth import state

    dn = "CN=Test,O=Org,C=US"
    state.allowed_client_subject_dn = [dn]
    encoded = quote_plus(f'Subject="{dn}"')
    response = client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": encoded})
    assert response.status_code == 200
    assert response.data == b"OK"


def test_validate_traefik_info_header_not_in_allowlist(client: FlaskClient) -> None:
    """URL-encoded Subject= info header with DN not in allow-list returns 403."""
    from nsi_auth import state

    state.allowed_client_subject_dn = ["CN=SomeoneElse,C=NL"]
    encoded = quote_plus('Subject="CN=Test,O=Org,C=US"')
    response = client.get("/validate", headers={"X-Forwarded-Tls-Client-Cert-Info": encoded})
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Priority and fallback behaviour
# ---------------------------------------------------------------------------


def test_validate_pem_takes_priority_over_info(
    client: FlaskClient, pem_header_value: str, test_cert_dn: str
) -> None:
    """When both headers are present, PEM DN is used (not Info DN)."""
    from nsi_auth import state

    # Only the PEM cert's DN is allowed; Info header carries a different DN
    state.allowed_client_subject_dn = [test_cert_dn]
    info_encoded = quote_plus('Subject="CN=Different,C=NL"')
    response = client.get(
        "/validate",
        headers={
            "X-Forwarded-Tls-Client-Cert": pem_header_value,
            "X-Forwarded-Tls-Client-Cert-Info": info_encoded,
        },
    )
    assert response.status_code == 200


def test_validate_pem_parse_failure_falls_back_to_info(client: FlaskClient) -> None:
    """Garbage PEM header falls back to Info header for DN extraction."""
    from nsi_auth import state

    dn = "CN=Test,O=Org,C=US"
    state.allowed_client_subject_dn = [dn]
    info_encoded = quote_plus(f'Subject="{dn}"')
    response = client.get(
        "/validate",
        headers={
            "X-Forwarded-Tls-Client-Cert": "not-a-valid-pem",
            "X-Forwarded-Tls-Client-Cert-Info": info_encoded,
        },
    )
    assert response.status_code == 200
