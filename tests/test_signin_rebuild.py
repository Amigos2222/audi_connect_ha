"""Sign-in rebuild (#846): Audi withdrew the device_code grant from the myAudi
client, so the device authorization endpoint answers

    HTTP 403 {"error":"unauthorized_client",
              "error_description":"client is not allowed to use the device_code grant"}

for every account. These tests pin the replacement: the refusal is recognised as
its own error so the flow can fall back, and browser sign-in (authorization code
+ PKCE) completes against either token endpoint.

No network: AudiAPI is replaced with a recorder and the session finalisation is
stubbed out.
"""

from __future__ import annotations

import asyncio
import base64
import json
from hashlib import sha256
from urllib.parse import parse_qs, urlparse

import pytest

from custom_components.audiconnect.audi_services import (
    BROWSER_REDIRECT_URI,
    IDK_TOKEN_ENDPOINT,
    AudiAuthError,
    AudiDeviceGrantUnavailable,
    AudiService,
)

BFF_TOKEN_ENDPOINT = "https://emea.bff.cariad.digital/auth/v1/idk/oidc/token"
DEVICE_ENDPOINT = "https://identity.vwgroup.io/oidc/v1/device_authorization"
CLIENT_ID = "09b6cbec-cd19-4589-82fd-363dfa8c24da@apps_vw-dilab_com"


class FakeAPI:
    """Stands in for AudiAPI: records calls, replays canned bodies."""

    def __init__(self, responses: dict[str, list[str]]) -> None:
        self._responses = {k: list(v) for k, v in responses.items()}
        self.calls: list[tuple[str, str, str]] = []

    async def request(self, method, url, data, **kwargs):
        self.calls.append((method, url, data))
        queue = self._responses.get(url)
        if not queue:
            raise AssertionError(f"unexpected request to {url}")
        body = queue.pop(0)
        return None, body

    def use_token(self, _token):
        pass

    def set_xclient_id(self, _xclientid):
        pass


def _service(responses):
    api = FakeAPI(responses)
    service = AudiService(api, "DE", None, 0)
    service._client_id = CLIENT_ID
    service._tokenEndpoint = BFF_TOKEN_ENDPOINT
    service._authorizationEndpoint = "https://identity.vwgroup.io/oidc/v1/authorize"
    service._deviceAuthorizationEndpoint = DEVICE_ENDPOINT

    async def _no_discovery():
        return None

    async def _no_finalize():
        service.finalized = True

    service._discover_endpoints = _no_discovery
    service._finalize_session = _no_finalize
    service.finalized = False
    return service, api


def _body(payload):
    return json.dumps(payload)


TOKEN_RESPONSE = _body(
    {
        "access_token": "at",
        "refresh_token": "rt",
        "id_token": "idt",
        "expires_in": 3600,
    }
)


# --------------------------------------------------------------- device grant
def test_withdrawn_device_grant_is_its_own_error():
    """The live refusal must be distinguishable, so the flow can fall back."""
    service, _ = _service(
        {
            DEVICE_ENDPOINT: [
                _body(
                    {
                        "error": "unauthorized_client",
                        "error_description": "client is not allowed to use the device_code grant",
                    }
                )
            ]
        }
    )
    with pytest.raises(AudiDeviceGrantUnavailable) as excinfo:
        asyncio.run(service.request_device_code())
    assert "not allowed to use the device_code grant" in str(excinfo.value)


def test_other_device_failures_stay_generic():
    """A transient failure must not be mistaken for a withdrawn grant."""
    service, _ = _service(
        {DEVICE_ENDPOINT: [_body({"error": "temporarily_unavailable"})]}
    )
    with pytest.raises(AudiAuthError) as excinfo:
        asyncio.run(service.request_device_code())
    assert not isinstance(excinfo.value, AudiDeviceGrantUnavailable)


def test_device_code_still_returned_when_the_grant_works():
    """If Audi restores the grant, nothing here should get in the way."""
    service, _ = _service(
        {
            DEVICE_ENDPOINT: [
                _body({"device_code": "dc", "user_code": "ABCD-EFGH", "expires_in": 300})
            ]
        }
    )
    assert asyncio.run(service.request_device_code())["user_code"] == "ABCD-EFGH"


# ------------------------------------------------------- redirect parsing
@pytest.mark.parametrize(
    "pasted",
    [
        "myaudi:///?code=THECODE&state=S",
        "  myaudi:///?code=THECODE&state=S  ",
        '"myaudi:///?code=THECODE&state=S"',
        "myaudi:///#code=THECODE&state=S",
        "https://example.invalid/cb?code=THECODE&state=S",
    ],
)
def test_redirect_parsing_accepts_what_users_actually_paste(pasted):
    parsed = AudiService.parse_authorization_response(pasted)
    assert parsed["code"] == "THECODE"


def test_bare_code_is_accepted():
    assert AudiService.parse_authorization_response("THECODE")["code"] == "THECODE"


def test_empty_paste_is_rejected():
    with pytest.raises(AudiAuthError):
        AudiService.parse_authorization_response("   ")


# ---------------------------------------------------------- browser sign-in
def test_authorization_url_carries_a_valid_pkce_challenge():
    service, _ = _service({})
    url = asyncio.run(service.build_authorization_url())
    query = parse_qs(urlparse(url).query)

    assert query["response_type"] == ["code"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["redirect_uri"] == [BROWSER_REDIRECT_URI]
    assert query["code_challenge_method"] == ["S256"]

    expected = (
        base64.urlsafe_b64encode(sha256(service._pkce_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    assert query["code_challenge"] == [expected]
    assert service.has_pending_authorization()


def test_browser_login_exchanges_the_code_and_opens_the_session():
    service, api = _service({IDK_TOKEN_ENDPOINT: [TOKEN_RESPONSE]})
    asyncio.run(service.build_authorization_url())
    verifier = service._pkce_verifier
    state = service._auth_state

    asyncio.run(service.complete_browser_login(f"myaudi:///?code=C&state={state}"))

    sent = parse_qs(api.calls[-1][2])
    assert sent["grant_type"] == ["authorization_code"]
    assert sent["code"] == ["C"]
    assert sent["code_verifier"] == [verifier]
    assert sent["redirect_uri"] == [BROWSER_REDIRECT_URI]
    assert service._bearer_token_json["refresh_token"] == "rt"
    assert service.finalized
    # The code is spent, so the flow knows to mint a fresh link.
    assert not service.has_pending_authorization()


def test_code_exchange_falls_back_to_the_discovered_endpoint():
    """The issuer is tried first; attestation lives on the BFF proxy. If the
    issuer refuses, the proxy still gets a turn rather than the sign-in dying."""
    service, api = _service(
        {
            IDK_TOKEN_ENDPOINT: [_body({"error": "invalid_request"})],
            BFF_TOKEN_ENDPOINT: [TOKEN_RESPONSE],
        }
    )
    asyncio.run(service.build_authorization_url())
    asyncio.run(service.complete_browser_login("myaudi:///?code=C"))

    assert [c[1] for c in api.calls] == [IDK_TOKEN_ENDPOINT, BFF_TOKEN_ENDPOINT]
    assert service.finalized


def test_refresh_keeps_using_the_discovered_endpoint_first():
    """Existing installations refresh against the BFF and must keep doing so."""
    service, api = _service({BFF_TOKEN_ENDPOINT: [TOKEN_RESPONSE]})
    assert asyncio.run(service.login_with_refresh_token("old")) == "rt"
    assert api.calls[0][1] == BFF_TOKEN_ENDPOINT


def test_rejection_by_every_endpoint_reports_what_audi_said():
    service, _ = _service(
        {
            IDK_TOKEN_ENDPOINT: [_body({"error_description": "code expired"})],
            BFF_TOKEN_ENDPOINT: [_body({"error": "invalid assertion headers"})],
        }
    )
    asyncio.run(service.build_authorization_url())
    with pytest.raises(AudiAuthError) as excinfo:
        asyncio.run(service.complete_browser_login("myaudi:///?code=C"))
    message = str(excinfo.value)
    assert "code expired" in message and "invalid assertion headers" in message


def test_state_mismatch_is_refused():
    service, _ = _service({IDK_TOKEN_ENDPOINT: [TOKEN_RESPONSE]})
    asyncio.run(service.build_authorization_url())
    with pytest.raises(AudiAuthError):
        asyncio.run(service.complete_browser_login("myaudi:///?code=C&state=somebodyelse"))


def test_error_redirect_is_reported_verbatim():
    service, _ = _service({})
    asyncio.run(service.build_authorization_url())
    with pytest.raises(AudiAuthError) as excinfo:
        asyncio.run(
            service.complete_browser_login(
                "myaudi:///?error=access_denied&error_description=User+said+no"
            )
        )
    assert "User said no" in str(excinfo.value)


def test_exchange_without_a_started_sign_in_is_refused():
    service, _ = _service({})
    with pytest.raises(AudiAuthError):
        asyncio.run(service.complete_browser_login("myaudi:///?code=C"))
