import pytest

from vulnresearch.execution.gce import GceCanaryError
from vulnresearch.execution.gce_rest import GceRestClient


class FakeResponse:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class PaginatedSession:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def request(self, method, url, *, params=None, json=None, timeout=None):
        self.calls.append((method, url, params))
        token = (params or {}).get("pageToken")
        return FakeResponse(self.pages[token])


def test_list_all_collects_multiple_pages():
    session = PaginatedSession(
        {
            None: {"items": [{"name": "one"}], "nextPageToken": "page-2"},
            "page-2": {"items": [{"name": "two"}]},
        }
    )
    client = GceRestClient(session=session)

    result = client._list_all("/projects/example/global/routes")

    assert result == [{"name": "one"}, {"name": "two"}]
    assert len(session.calls) == 2


def test_list_all_rejects_repeated_page_token():
    session = PaginatedSession(
        {
            None: {"items": [], "nextPageToken": "repeat"},
            "repeat": {"items": [], "nextPageToken": "repeat"},
        }
    )
    client = GceRestClient(session=session)

    with pytest.raises(GceCanaryError, match="repeated page token"):
        client._list_all("/projects/example/global/routes")

    assert len(session.calls) == 2


def test_list_all_stops_at_configured_page_limit():
    session = PaginatedSession(
        {
            None: {"items": [], "nextPageToken": "page-2"},
            "page-2": {"items": [], "nextPageToken": "page-3"},
        }
    )
    client = GceRestClient(session=session)
    client.MAX_LIST_PAGES = 2

    with pytest.raises(GceCanaryError, match="page limit"):
        client._list_all("/projects/example/global/routes")

    assert len(session.calls) == 2


def test_list_all_stops_at_configured_item_limit():
    session = PaginatedSession(
        {
            None: {
                "items": [{"name": "one"}, {"name": "two"}],
                "nextPageToken": "page-2",
            },
            "page-2": {"items": [{"name": "three"}]},
        }
    )
    client = GceRestClient(session=session)
    client.MAX_LIST_ITEMS = 2

    with pytest.raises(GceCanaryError, match="item limit"):
        client._list_all("/projects/example/global/routes")

    assert len(session.calls) == 2


def test_list_all_rejects_non_mapping_items():
    session = PaginatedSession({None: {"items": ["not-a-resource"]}})
    client = GceRestClient(session=session)

    with pytest.raises(GceCanaryError, match="invalid items collection"):
        client._list_all("/projects/example/global/routes")


@pytest.mark.parametrize("invalid_token", ["", 0, False, [], {}])
def test_list_all_rejects_malformed_present_page_token(invalid_token):
    session = PaginatedSession(
        {None: {"items": [{"name": "one"}], "nextPageToken": invalid_token}}
    )
    client = GceRestClient(session=session)

    with pytest.raises(GceCanaryError, match="invalid page token"):
        client._list_all("/projects/example/global/routes")

    assert len(session.calls) == 1
