import io

from vulnresearch.sandbox import _read_bounded


def test_read_bounded_caps_retained_output_and_drains_stream():
    content = b"abcdefghij"
    retained, truncated = _read_bounded(io.BytesIO(content), 4)
    assert retained == b"abcd"
    assert truncated
