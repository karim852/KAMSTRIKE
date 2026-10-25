import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.fixtures.mock_camera import MockCamera


@pytest.fixture(scope="session")
def mock_camera():
    """A deliberately vulnerable mock Hikvision-style camera on an ephemeral port."""
    with MockCamera() as cam:
        yield cam
