"""Safe application build metadata.

Values supplied by the image build are deliberately non-secret and are used by
offline backup metadata. They are not exposed by the public health endpoints.
"""

from __future__ import annotations

import os


APPLICATION_VERSION = "0.9.0"
GIT_COMMIT = os.getenv("APP_GIT_COMMIT", "unknown").strip() or "unknown"
BUILD_TIMESTAMP = os.getenv("APP_BUILD_TIMESTAMP", "unknown").strip() or "unknown"
