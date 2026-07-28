#!/usr/bin/env python3
from __future__ import annotations

import base64
import secrets

print("APP_SECRET_KEY=" + secrets.token_urlsafe(48))
print("MASTER_ENCRYPTION_KEY=" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"))
