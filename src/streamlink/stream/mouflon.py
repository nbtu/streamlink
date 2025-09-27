from __future__ import annotations

import logging
import re
import base64
import hashlib
from typing import TYPE_CHECKING

from requests import Response

from streamlink.exceptions import StreamError
from streamlink.plugin import Plugin, pluginmatcher
from streamlink.stream.hls import HLSStream, HLSStreamWorker, HLSStreamReader
from streamlink.stream.hls.m3u8 import parse_m3u8

if TYPE_CHECKING:
    from streamlink.session import Streamlink

log = logging.getLogger(__name__)

class MouflonDecryptor:
    _cached_hash = {}
    key = "Quean4cai9boJa5a"

    @classmethod
    def _compute_hash(cls, key: str) -> bytes:
        if key not in cls._cached_hash:
            cls._cached_hash[key] = hashlib.sha256(key.encode("utf-8")).digest()
        return cls._cached_hash[key]

    @classmethod
    def decode(cls, encrypted_b64: str) -> str:
        hash_bytes = cls._compute_hash(cls.key)
        hash_len = len(hash_bytes)
        padded = encrypted_b64 + "=="
        encrypted_data = base64.b64decode(padded)
        decrypted_bytes = bytearray()
        for i, cipher_byte in enumerate(encrypted_data):
            decrypted_bytes.append(cipher_byte ^ hash_bytes[i % hash_len])
        return decrypted_bytes.decode("utf-8", errors="ignore")

class MouflonHLSStreamWorker(HLSStreamWorker):
    SEGMENT_QUEUE_TIMING_THRESHOLD_MIN = 15.0

    def _fetch_playlist(self) -> Response:
        res = self.session.http.get(
            self.stream.url,
            exception=StreamError,
            retries=self.playlist_reload_retries,
            **self.reader.request_params,
        )
        res.encoding = "utf-8"

        # 解密 #EXT-X-MOUFLON:FILE: 标签
        lines = res.text.splitlines()
        new_lines = []
        for i, line in enumerate(lines):
            if line.startswith("#EXT-X-MOUFLON:FILE:"):
                enc_str = line.split(":", 2)[2]  # 获取加密串
                real_url = MouflonDecryptor.decode(enc_str)
                # 替换下一行的占位符 URL
                if i + 1 < len(lines) and lines[i + 1] and not lines[i + 1].startswith("#"):
                    lines[i + 1] = real_url
            new_lines.append(line)
        res._content = "\n".join(new_lines).encode("utf-8")

        return res

class MouflonHLSStreamReader(HLSStreamReader):
    __worker__ = MouflonHLSStreamWorker

class MouflonHLSStream(HLSStream):
    __reader__ = MouflonHLSStreamReader

@pluginmatcher(re.compile(
    r"https://[\w-]+\.doppiocdn\..*\.m3u8"  # 匹配 https://*.doppiocdn.*.m3u8
))
class MouflonPlugin(Plugin):
    def _get_streams(self):
        try:
            # 使用自定义的 HLSStream 类
            stream = MouflonHLSStream(self.session, self.url)
            return {"live": stream}
        except StreamError as err:
            log.error(f"Failed to fetch streams: {err}")
            return {}

__plugin__ = MouflonPlugin
