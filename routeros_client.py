"""RouterOS API client + persistent connection.

Kept as a separate module so a future connection-handling fix only needs to
be made in one place rather than re-implemented by hand inside server.py.
"""

import socket
import struct
import hashlib
import threading
import time


class RouterOSAPI:
    """Minimal synchronous RouterOS API client (port 8728)."""

    def __init__(self, host, port, username, password, timeout=10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        self._login()

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    # ── length encoding ───────────────────────────────────────────────────────

    def _encode_length(self, length):
        if length < 0x80:
            return bytes([length])
        elif length < 0x4000:
            length |= 0x8000
            return struct.pack("!H", length)
        elif length < 0x200000:
            length |= 0xC00000
            return struct.pack("!I", length)[1:]
        elif length < 0x10000000:
            length |= 0xE0000000
            return struct.pack("!I", length)
        else:
            return b'\xF0' + struct.pack("!I", length)

    def _decode_length(self):
        b = self._recv_exact(1)
        first = b[0]
        if first < 0x80:
            return first
        elif first < 0xC0:
            second = self._recv_exact(1)[0]
            return ((first & 0x3F) << 8) | second
        elif first < 0xE0:
            rest = self._recv_exact(2)
            return ((first & 0x1F) << 16) | (rest[0] << 8) | rest[1]
        elif first < 0xF0:
            rest = self._recv_exact(3)
            return ((first & 0x0F) << 24) | (rest[0] << 16) | (rest[1] << 8) | rest[2]
        else:
            rest = self._recv_exact(4)
            return struct.unpack("!I", rest)[0]

    def _recv_exact(self, n):
        """Reads exactly n bytes or raises."""
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("RouterOS API: connection closed")
            data += chunk
        return data

    # ── protocol ──────────────────────────────────────────────────────────────

    def _write_sentence(self, words):
        data = b""
        for word in words:
            encoded = word.encode("utf-8")
            data += self._encode_length(len(encoded)) + encoded
        data += b"\x00"
        self.sock.sendall(data)

    def _read_sentence(self):
        words = []
        while True:
            length = self._decode_length()
            if length == 0:
                break
            word = self._recv_exact(length).decode("utf-8", errors="replace")
            words.append(word)
        return words

    def _login(self):
        self._write_sentence(["/login", f"=name={self.username}", f"=password={self.password}"])
        response = self._read_sentence()
        if response and response[0] == "!done":
            return
        # Legacy challenge-based login
        challenge = None
        for word in response:
            if word.startswith("=ret="):
                challenge = bytes.fromhex(word[5:])
        if challenge:
            md5 = hashlib.md5()
            md5.update(b"\x00")
            md5.update(self.password.encode("utf-8"))
            md5.update(challenge)
            self._write_sentence(["/login", f"=name={self.username}", f"=response=00{md5.hexdigest()}"])
            self._read_sentence()

    def _read_records(self):
        """Reads !re records up to !done. Shared loop for query() and query_words()."""
        results = []
        while True:
            sentence = self._read_sentence()
            if not sentence:
                break
            tag = sentence[0]
            if tag == "!re":
                obj = {}
                for word in sentence[1:]:
                    if word.startswith("="):
                        parts = word[1:].split("=", 1)
                        if len(parts) == 2:
                            obj[parts[0]] = parts[1]
                results.append(obj)
            elif tag == "!done":
                break
            elif tag in ("!trap", "!fatal"):
                raise Exception(f"RouterOS error: {' '.join(sentence[1:])}")
        return results

    def query(self, command, params=None, filters=None):
        """Runs a command and returns a list of dicts."""
        words = [command]
        if params:
            for k, v in params.items():
                words.append(f"={k}={v}")
        if filters:
            for f in filters:
                words.append(f"?{f}")
        self._write_sentence(words)
        return self._read_records()

    def query_words(self, words):
        """Like query(), but takes a pre-built word list — needed for commands
        with value-less flags (e.g. 'once' on /interface/monitor-traffic)."""
        self._write_sentence(words)
        return self._read_records()

    def run(self, command, params=None):
        """Runs a command without returning data (add/remove/set)."""
        words = [command]
        if params:
            for k, v in params.items():
                words.append(f"={k}={v}")
        self._write_sentence(words)
        while True:
            sentence = self._read_sentence()
            if not sentence:
                break
            tag = sentence[0]
            if tag == "!done":
                break
            elif tag in ("!trap", "!fatal"):
                raise Exception(f"RouterOS error: {' '.join(sentence[1:])}")


class PersistentRouterOSHandle:
    """Reuses one long-lived connection to the RouterOS API instead of
    connect+login/close on every tool call (that pattern floods the router's
    /log with a login/logout pair several times a second).

    The lock is held for the whole tool call (the entire `with` block), not
    just setup -- RouterOSAPI isn't designed for concurrent use over one
    socket."""

    def __init__(self, host, port, username, password, idle_limit=480):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._idle_limit = idle_limit  # seconds — headroom below the router's own inactivity-timeout for this user
        self._lock = threading.Lock()
        self._instance = None
        self._last_used = 0.0

    def __enter__(self):
        self._lock.acquire()
        try:
            now = time.time()
            if self._instance is not None and (now - self._last_used) > self._idle_limit:
                self._instance.close()
                self._instance = None
            if self._instance is None:
                self._instance = RouterOSAPI(self._host, self._port, self._username, self._password)
                self._instance.connect()
            self._last_used = now
            return self._instance
        except Exception:
            # __enter__ failed → __exit__ will NOT be called (that's how the
            # `with` protocol works), so the lock must be released here or it
            # stays held forever and every subsequent tool call (routed through
            # run_in_threadpool) hangs until the whole thread pool is exhausted
            # and the service stops responding entirely.
            if self._instance:
                try:
                    self._instance.close()
                except Exception:
                    pass
            self._instance = None
            self._lock.release()
            raise

    def __exit__(self, exc_type, exc, tb):
        # Connection died (socket/timeout) — drop it so the next call reconnects
        if exc_type is not None and issubclass(exc_type, (ConnectionError, OSError, socket.timeout)):
            if self._instance:
                self._instance.close()
            self._instance = None
        self._lock.release()
        return False  # don't suppress the exception
