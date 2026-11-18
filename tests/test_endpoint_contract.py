"""Contract tests for OpenAI-compatible and generic HTTP targets."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from redteam import (
    HTTPJSONTarget,
    Message,
    OpenAICompatibleTarget,
    TargetError,
)


class _Handler(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).received.append({
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "payload": json.loads(body.decode("utf-8")),
        })
        response = {
            "choices": [{"message": {"role": "assistant", "content": "staging response"}}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3},
        }
        encoded = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        pass


def _serve():
    _Handler.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_openai_target_posts_chat_completion_with_bearer_auth():
    server, thread = _serve()
    try:
        base = f"http://127.0.0.1:{server.server_port}/v1"
        target = OpenAICompatibleTarget(base, api_key="test-only-secret")
        result = target.generate([Message("user", "synthetic probe")], model="staging-model")

        request = _Handler.received[-1]
        assert request["path"] == "/v1/chat/completions"
        assert request["authorization"] == "Bearer test-only-secret"
        assert request["payload"]["model"] == "staging-model"
        assert request["payload"]["messages"] == [
            {"role": "user", "content": "synthetic probe"}
        ]
        assert result.text == "staging response"
        assert result.input_tokens == 7
        assert result.output_tokens == 3
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_openai_target_does_not_add_bearer_header_without_key():
    server, thread = _serve()
    try:
        target = OpenAICompatibleTarget(
            f"http://127.0.0.1:{server.server_port}/v1"
        )
        target.generate([Message("user", "hello")], model="staging-model")
        assert _Handler.received[-1]["authorization"] is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_generic_http_target_accepts_common_json_response_shape():
    server, thread = _serve()
    try:
        target = HTTPJSONTarget(
            f"http://127.0.0.1:{server.server_port}/generate"
        )
        result = target.generate([Message("user", "hello")], model="test-model")
        request = _Handler.received[-1]
        assert request["path"] == "/generate"
        assert request["payload"]["model"] == "test-model"
        assert result.text == "staging response"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_generic_http_target_rejects_non_json_response():
    class InvalidJSONHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"not-json")

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), InvalidJSONHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = HTTPJSONTarget(
            f"http://127.0.0.1:{server.server_port}/generate"
        )
        try:
            target.generate([Message("user", "hello")], model="test-model")
        except TargetError as exc:
            assert "invalid JSON" in str(exc)
        else:
            raise AssertionError("invalid JSON response should raise TargetError")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
