# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for the JSON-RPC layer.

The protocol is implemented directly rather than through an SDK, so these
tests cover the parts an SDK would otherwise have covered: notifications must
not be answered, malformed input must not end the session, and standard
output must carry nothing but protocol messages.
"""

from __future__ import annotations

import io
import json
import logging

import pytest
from encryption_helper import encode_public_key, encrypt, generate

from encryption_helper_mcp import __version__
from encryption_helper_mcp.server import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    PROTOCOL_VERSION,
    build_parser,
    dispatch,
    main,
    serve,
)


def exchange(root, *messages):
    """Run a session over the given messages and return the responses."""
    source = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    sink = io.StringIO()
    assert serve(root, source, sink) == 0
    return [json.loads(line) for line in sink.getvalue().splitlines()]


def request(method, request_id=1, **params):
    """Build a JSON-RPC request."""
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params:
        message["params"] = params
    return message


class TestHandshake:
    def test_initialize_reports_the_protocol_revision(self, tmp_path):
        result = exchange(tmp_path, request("initialize"))[0]["result"]
        assert result["protocolVersion"] == PROTOCOL_VERSION
        assert result["serverInfo"]["version"] == __version__

    def test_initialize_declares_only_the_tools_capability(self, tmp_path):
        """Declaring a capability the server lacks would mislead the client."""
        capabilities = exchange(tmp_path, request("initialize"))[0]["result"][
            "capabilities"
        ]
        assert set(capabilities) == {"tools"}

    def test_the_instructions_state_what_the_server_cannot_do(self, tmp_path):
        """A model should learn the limit from the handshake, not by failing."""
        instructions = exchange(tmp_path, request("initialize"))[0]["result"][
            "instructions"
        ]
        assert "cannot generate, encrypt, decrypt, sign" in instructions
        assert "never accepts a passphrase" in instructions

    def test_the_initialized_notification_is_not_answered(self, tmp_path):
        """Replying to a notification is a protocol violation."""
        assert (
            exchange(
                tmp_path, {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )
            == []
        )

    def test_an_unknown_notification_is_ignored_not_rejected(self, tmp_path):
        assert (
            exchange(tmp_path, {"jsonrpc": "2.0", "method": "notifications/odd"}) == []
        )

    def test_ping_is_answered_with_an_empty_result(self, tmp_path):
        assert exchange(tmp_path, request("ping"))[0]["result"] == {}


class TestToolsList:
    def test_every_tool_is_listed_with_a_schema(self, tmp_path):
        tools = exchange(tmp_path, request("tools/list"))[0]["result"]["tools"]
        assert tools
        for tool in tools:
            assert tool["name"]
            assert tool["description"]
            assert tool["inputSchema"]["type"] == "object"

    def test_no_tool_accepts_undeclared_arguments(self, tmp_path):
        """Open schemas invite a model to invent arguments."""
        for tool in exchange(tmp_path, request("tools/list"))[0]["result"]["tools"]:
            assert tool["inputSchema"]["additionalProperties"] is False

    def test_the_listed_names_are_the_read_only_set(self, tmp_path):
        names = {
            tool["name"]
            for tool in exchange(tmp_path, request("tools/list"))[0]["result"]["tools"]
        }
        assert names == {
            "pq_horizon",
            "assess_algorithm",
            "algorithm_inventory",
            "inspect_container",
            "scan_directory",
            "fingerprint_public_key",
        }


class TestToolCalls:
    def test_pq_horizon_returns_the_dates_and_the_caveat(self, tmp_path):
        result = exchange(
            tmp_path, request("tools/call", name="pq_horizon", arguments={})
        )[0]["result"]
        payload = result["structuredContent"]
        assert payload["disallowed_from"] == 2035
        assert "not to this library" in payload["validation_note"]
        assert result["isError"] is False

    def test_assess_algorithm_answers_for_rsa(self, tmp_path):
        result = exchange(
            tmp_path,
            request(
                "tools/call",
                name="assess_algorithm",
                arguments={"algorithm": "rsa", "key_size": 2048},
            ),
        )[0]["result"]["structuredContent"]
        assert result["quantum_vulnerable"] is True
        assert result["replacements"] == ["mlkem", "mldsa"]

    def test_naming_a_purpose_narrows_the_recommendation(self, tmp_path):
        result = exchange(
            tmp_path,
            request(
                "tools/call",
                name="assess_algorithm",
                arguments={"algorithm": "rsa", "purpose": "sign"},
            ),
        )[0]["result"]["structuredContent"]
        assert result["replacement"] == "mldsa"

    def test_algorithm_inventory_covers_every_algorithm(self, tmp_path):
        from encryption_helper.keys.generate import SUPPORTED_ALGORITHMS

        result = exchange(
            tmp_path, request("tools/call", name="algorithm_inventory", arguments={})
        )[0]["result"]["structuredContent"]
        assert set(result["algorithms"]) == set(SUPPORTED_ALGORITHMS)

    def test_inspect_container_reports_the_mechanism(self, tmp_path):
        key = generate("mlkem")
        (tmp_path / "data.enc").write_bytes(encrypt(key.public_key(), b"payload"))
        result = exchange(
            tmp_path,
            request(
                "tools/call", name="inspect_container", arguments={"path": "data.enc"}
            ),
        )[0]["result"]["structuredContent"]
        assert result["key_establishment"] == "ml-kem-768"

    def test_scan_directory_reports_a_summary_and_findings(self, tmp_path):
        key = generate("rsa", key_size=2048)
        (tmp_path / "legacy.pub").write_bytes(encode_public_key(key.public_key()))
        result = exchange(
            tmp_path,
            request("tools/call", name="scan_directory", arguments={"path": "."}),
        )[0]["result"]["structuredContent"]
        assert result["summary"]["examined"] == 1
        assert result["findings"][0]["algorithm"] == "rsa"

    def test_fingerprint_public_key_returns_a_fingerprint(self, tmp_path):
        key = generate("ed25519")
        (tmp_path / "k.pub").write_bytes(encode_public_key(key.public_key()))
        result = exchange(
            tmp_path,
            request(
                "tools/call", name="fingerprint_public_key", arguments={"path": "k.pub"}
            ),
        )[0]["result"]["structuredContent"]
        assert result["fingerprint"].startswith("SHA256")

    def test_the_text_block_carries_the_same_data_as_the_structure(self, tmp_path):
        """A client without structured support must not get less."""
        result = exchange(
            tmp_path, request("tools/call", name="pq_horizon", arguments={})
        )[0]["result"]
        assert json.loads(result["content"][0]["text"]) == result["structuredContent"]


class TestToolFailuresAreRecoverable:
    """A bad argument is the model's mistake to correct, not a transport fault.

    Returning a JSON-RPC error would surface to the user as a broken server;
    returning ``isError`` lets the client show the message and retry.
    """

    def test_an_unknown_algorithm_is_an_error_result_not_a_protocol_error(
        self, tmp_path
    ):
        response = exchange(
            tmp_path,
            request(
                "tools/call", name="assess_algorithm", arguments={"algorithm": "dsa"}
            ),
        )[0]
        assert "error" not in response
        assert response["result"]["isError"] is True

    def test_the_failure_message_lists_what_is_supported(self, tmp_path):
        response = exchange(
            tmp_path,
            request(
                "tools/call", name="assess_algorithm", arguments={"algorithm": "dsa"}
            ),
        )[0]
        assert "mlkem" in response["result"]["content"][0]["text"]

    def test_an_unknown_tool_names_the_available_ones(self, tmp_path):
        response = exchange(
            tmp_path, request("tools/call", name="keygen", arguments={})
        )[0]
        text = response["result"]["content"][0]["text"]
        assert "Unknown tool 'keygen'" in text
        assert "scan_directory" in text

    @pytest.mark.parametrize(
        "arguments",
        [
            pytest.param({}, id="missing-required"),
            pytest.param({"algorithm": "rsa", "key_size": "big"}, id="wrong-type"),
            pytest.param({"algorithm": "rsa", "purpose": "wrap"}, id="bad-enum"),
        ],
    )
    def test_a_bad_tool_argument_comes_back_as_a_retryable_result(
        self, tmp_path, arguments
    ):
        response = exchange(
            tmp_path,
            request("tools/call", name="assess_algorithm", arguments=arguments),
        )[0]
        assert "error" not in response
        assert response["result"]["isError"] is True
        assert response["result"]["content"][0]["text"]

    def test_a_malformed_call_envelope_is_a_protocol_error(self, tmp_path):
        """Distinct from a bad argument: the request itself is unusable.

        A missing tool name is not something the model can learn from a tool
        result, because no tool was identified to return one.
        """
        response = exchange(tmp_path, request("tools/call", arguments={}))[0]
        assert response["error"]["code"] == INVALID_PARAMS
        assert "'name' is required" in response["error"]["message"]

    def test_non_object_arguments_are_a_protocol_error(self, tmp_path):
        response = dispatch(
            tmp_path,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "pq_horizon", "arguments": 7},
            },
        )
        assert response["error"]["code"] == INVALID_PARAMS


class TestProtocolErrors:
    def test_an_unknown_method_is_refused(self, tmp_path):
        response = exchange(tmp_path, request("resources/list"))[0]
        assert response["error"]["code"] == METHOD_NOT_FOUND

    def test_malformed_json_does_not_end_the_session(self, tmp_path):
        """One bad line must not take the connection down with it."""
        source = io.StringIO("not json\n" + json.dumps(request("ping")) + "\n")
        sink = io.StringIO()
        assert serve(tmp_path, source, sink) == 0
        responses = [json.loads(line) for line in sink.getvalue().splitlines()]
        assert responses[0]["error"]["code"] == PARSE_ERROR
        assert responses[1]["result"] == {}

    def test_blank_lines_are_skipped(self, tmp_path):
        source = io.StringIO("\n\n" + json.dumps(request("ping")) + "\n")
        sink = io.StringIO()
        serve(tmp_path, source, sink)
        assert len(sink.getvalue().splitlines()) == 1

    def test_a_non_object_message_is_refused(self, tmp_path):
        assert dispatch(tmp_path, [1, 2, 3])["error"]["code"] == INVALID_REQUEST

    def test_a_message_without_a_method_is_refused(self, tmp_path):
        response = dispatch(tmp_path, {"jsonrpc": "2.0", "id": 1})
        assert response["error"]["code"] == INVALID_REQUEST

    def test_non_object_params_are_refused(self, tmp_path):
        response = dispatch(
            tmp_path, {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": 7}
        )
        assert response["error"]["code"] == INVALID_PARAMS

    def test_an_oversized_message_is_refused(self, tmp_path):
        from encryption_helper_mcp.server import MAX_MESSAGE_BYTES

        source = io.StringIO("x" * (MAX_MESSAGE_BYTES + 1) + "\n")
        sink = io.StringIO()
        serve(tmp_path, source, sink)
        response = json.loads(sink.getvalue())
        assert response["error"]["code"] == INVALID_REQUEST
        assert "too large" in response["error"]["message"]

    def test_the_request_id_is_echoed(self, tmp_path):
        assert exchange(tmp_path, request("ping", request_id="abc"))[0]["id"] == "abc"


class TestUnexpectedFailuresAreOpaque:
    def test_an_internal_error_does_not_quote_the_exception(
        self, tmp_path, monkeypatch, caplog
    ):
        """An exception's text may quote a path the operator never exposed."""
        import encryption_helper_mcp.server as server_module

        def boom(_root, _params):
            msg = "/home/someone/secret-location/key.pem is unreadable"
            raise RuntimeError(msg)

        monkeypatch.setitem(server_module._METHODS, "ping", boom)
        with caplog.at_level(logging.ERROR):
            response = exchange(tmp_path, request("ping"))[0]

        assert response["error"]["code"] == INTERNAL_ERROR
        assert response["error"]["message"] == "Internal error."
        assert "secret-location" not in json.dumps(response)
        # The detail is still available locally, where the operator controls it.
        assert "secret-location" in caplog.text


class TestCommandLine:
    def test_the_help_states_the_server_cannot_act(self, capsys):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--help"])
        out = capsys.readouterr().out
        assert "cannot generate, encrypt, decrypt or sign" in out

    def test_version_is_reported(self, capsys):
        with pytest.raises(SystemExit):
            main(["--version"])
        assert __version__ in capsys.readouterr().out

    def test_a_root_that_is_not_a_directory_is_refused(self, tmp_path, capsys):
        path = tmp_path / "file"
        path.write_text("x")
        assert main(["--root", str(path)]) == 2
        assert "not a directory" in capsys.readouterr().err

    def test_diagnostics_never_reach_stdout(self, tmp_path, capsys, monkeypatch):
        """A log line on stdout would be read as a malformed message."""
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        assert main(["--root", str(tmp_path), "--log-level", "DEBUG"]) == 0
        assert capsys.readouterr().out == ""
