"""Restricted local media artifact worker."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Any
import wave
import zlib


def main() -> int:
    try:
        request = json.loads(sys.stdin.read())
        result = _handle_request(request)
    except Exception as exc:  # pragma: no cover - exercised through parent error path
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


def _handle_request(request: dict[str, Any]) -> dict[str, Any]:
    artifact_name = str(request.get("artifact_name") or "")
    if not artifact_name or "/" in artifact_name or "\\" in artifact_name or artifact_name.startswith("."):
        raise ValueError("artifact_name must be a simple filename")
    path = Path.cwd() / artifact_name
    if path.parent != Path.cwd():
        raise ValueError("artifact path must stay in worker cwd")
    tool = str(request.get("tool") or "")
    if tool == "tts":
        duration_seconds = _write_tts_tone(path, text=str(request.get("text") or ""))
        return {"duration_seconds": duration_seconds, "sample_rate": 8000}
    if tool == "voice_record":
        duration_seconds = _bounded_float(request.get("duration"), minimum=0.1, maximum=60.0)
        _write_silence_wav(path, duration_seconds=duration_seconds)
        return {"duration_seconds": round(duration_seconds, 3), "sample_rate": 8000}
    if tool in {"image_generate", "image_edit"}:
        width, height = _write_prompt_png(path, prompt=str(request.get("prompt") or ""), source=str(request.get("source") or ""))
        return {"width": width, "height": height}
    raise ValueError(f"unsupported media tool: {tool}")


def _bounded_float(value: Any, *, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = minimum
    return max(minimum, min(maximum, number))


def _write_tts_tone(path: Path, *, text: str) -> float:
    sample_rate = 8000
    duration_seconds = min(3.0, max(0.35, 0.08 * max(len(text.split()), 1)))
    frame_count = int(sample_rate * duration_seconds)
    amplitude = 9000
    frequency = 440
    with wave.open(str(path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(sample_rate)
        frames = bytearray()
        for index in range(frame_count):
            phase = (index * frequency) % sample_rate
            value = amplitude if phase < sample_rate // 2 else -amplitude
            frames.extend(struct.pack("<h", value))
        handle.writeframes(bytes(frames))
    path.chmod(0o600)
    return round(duration_seconds, 3)


def _write_silence_wav(path: Path, *, duration_seconds: float) -> None:
    sample_rate = 8000
    frame_count = int(sample_rate * duration_seconds)
    with wave.open(str(path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(sample_rate)
        handle.writeframes(b"\x00\x00" * frame_count)
    path.chmod(0o600)


def _write_prompt_png(path: Path, *, prompt: str, source: str = "") -> tuple[int, int]:
    width = 128
    height = 80
    seed = hashlib.sha256(f"{prompt}\0{source}".encode("utf-8", errors="replace")).digest()
    base_r, base_g, base_b = seed[0], seed[1], seed[2]
    accent_r, accent_g, accent_b = seed[3], seed[4], seed[5]
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            band = (x // 16 + y // 10) % 2
            blend = (x * 3 + y * 5 + seed[(x + y) % len(seed)]) % 64
            if band:
                rows.extend(((accent_r + blend) % 256, (accent_g + blend // 2) % 256, (accent_b + blend * 2) % 256))
            else:
                rows.extend(((base_r + blend * 2) % 256, (base_g + blend) % 256, (base_b + blend // 2) % 256))
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(bytes(rows), level=9))
        + _png_chunk(b"IEND", b"")
    )
    path.chmod(0o600)
    return width, height


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


if __name__ == "__main__":
    raise SystemExit(main())
