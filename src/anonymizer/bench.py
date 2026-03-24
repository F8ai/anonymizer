"""Latency benchmarks for ``anonymize`` over standard token-window sizes."""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from typing import Callable, Sequence

from anonymizer.core import anonymize, load_config

# Common LLM / API context sizes (tokens).
DEFAULT_WINDOWS: tuple[int, ...] = (
    256,
    512,
    1024,
    2048,
    4096,
    8192,
    16384,
    32768,
    65536,
    131072,
)

# English-ish rough average (OpenAI-style estimates often use ~4 chars/token).
CHARS_PER_TOKEN_FALLBACK = 4.0

_BASE_CHUNK = (
    "The cultivation batch report lists yield and compliance notes. "
    "Contact operations if METRC tags fail validation. "
)


def _get_encoder():
    try:
        import tiktoken  # type: ignore[import-untyped]

        return tiktoken.get_encoding("cl100k_base")
    except ImportError:
        return None


def build_corpus(target_tokens: int, *, seed: int = 0) -> tuple[str, int]:
    """Build synthetic text of approximately ``target_tokens`` tokens.

    Returns ``(text, token_count)``. If ``tiktoken`` is installed, token count
    is exact (cl100k_base); otherwise it is estimated from byte length using
    ``CHARS_PER_TOKEN_FALLBACK``.
    """
    rng = __import__("random").Random(seed)
    enc = _get_encoder()

    # Long enough pool: repeat with tiny RNG jitter so paths aren't trivially cached.
    parts: list[str] = []
    for _ in range(target_tokens // 8 + 500):
        jitter = rng.randint(0, 9999)
        parts.append(f"{_BASE_CHUNK}[ref:{jitter}] ")
    raw = "".join(parts)

    # Realistic PHI-like needles (exercise redaction pipeline).
    needle = (
        " patient@clinic.example.org SSN 123-45-6789 "
        "EIN 12-3456789 visit 2025-03-15 192.168.1.1 2001:db8::1 "
        "1A4FF000000012400000000 card 4111111111111111 "
    )
    if len(raw) > len(needle) + 100:
        mid = len(raw) // 2
        raw = raw[:mid] + needle + raw[mid:]

    if enc is not None:
        toks = enc.encode(raw)
        filler = enc.encode((_BASE_CHUNK * 120) + "\n")
        while len(toks) < target_tokens:
            toks.extend(filler)
        text = enc.decode(toks[:target_tokens])
        return text, target_tokens

    approx_chars = max(1, int(target_tokens * CHARS_PER_TOKEN_FALLBACK))
    text = raw[:approx_chars]
    est_tokens = max(1, int(len(text) / CHARS_PER_TOKEN_FALLBACK))
    return text, est_tokens


def run_latency(
    *,
    windows: Sequence[int],
    repeats: int = 7,
    warmup: int = 2,
    cfg: dict | None = None,
    build: Callable[[int], tuple[str, int]] = build_corpus,
) -> list[dict[str, float | int]]:
    """Run ``anonymize`` for each window; return rows with timing stats (ms)."""
    rows: list[dict[str, float | int]] = []
    cfg = cfg or {}

    for target in windows:
        text, tok_label = build(target)
        n_chars = len(text)

        def once() -> None:
            anonymize(text, cfg)

        for _ in range(warmup):
            once()

        samples_ms: list[float] = []
        for _ in range(repeats):
            t0 = time.perf_counter()
            once()
            samples_ms.append((time.perf_counter() - t0) * 1000.0)

        rows.append(
            {
                "target_tokens": target,
                "label_tokens": tok_label,
                "chars": n_chars,
                "ms_mean": statistics.mean(samples_ms),
                "ms_stdev": statistics.stdev(samples_ms) if len(samples_ms) > 1 else 0.0,
                "ms_min": min(samples_ms),
                "ms_max": max(samples_ms),
                "repeats": repeats,
            }
        )
    return rows


def _format_table(rows: list[dict[str, float | int]]) -> str:
    lines = [
        "tokens(target)  tokens(label)    chars      mean_ms   stdev_ms   min_ms   max_ms",
        "--------------  -------------  ---------  --------  --------  -------  -------",
    ]
    for r in rows:
        lines.append(
            f"{r['target_tokens']!s:>14}  "
            f"{r['label_tokens']!s:>13}  "
            f"{r['chars']!s:>9}  "
            f"{r['ms_mean']:>8.3f}  "
            f"{r['ms_stdev']:>8.3f}  "
            f"{r['ms_min']:>7.3f}  "
            f"{r['ms_max']:>7.3f}"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Measure anonymize() latency over standard token windows. "
            "Install tiktoken for exact cl100k_base token lengths; "
            "otherwise length uses ~4 chars/token."
        )
    )
    parser.add_argument(
        "--windows",
        type=str,
        default=",".join(str(w) for w in DEFAULT_WINDOWS),
        help="Comma-separated token window sizes (default: standard set up to 128k).",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=7,
        help="Timed iterations per window after warmup (default: 7).",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=2,
        help="Untimed runs per window before timing (default: 2).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=0,
        help="RNG seed for synthetic text (default: 0).",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Optional YAML config passed to anonymize (same as CLI).",
    )
    args = parser.parse_args()

    try:
        windows = [int(x.strip()) for x in args.windows.split(",") if x.strip()]
    except ValueError:
        print("Invalid --windows; use comma-separated integers.", file=sys.stderr)
        sys.exit(2)
    if not windows:
        print("No windows to run.", file=sys.stderr)
        sys.exit(2)
    if any(w < 1 for w in windows):
        print("All window sizes must be >= 1.", file=sys.stderr)
        sys.exit(2)

    cfg = load_config(args.config)

    def build_wrapped(n: int) -> tuple[str, int]:
        return build_corpus(n, seed=args.seed)

    rows = run_latency(
        windows=windows,
        repeats=max(1, args.repeats),
        warmup=max(0, args.warmup),
        cfg=cfg,
        build=build_wrapped,
    )

    enc = _get_encoder()
    mode = "tiktoken cl100k_base (exact token lengths)" if enc else (
        f"heuristic ~{CHARS_PER_TOKEN_FALLBACK:.1f} chars/token (pip install tiktoken for exact)"
    )
    print(f"anonymize() latency — {mode}\n")
    print(_format_table(rows))
    print()
    for r in rows:
        c = int(r["chars"])
        m = float(r["ms_mean"])
        if c > 0 and m > 0:
            mb_s = (c / (1024 * 1024)) / (m / 1000.0)
            print(
                f"  {r['target_tokens']} tokens: ~{m / max(1, int(r['target_tokens'])) * 1000:.4f} µs/token "
                f"(mean), ~{mb_s:.1f} MB/s corpus throughput"
            )


if __name__ == "__main__":  # pragma: no cover
    main()
