from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from anonymizer.core import anonymize, load_config, unredact


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Redact PHI/PII-style data from prompts before OpenRouter (SSN, cards, dates, IPs, METRC-like IDs, lists)."
    )
    parser.add_argument(
        "-c",
        "--config",
        help="YAML config (strains, companies, extra regexes)",
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Input file (UTF-8); stdin if omitted",
    )
    parser.add_argument(
        "--mapping-out",
        type=Path,
        metavar="FILE",
        help="Write JSON placeholder→original mapping for unredact (sensitive; treat like secrets).",
    )
    parser.add_argument(
        "--unredact",
        action="store_true",
        help="Restore original identifiers using --mapping (stdin or path is redacted text).",
    )
    parser.add_argument(
        "--mapping",
        type=Path,
        metavar="FILE",
        help="JSON mapping from a prior --mapping-out (required with --unredact).",
    )
    args = parser.parse_args()

    if args.unredact:
        if not args.mapping or not args.mapping.is_file():
            parser.error("--unredact requires an existing --mapping JSON file.")
        raw = args.mapping.read_text(encoding="utf-8")
        mapping: dict[str, str] = json.loads(raw)
        if args.path:
            with open(args.path, encoding="utf-8") as f:
                text = f.read()
        else:
            text = sys.stdin.read()
        sys.stdout.write(unredact(text, mapping))
        return

    cfg = load_config(args.config)

    if args.path:
        with open(args.path, encoding="utf-8") as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    out, mapping = anonymize(text, cfg, return_mapping=True)
    sys.stdout.write(out)
    if args.mapping_out is not None:
        args.mapping_out.write_text(
            json.dumps(mapping, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":  # pragma: no cover
    main()
