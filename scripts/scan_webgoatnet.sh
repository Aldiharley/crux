#!/usr/bin/env bash
# Generate REAL findings from WebGoat.NET and feed them to Crux.
#
# Prereqs: git, and semgrep (pipx install semgrep  OR  pip install semgrep).
# WebGoat.NET is a deliberately vulnerable ASP.NET / C# app, so it is a safe,
# legal target you own a copy of. This doubles as .NET reading practice.
set -euo pipefail

WORK="${1:-./_webgoatnet}"
OUT="${2:-semgrep_webgoatnet.json}"

if [ ! -d "$WORK" ]; then
  echo "Cloning WebGoat.NET into $WORK ..."
  git clone --depth 1 https://github.com/jerryhoff/WebGoat.NET.git "$WORK"
fi

echo "Running Semgrep (C# security rules) ..."
# --config auto pulls community rules; the csharp + security packs catch the classics.
semgrep scan --config "p/csharp" --config "p/security-audit" \
  --json --output "$OUT" "$WORK" || true

echo "Semgrep findings written to $OUT"
echo
echo "Now triage them with Crux:"
echo "  python -m crux --input $OUT --mock                 # offline"
echo "  python -m crux --input $OUT --model claude-opus-5-5 # Claude-assisted (needs ANTHROPIC_API_KEY)"
