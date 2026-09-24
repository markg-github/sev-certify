#!/usr/bin/bash
set -euo pipefail

RESULTS_DIR="/root/results"
SEV_VERIFY_LOG="${RESULTS_DIR}/sev-verify.log"
JSON_FILE="${RESULTS_DIR}/cert-combined.json"
MD_FILE="${RESULTS_DIR}/cert-combined.md"

# Exactly one `beacon report` call is made per boot: dispatch advertises a
# single consumable service-discovery lease per boot session, so a second
# call in the same boot fails with "no dispatch services found" (confirmed
# on real hardware). sev_verify merges every manifest that ran into one
# cert-combined.json/.md for exactly this reason — this script used to loop
# over cert-*.json and call `beacon report` once per file, which broke the
# moment a run produced more than one.

build_beacon_body() {
  local body_file
  body_file=$(mktemp)

  cat "$MD_FILE" > "$body_file"

  # The raw log is large and mostly redundant with the structured "Details"
  # sections cert-combined.md already carries, so it's only worth the space
  # when something failed. Trimmed to a tail, not the whole thing: GitHub's
  # issue/comment body limit is 65,536 characters, and it must never crowd
  # out the structured per-certification content, which is never truncated.
  if [ "$OVERALL_RESULT" != "pass" ] && [ -f "$SEV_VERIFY_LOG" ]; then
    {
      echo ""
      echo "### sev-verify output (tail)"
      echo '```'
      tail -c 20000 "$SEV_VERIFY_LOG"
      echo '```'
    } >> "$body_file"
  fi

  echo "$body_file"
}

# Determine OS name and version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="${ID}"
    OS_VERSION="${VERSION_ID:-""}"

    # Initialize OS release with the OS VERSION_CODENAME if VERSION_ID is missing in /etc/os-release.
    if [[ -z "${OS_VERSION}" && -n "${VERSION_CODENAME:-}" ]]; then
        OS_VERSION="${VERSION_CODENAME:-}"
    fi

    OS_LABEL="${OS_NAME}-${OS_VERSION}"
else
    OS_NAME="$(uname -s)"
    OS_VERSION=""
    OS_LABEL="${OS_NAME}"
fi

# Fetch AMD processor model
PROC_LABEL=$(/usr/bin/python3 /usr/local/lib/scripts/get_processor_model.py series)

if [ ! -f "$JSON_FILE" ]; then
    echo "No combined certification results found: ${JSON_FILE}" >&2
    exit 1
fi
if [ ! -f "$MD_FILE" ]; then
    echo "Combined markdown report not found: ${MD_FILE}" >&2
    exit 1
fi

# Parse fields from sev-verify's combined JSON output
CERT_VERSIONS=$(jq -r '[.certifications[].certification_version] | join(", ")' "$JSON_FILE")
CERTIFIED_LEVEL=$(jq -r '[.certifications[].certified_level | select(. != null)][0] // empty' "$JSON_FILE")
OVERALL_RESULT=$(jq -r 'if ([.certifications[].result] | all(. == "pass")) then "pass" else "fail" end' "$JSON_FILE")

# Build title
if [ -n "$OS_VERSION" ]; then
  SEV_TITLE="${OS_NAME} ${OS_VERSION} SEV versions: ${CERT_VERSIONS}"
else
  SEV_TITLE="${OS_NAME} SEV versions: ${CERT_VERSIONS}"
fi

# Set up parameters
PARAMS=()

# Add labels
PARAMS+=("--label" "certificate")
PARAMS+=("--label" "os-${OS_LABEL}")
PARAMS+=("--label" "proc-${PROC_LABEL}")

# Add milestone for max achieved certification level, if any certification
# in this run achieved one (there's realistically only ever one leveled
# certification per run; experimental manifests have no level at all).
if [ -n "$CERTIFIED_LEVEL" ]; then
  PARAMS+=("--milestone" "c${CERTIFIED_LEVEL}")
fi

body_file=$(build_beacon_body)

beacon report --title "$SEV_TITLE" --body "$body_file" "${PARAMS[@]}"
rm -f "$body_file"

echo "Published SEV certificate via beacon with title: $SEV_TITLE"
