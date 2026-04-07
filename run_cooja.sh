#!/bin/bash
# Script to launch COOJA simulator from a nearby Contiki-NG directory.
# This script is for local testing only.

CONTIKI_NG_PATH="../contiki-ng"
COOJA_PATH="${CONTIKI_NG_PATH}/tools/cooja"

# Try to find a compatible Java version (17 or 21)
# Prioritize Homebrew specific paths as they might not be in java_home
if [ -d "/opt/homebrew/opt/openjdk@21" ]; then
    COMPAT_JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
elif [ -d "/opt/homebrew/opt/openjdk@17" ]; then
    COMPAT_JAVA_HOME="/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home"
elif command -v /usr/libexec/java_home >/dev/null 2>&1; then
    # Filter java_home to ensure we actually get 21 or 17
    COMPAT_JAVA_HOME=$(/usr/libexec/java_home -v 21 2>/dev/null)
    if [[ "$COMPAT_JAVA_HOME" == *"25."* ]] || [[ "$COMPAT_JAVA_HOME" == *"24."* ]]; then
        COMPAT_JAVA_HOME=$(/usr/libexec/java_home -v 17 2>/dev/null)
    fi
    if [[ "$COMPAT_JAVA_HOME" == *"25."* ]] || [[ "$COMPAT_JAVA_HOME" == *"24."* ]]; then
        COMPAT_JAVA_HOME=""
    fi
fi

if [ -n "$COMPAT_JAVA_HOME" ]; then
    echo "Using compatible Java at $COMPAT_JAVA_HOME"
    export JAVA_HOME="$COMPAT_JAVA_HOME"
else
    echo "Warning: No Java 21 or 17 found. Attempting with system default."
fi

if [ ! -f "${COOJA_PATH}/gradlew" ]; then
    echo "Error: COOJA not found at ${COOJA_PATH}"
    exit 1
fi

echo "Launching COOJA..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIM_FILE="${1:-${SCRIPT_DIR}/cooja-rpl-br.csc}"

if [ -f "$SIM_FILE" ]; then
    # Get absolute path for the simulation file
    ABS_SIM_FILE=$(cd "$(dirname "$SIM_FILE")" && pwd)/$(basename "$SIM_FILE")
    echo "Loading simulation: $ABS_SIM_FILE"
    (cd "${COOJA_PATH}" && ./gradlew run --args="$ABS_SIM_FILE")
else
    echo "Simulation file not found, launching empty COOJA."
    (cd "${COOJA_PATH}" && ./gradlew run)
fi
