#!/bin/bash

set -euo pipefail

join_by() { local IFS="$1"; shift; echo "$*"; }

OPTIONS_COMPRESS=(
    drop_console=false
    drop_debugger=false
    hoist_funs=true
    hoist_vars=true
    passes=3
    pure_getters=true
    sequences=false
    unsafe_comps=true
    unsafe_math=true
    unsafe_proto=true
    unsafe_undefined=true
)

OPTIONS_BEAUTIFY=(
    ascii_only=true
    beautify=false
    inline_script=true
    semicolons=true
    webkit=true
)


[[ -z "${TOOL_DIR:-}" ]] && export TOOL_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
[[ -z "${NODE_PATH:-}" ]] && export NODE_PATH="${TOOL_DIR}/node_modules"

NAME="$(realpath --canonicalize-missing -- "${1}")"
shift

DEST_DIR="$(dirname -- "${NAME}")"
BASENAME="$(basename --suffix=.js -- ${NAME})"


cat "$@" | (
    cd -- "${DEST_DIR}"
    cat > "${BASENAME}.src.js"
    "${NODE_PATH}"/.bin/babel \
        --source-maps=true \
        --config-file="${TOOL_DIR}/babel.config.json" \
        --out-file="${BASENAME}.es5.js" \
        -- \
        "${BASENAME}.src.js"
)


cd -- "${DEST_DIR}"


"${NODE_PATH}"/.bin/uglifyjs \
    --compress "$(join_by , "${OPTIONS_COMPRESS[@]}")" \
    --beautify "$(join_by , "${OPTIONS_BEAUTIFY[@]}")" \
    --mangle \
    --output "${BASENAME}.js" \
    --source-map filename="${BASENAME}.js.map",url="${BASENAME}.js.map",content="${BASENAME}.es5.js.map" \
    -- \
    "${BASENAME}.es5.js"


parallel zopfli                ::: "${BASENAME}.src.js" "${BASENAME}.es5.js" "${BASENAME}.es5.js.map" "${BASENAME}.js" "${BASENAME}.js.map"
parallel brotli --keep --force ::: "${BASENAME}.src.js" "${BASENAME}.es5.js" "${BASENAME}.es5.js.map" "${BASENAME}.js" "${BASENAME}.js.map"
