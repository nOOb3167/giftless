#!/bin/bash

# This script builds the wheel (bdist_wheel) of a specific flask_classful GIT SHA
#   and places it in giftless/fix_flask_classful.whl to be packaged by giftless
# Ths wheel file is intended to be loaded should the presence of an incompatible
#   flask_classful be detected at runtime

set -e

FLASK_CLASSFUL_COMMIT_SHA=${FLASK_CLASSFUL_COMMIT_SHA:-3bbab31705b4aa2903e7e62aa8c5ee70a1e6d789}
FLASK_CLASSFUL_WHEEL_NAME=${FLASK_CLASSFUL_WHEEL_NAME:-Flask_Classful-0.15.0.dev0-py3-none-any.whl}
GIT_CMD=${GIT_CMD:-git}
PYTHON_CMD=${PYTHON_CMD:-python}

ROOT_DIR=$(readlink -e "$(dirname $0)")
BUILD_DIR="${ROOT_DIR}/build/fix_flask_classful"
LOG_FILE="${ROOT_DIR}/build/generate-classless.log"
DIST_FILE="${BUILD_DIR}/dist/${FLASK_CLASSFUL_WHEEL_NAME}"
OUT_FILE="${ROOT_DIR}/giftless/fix_flask_classful.whl"

error()
{
	echo "ERROR: [$1]" >&2
	exit 1
}

[ -f setup.py ] || error "run script in giftless source dir"

echo "Log File [${LOG_FILE}]"
echo "Build directory [${BUILD_DIR}]"

echo "Cleaning build directory"

rm -rf   "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd       "${BUILD_DIR}"

echo "Cloning flask-classful"

${GIT_CMD} clone https://github.com/teracyhq/flask-classful.git . > "${LOG_FILE}" 2>&1
${GIT_CMD} checkout "${FLASK_CLASSFUL_COMMIT_SHA}" > "${LOG_FILE}" 2>&1

echo "Building bdist_wheel"

${PYTHON_CMD} -m setup bdist_wheel > "${LOG_FILE}" 2>&1

[ -f "${DIST_FILE}" ] || error "wheel file [${DIST_FILE}] not found"

echo "Copying wheel to [${OUT_FILE}]"

cp -f "${DIST_FILE}" "${OUT_FILE}"

echo "Done"
