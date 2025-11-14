#!/bin/bash

BUILD_ROOT=build
BUILD_NAME=alinas_utils_tests
BUILD_DIR=${BUILD_ROOT}/${BUILD_NAME}

mkdir -p ${BUILD_DIR}
cp requirements.txt ${BUILD_DIR}
cp -r test ${BUILD_DIR}

cd ${BUILD_ROOT}
tar -cf ${BUILD_NAME}.tar ${BUILD_NAME}
