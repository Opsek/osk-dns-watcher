# Entry points. Every tool runs in a container. The settings DOCKER,
# BUILD_FLAGS, LAB_ID, HOST_LAB_A, HOST_LAB_B, FUZZTIME, DOCKER_SOCK,
# SELFTEST, OSK_RELEASE and OSK_IMAGE reach the scripts through the
# environment (see gate/bin/gate).
# HOST_LAB_A and HOST_LAB_B (default 8 and 9) are the two labs that the lab
# phase of make check starts besides LAB_ID; no other lab may use them.
# SELFTEST=skip leaves out the selftest phase (default run).
# OSK_RELEASE=<version> adds the release phase to make check: it checks the
# files in out/release/<version>/ and the image that their CONTENTS names.
# OSK_IMAGE is the name of that image. See release/README.md.
# make vulncheck scans for known vulnerabilities, with the network; so does
# every release run.

OSK_IMAGE ?= ghcr.io/opsek/osk-dns-watcher

# make expands $(...) in a value that it passes on, so these reach the
# scripts as typed; the scripts refuse any text of another form.
override VERSION := $(value VERSION)
override OSK_RELEASE := $(value OSK_RELEASE)
override OSK_IMAGE := $(value OSK_IMAGE)
export VERSION OSK_RELEASE OSK_IMAGE

.PHONY: check build vulncheck release image image-digests verify-release lab-up lab-down

check:
	gate/bin/gate

vulncheck:
	gate/bin/gate vulncheck

build:
	gate/bin/gate build

release:
	release/build.sh "$$VERSION"

image:
	release/image.sh "$$VERSION"

verify-release:
	release/verify.sh "$$VERSION"

image-digests:
	release/digests.sh "$$VERSION"

lab-up:
	lab/bin/lab up

lab-down:
	lab/bin/lab down
