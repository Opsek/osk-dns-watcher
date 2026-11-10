# Entry points. Every tool runs in a container. The settings DOCKER,
# BUILD_FLAGS, LAB_ID, HOST_LAB_A, HOST_LAB_B and FUZZTIME reach the scripts
# through the environment (see gate/bin/gate). HOST_LAB_A and HOST_LAB_B
# (default 8 and 9) are the two labs that the lab phase of make check starts
# besides LAB_ID; no other lab may use them.

.PHONY: check build lab-up lab-down

check:
	gate/bin/gate

build:
	gate/bin/gate build

lab-up:
	lab/bin/lab up

lab-down:
	lab/bin/lab down
