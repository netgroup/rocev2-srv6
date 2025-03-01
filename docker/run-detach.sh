#!/bin/bash

sudo podman run \
	--rm \
	-d \
	--replace \
	--privileged \
	--name rocesrv6-builder \
	-v ../:/opt/rocesrv6 \
	-it localhost/rocesrv6-builder
