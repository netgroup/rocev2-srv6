#!/bin/bash

sudo podman run \
	--rm \
	--replace \
	--name rocesrv6-builder \
	-v ../:/opt/rocesrv6 \
	-t localhost/rocesrv6-builder \
	bash -c "cd /opt/rocesrv6 && ./init.sh"
