
To build the image, just run:
```bash
# ./container-build.sh
```

Once you have the image, you can compile everything is needed:
```bash
# ./compile.sh
```

It is possibile run the container (in detached mode):
```bash
# ./run-detach
```

To enter into the container:
```bash
# podman exec -it rocesrv6-builder bash
```
