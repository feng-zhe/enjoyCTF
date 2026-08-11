#!/bin/sh
docker build --tag=pixel_audio .
# Mine: need this --cap-add=SYS_PTRACE otherwise we cannot use AppArmor.
docker run --cap-add=SYS_PTRACE -it -p 1337:1337 --rm --name=pixel_audio pixel_audio
