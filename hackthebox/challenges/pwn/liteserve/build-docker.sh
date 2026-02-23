#!/bin/sh
docker build --tag=liteserve .
docker run -it -p 1337:1337 --rm --name=liteserve liteserve --privileged
