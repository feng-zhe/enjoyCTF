#!/bin/bash

coproc ./calc
nc -kl -p 4000 <&"${COPROC[0]}" >&"${COPROC[1]}"
