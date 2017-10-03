#!/bin/sh/
tshark -r data.pcap -Y "!(usb.capdata == 00:00:00:00:00:00:00:00)" -e usb.capdata -T fields > data.txt
