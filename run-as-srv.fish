#!/usr/bin/env fish
systemd-run --pty --quiet --collect \
  --property=DynamicUser=yes \
  --property=StateDirectory=vrunsrv \
  --property=User=vrun-srv \
  --property=Group=vrun-srv \
  --working-directory=/var/lib/vrunsrv/work \
  $argv
