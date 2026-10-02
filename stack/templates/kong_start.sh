#!/bin/sh
# Kong's start command: fill the stack's keys into its config, then start Kong.
#
# The template is mounted as it is in the repository, with no secret in it, and
# the keys arrive in Kong's environment from `.env`. So nothing on the host has
# to be readable by Kong's user (uid 1001 in the image) — which a rendered file
# kept private to whoever ran setup.py was not, unless that user happened to be
# 1001 too. The filled-in copy goes to a tmpfs only Kong can read.
#
# Doubled-brace placeholders only, read through awk's ENVIRON rather than a
# shell: the template's `$(...)` expressions are Kong's own and must survive.
set -eu
umask 077
awk '
{
  rest = $0
  out = ""
  while (match(rest, /[{][{][A-Z_]+[}][}]/)) {
    name = substr(rest, RSTART + 2, RLENGTH - 4)
    if (ENVIRON[name] == "") {
      print "kong: no " name " in the environment" > "/dev/stderr"
      exit 1
    }
    out = out substr(rest, 1, RSTART - 1) ENVIRON[name]
    rest = substr(rest, RSTART + RLENGTH)
  }
  print out rest
}' /home/kong/kong.yml.template > /run/kong/kong.yml
exec /entrypoint.sh kong docker-start
