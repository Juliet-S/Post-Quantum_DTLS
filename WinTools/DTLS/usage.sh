#!/bin/sh

top -b | head -n7

while true
do
    if pidof dtls_server; then
        break
    fi
    sleep 0.1
done

while true
do
    { date "+%s.%N"; top -b -d 0.05 -n 1 -p $(pidof dtls_server) | tail -n1; } | tr "\n" " " | sed '$s/ $/\n/'
    sleep 0.05
done
