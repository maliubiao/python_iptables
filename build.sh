#! /bin/sh
gcc -o iptables.so iptables.c -shared -fPIC $(python2-config --cflags --libs)
