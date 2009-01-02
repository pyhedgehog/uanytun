##
##  µAnytun
##
##  µAnytun is a tiny implementation of SATP. Unlike Anytun which is a full
##  featured implementation µAnytun has no support for multiple connections
##  or synchronisation. It is a small single threaded implementation intended
##  to act as a client on small platforms.
##  The secure anycast tunneling protocol (satp) defines a protocol used
##  for communication between any combination of unicast and anycast
##  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
##  mode and allows tunneling of every ETHER TYPE protocol (e.g.
##  ethernet, ip, arp ...). satp directly includes cryptography and
##  message authentication based on the methodes used by SRTP.  It is
##  intended to deliver a generic, scaleable and secure solution for
##  tunneling and relaying of packets of any protocol.
##  
##
##  Copyright (C) 2007-2008 Christian Pointner <equinox@anytun.org>
##
##  This file is part of µAnytun.
##
##  µAnytun is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License version 3 as
##  published by the Free Software Foundation.
##
##  µAnytun is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with µAnytun. If not, see <http://www.gnu.org/licenses/>.
##

TARGET=$(shell uname -s)
CC = gcc
CCFLAGS = -g -O2
LD = gcc
LDFLAGS = -g -Wall -O2 -lgcrypt -lgpg-error -lgmp

ifeq ($(TARGET),Linux)
  LDFLAGS += -ldl
endif
ifeq ($(TARGET),OpenBSD)
  CCFLAGS += -I/usr/local/include -DNO_UDPV6
  LDFLAGS += -L/usr/local/lib
endif

OBJS = log.o \
       signal.o \
       options.o \
       tun.o \
       udp.o \
       plain_packet.o \
       encrypted_packet.o \
       seq_window.o \
       cipher.o \
       key_derivation.o \
       uanytun.o

EXECUTABLE = uanytun

all: $(EXECUTABLE)

uanytun: $(OBJS)
	$(LD) $(OBJS) -o $@ $(LDFLAGS)

uanytun.o: uanytun.c
	$(CC) $(CCFLAGS) $< -c

log.o: log.c log.h
	$(CC) $(CCFLAGS) $< -c

signal.o: signal.c signal.h
	$(CC) $(CCFLAGS) $< -c

options.o: options.c options.h
	$(CC) $(CCFLAGS) $< -c

tun.o: tun.c tun.h
	$(CC) $(CCFLAGS) $< -c

udp.o: udp.c udp.h
	$(CC) $(CCFLAGS) $< -c

plain_packet.o: plain_packet.c plain_packet.h
	$(CC) $(CCFLAGS) $< -c

encrypted_packet.o: encrypted_packet.c encrypted_packet.h
	$(CC) $(CCFLAGS) $< -c

seq_window.o: seq_window.c seq_window.h
	$(CC) $(CCFLAGS) $< -c

cipher.o: cipher.c cipher.h
	$(CC) $(CCFLAGS) $< -c

key_derivation.o: key_derivation.c key_derivation.h
	$(CC) $(CCFLAGS) $< -c

distclean: clean
	find . -name *.o -exec rm -f {} \;
	find . -name "*.\~*" -exec rm -rf {} \;
	rm -f tun.c

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)

ctags:
	ctags -R --c++-kinds=+p --fields=+iaS --extra=+q .

