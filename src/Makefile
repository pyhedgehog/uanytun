##
##  �Anytun
##
##  �Anytun is a tiny implementation of SATP. Unlike Anytun which is a full
##  featured implementation �Anytun has no support for multiple connections
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
##  This file is part of �Anytun.
##
##  �Anytun is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License version 3 as
##  published by the Free Software Foundation.
##
##  �Anytun is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with �Anytun. If not, see <http://www.gnu.org/licenses/>.
##

TARGET=$(shell uname -s)
CC = gcc
CCFLAGS = -g
LD = gcc
LDFLAGS = -g -Wall -O2 -lgcrypt -lgpg-error

ifeq ($(TARGET),Linux)
  LDFLAGS += -ldl
endif
ifeq ($(TARGET),OpenBSD)
  LDFLAGS += -L/usr/local/lib
endif

OBJS = log.o \
       signal.o \
       tun.o \
       udp.o \
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

tun.o: tun.c tun.h
	$(CC) $(CCFLAGS) $< -c

udp.o: udp.c udp.h
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
