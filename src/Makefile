##
##  uAnytun
##
##  uAnytun is a tiny implementation of SATP. Unlike Anytun which is a full
##  featured implementation uAnytun has no support for multiple connections
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
##  This file is part of uAnytun.
##
##  uAnytun is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License version 3 as
##  published by the Free Software Foundation.
##
##  uAnytun is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with uAnytun. If not, see <http://www.gnu.org/licenses/>.
##

include include.mk

EXECUTABLE := uanytun

CRYPT_OBJ := key_derivation.o \
            auth_algo.o
OBJ := log.o \
      signal.o \
      options.o \
      tun.o \
      udp.o \
      plain_packet.o \
      encrypted_packet.o \
      seq_window.o \
      cipher.o \
      uanytun.o


ifndef NO_CRYPT_OBJ
OBJ += $(CRYPT_OBJ)
endif

SRC := $(OBJ:%.o=%.c)

.PHONY: distclean clean

all: $(EXECUTABLE)

%.d: %.c
	@set -e; rm -f $@; \
	 $(CC) -MM $(CFLAGS) $< > $@.$$$$; \
   sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
   rm -f $@.$$$$; echo '(re)building $@'

-include $(SRC:%.c=%.d)

uanytun: $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<


distclean: clean
	find . -name *.o -exec rm -f {} \;
	find . -name "*.\~*" -exec rm -rf {} \;
	rm -f include.mk
	rm -f tun.c

clean:
	rm -f *.o
	rm -f *.d
	rm -f $(EXECUTABLE)
