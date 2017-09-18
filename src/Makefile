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
##  message authentication based on the methods used by SRTP.  It is
##  intended to deliver a generic, scaleable and secure solution for
##  tunneling and relaying of packets of any protocol.
##
##
##  Copyright (C) 2007-2017 Christian Pointner <equinox@anytun.org>
##
##  This file is part of uAnytun.
##
##  uAnytun is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation, either version 3 of the License, or
##  any later version.
##
##  uAnytun is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with uAnytun. If not, see <http://www.gnu.org/licenses/>.
##
##  In addition, as a special exception, the copyright holders give
##  permission to link the code of portions of this program with the
##  OpenSSL library under certain conditions as described in each
##  individual source file, and distribute linked combinations
##  including the two.
##  You must obey the GNU General Public License in all respects
##  for all of the code used other than OpenSSL.  If you modify
##  file(s) with this exception, you may extend this exception to your
##  version of the file(s), but you are not obligated to do so.  If you
##  do not wish to do so, delete this exception statement from your
##  version.  If you delete this exception statement from all source
##  files in the program, then also delete it here.
##

ifneq ($(MAKECMDGOALS),distclean)
include include.mk
endif

EXECUTABLE := uanytun
EXECUTABLE_TEST := testvectors

CRYPT_OBJ := key_derivation.o \
             auth_algo.o
OBJ := log.o \
       string_list.o \
       sig_handler.o \
       sysexec.o \
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

OBJ_TEST := key_derivation.o \
						log.o \
						testvectors.o

SRC := $(OBJ:%.o=%.c)
SRC_TEST := $(OBJ_TEST:%.o=%.c)

.PHONY: clean cleanall distclean manpage install install-bin install-etc install-man uninstall remove purge

all: $(EXECUTABLE)

%.d: %.c
	@set -e; rm -f $@; \
  $(CC) -MM $(CFLAGS) $< > $@.$$$$; \
  sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
  rm -f $@.$$$$; echo '(re)building $@'

ifneq ($(MAKECMDGOALS),distclean)
-include $(SRC:%.c=%.d)
endif

$(EXECUTABLE): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

testvectors: $(OBJ_TEST)
	$(CC) $(OBJ_TEST) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<


strip: $(EXECUTABLE)
	$(STRIP) -s $(EXECUTABLE)

distclean: cleanall
	find . -name *.o -exec rm -f {} \;
	find . -name "*.\~*" -exec rm -rf {} \;
	rm -f include.mk
	rm -f version.h
	rm -f tun.c

clean:
	rm -f *.o
	rm -f *.d
	rm -f *.d.*
	rm -f $(EXECUTABLE)

cleanall: clean
	$(MAKE) --directory="../doc/" clean

manpage:
	$(MAKE) --directory="../doc/" manpage


INSTALL_TARGETS := install-bin install-etc
REMOVE_TARGETS := remove-bin remove-etc

ifdef MANDIR
INSTALL_TARGETS += install-man
REMOVE_TARGETS += remove-man
endif

ifdef EXAMPLESDIR
INSTALL_TARGETS += install-examples
REMOVE_TARGETS += remove-examples
endif

install: all $(INSTALL_TARGETS)

install-bin: $(EXECUTABLE)
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 755 $(EXECUTABLE) $(DESTDIR)$(SBINDIR)

install-etc:
	$(INSTALL) -d $(DESTDIR)$(ETCDIR)/$(EXECUTABLE)
	@ echo "example configurations can be found at $(EXAMPLESDIR)/$(EXECUTABLE)" > $(DESTDIR)$(ETCDIR)/$(EXECUTABLE)/README
	$(INSTALL) -d $(DESTDIR)$(ETCDIR)/init.d
	@ sed -e 's#DAEMON=/usr/sbin/uanytun#DAEMON=$(SBINDIR)/$(EXECUTABLE)#' \
        -e 's#CONFIG_DIR=/etc/uanytun#CONFIG_DIR=$(ETCDIR)/uanytun#' ../etc/init.d/uanytun > ../etc/init.d/uanytun.bak
	$(INSTALL) -m 755 ../etc/init.d/uanytun.bak $(DESTDIR)$(ETCDIR)/init.d/$(EXECUTABLE)
	rm -f ../etc/init.d/uanytun.bak

install-examples:
	$(INSTALL) -d $(DESTDIR)$(EXAMPLESDIR)/$(EXECUTABLE)
	$(INSTALL) -m 644 ../etc/uanytun/autostart $(DESTDIR)$(EXAMPLESDIR)/$(EXECUTABLE)/autostart
	@( cd '../etc/uanytun/' ;                                                                        \
     for dir in `ls`; do                                                                           \
       if [ -d $$dir ]; then                                                                       \
         echo "install $$dir configuration" ;                                                      \
         cd $$dir ;                                                                                \
         $(INSTALL) -d $(DESTDIR)$(EXAMPLESDIR)/$(EXECUTABLE)/$$dir ;                              \
         $(INSTALL) -m 600 config $(DESTDIR)$(EXAMPLESDIR)/$(EXECUTABLE)/$$dir/config ;            \
         if [ -e 'post-up.sh' ]; then                                                              \
           $(INSTALL) -m 755 post-up.sh $(DESTDIR)$(EXAMPLESDIR)/$(EXECUTABLE)/$$dir/post-up.sh ;  \
         fi ;                                                                                      \
         cd .. ;                                                                                   \
       fi ;                                                                                        \
     done                                                                                          \
   )

install-man: manpage
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 644 ../doc/uanytun.8 $(DESTDIR)$(MANDIR)/man8/$(EXECUTABLE).8

uninstall: remove

remove: $(REMOVE_TARGETS)

remove-bin:
	rm -f $(DESTDIR)$(SBINDIR)/$(EXECUTABLE)

remove-etc:
	rm -f $(DESTDIR)$(ETCDIR)/init.d/$(EXECUTABLE)

remove-examples:
	rm -rf $(DESTDIR)$(EXAMPLESDIR)/$(EXECUTABLE)/

remove-man:
	rm -f $(DESTDIR)$(MANDIR)/man8/$(EXECUTABLE).8

purge: remove
	rm -rf $(DESTDIR)$(ETCDIR)/$(EXECUTABLE)/
