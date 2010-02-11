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
##  Copyright (C) 2007-2010 Christian Pointner <equinox@anytun.org>
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

VERSION=$(shell cat ../version)

.PHONY: clean 

all: manpage

uanytun.8: uanytun.8.txt
	a2x -f manpage $<
	@ sed -i -e 's/\[FIXME: source\]/uanytun ${VERSION}/' $@
	@ sed -i -e 's/\[FIXME: manual\]/uanytun user manual/' $@
	@ sed -i -e 's/^uanytun$$/\\fBuanytun\\fR/' $@
	@ sed -i -e 's/^  \[ \([^ ]*\)/  [ \\fB\1\\fR/' $@

manpage: uanytun.8

clean:
	rm -f uanytun.8.xml

realclean: clean
	rm -f uanytun.8
