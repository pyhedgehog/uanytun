/*
 *  �Anytun
 *
 *  �Anytun is a tiny implementation of SATP. Unlike Anytun which is a full
 *  featured implementation �Anytun has no support for multiple connections
 *  or synchronisation. It is a small single threaded implementation intended
 *  to act as a client on small platforms.
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methodes used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *  
 *
 *  Copyright (C) 2007-2008 Christian Pointner <equinox@anytun.org>
 *
 *  This file is part of �Anytun.
 *
 *  �Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  �Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with �Anytun. If not, see <http://www.gnu.org/licenses/>.
 */

#include "log.h"
#include "signal.h"
#include <signal.h>

volatile sig_atomic_t signal_exit = 0;

void signal_init()
{
  signal(SIGINT, handle_signal_exit);
  signal(SIGQUIT, handle_signal_exit);
  signal(SIGTERM, handle_signal_exit);

  signal(SIGHUP, handle_signal);
  signal(SIGUSR1, handle_signal);
  signal(SIGUSR2, handle_signal);
}

void handle_signal(int sig)
{
  switch(sig) {
  case SIGHUP: log_printf(NOTICE, "SIG-Hup caught"); break;
  case SIGUSR1: log_printf(NOTICE, "SIG-Usr1 caught"); break;
  case SIGUSR2: log_printf(NOTICE, "SIG-Usr2 caught"); break;
  default: log_printf(NOTICE, "Signal %d caught, ignoring", sig); break;
  }
}

void handle_signal_exit(int sig)
{
  switch(sig) {
  case SIGINT: log_printf(NOTICE, "SIG-Int caught, exiting"); break;
  case SIGQUIT: log_printf(NOTICE, "SIG-Quit caught, exiting"); break;
  case SIGTERM: log_printf(NOTICE, "SIG-Term caught, exiting"); break;
  default: log_printf(NOTICE, "Signal %d caught, ignoring", sig); return;
  }

  if (signal_exit)
    raise (sig);
  signal_exit = 1;
 
  // do cleanup here

  signal (sig, SIG_DFL);
  raise (sig);
}

