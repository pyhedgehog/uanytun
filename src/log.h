/*
 *  uAnytun
 *
 *  uAnytun is a tiny implementation of SATP. Unlike Anytun which is a full
 *  featured implementation uAnytun has no support for multiple connections
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
 *  This file is part of uAnytun.
 *
 *  uAnytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  uAnytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with uAnytun. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <syslog.h>

enum log_facility_enum { USER = LOG_USER, MAIL = LOG_MAIL,
                         DAEMON = LOG_DAEMON, AUTH = LOG_AUTH,
                         SYSLOG = LOG_SYSLOG, LPR = LOG_LPR,
                         NEWS = LOG_NEWS, UUCP = LOG_UUCP,
                         CRON = LOG_CRON, AUTHPRIV = LOG_AUTHPRIV,
                         FTP = LOG_FTP, LOCAL0 = LOG_LOCAL0,
                         LOCAL1 = LOG_LOCAL1, LOCAL2 = LOG_LOCAL2,
                         LOCAL3 = LOG_LOCAL3, LOCAL4 = LOG_LOCAL4,
                         LOCAL5 = LOG_LOCAL5, LOCAL6 = LOG_LOCAL6,
                         LOCAL7 = LOG_LOCAL7 };
typedef enum log_facility_enum log_facility_t;

enum log_prio_enum { EMERG = LOG_EMERG, ALERT = LOG_ALERT,
                     CRIT = LOG_CRIT, ERR = LOG_ERR,
                     WARNING = LOG_WARNING, NOTICE = LOG_NOTICE,
                     INFO = LOG_INFO, DEBUG = LOG_DEBUG };
typedef enum log_prio_enum log_prio_t;

void log_init(const char* name, log_facility_t facility);
void log_printf(log_prio_t prio, const char* fmt, ...);

#endif
