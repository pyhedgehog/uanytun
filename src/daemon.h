/*
 *  µAnytun
 *
 *  µAnytun is a tiny implementation of SATP. Unlike Anytun which is a full
 *  featured implementation µAnytun has no support for multiple connections
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
 *  This file is part of µAnytun.
 *
 *  µAnytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  µAnytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with µAnytun. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _DAEMON_H_
#define _DAEMON_H_

#include <poll.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

void chrootAndDrop(const char* chrootdir, const char* username)
{
  if (getuid() != 0)
  {
    fprintf(stderr, "this programm has to be run as root in order to run in a chroot\n");
    exit(-1);
  }

  struct passwd *pw = getpwnam(username);
  if(pw) {
    if(chroot(chrootdir))
    {
      fprintf(stderr, "can't chroot to %s\n", chrootdir);
      exit(-1);
    }
    log_printf(NOTICE, "we are in chroot jail (%s) now\n", chrootdir);
    if(chdir("/"))
    {
      fprintf(stderr, "can't change to /\n");
      exit(-1);
    }
    if (initgroups(pw->pw_name, pw->pw_gid) || setgid(pw->pw_gid) || setuid(pw->pw_uid))
    {
      fprintf(stderr, "can't drop to user %s %d:%d\n", username, pw->pw_uid, pw->pw_gid);
      exit(-1);
    }
    log_printf(NOTICE, "dropped user to %s %d:%d\n", username, pw->pw_uid, pw->pw_gid);
  }
  else
  {
    fprintf(stderr, "unknown user %s\n", username);
    exit(-1);
  }
}

void daemonize()
{
  pid_t pid;

  pid = fork();
  if(pid) exit(0);
  setsid();
  pid = fork();
  if(pid) exit(0);

  int fd;
  for (fd=0;fd<=2;fd++) // close all file descriptors
    close(fd);
  fd = open("/dev/null",O_RDWR);        // stdin
  if(fd == -1)
    log_printf(WARNING, "can't open stdin (chroot and no link to /dev/null?)");
  else {
    if(dup(fd) == -1)   // stdout
      log_printf(WARNING, "can't open stdout");
    if(dup(fd) == -1)   // stderr
      log_printf(WARNING, "can't open stderr");
  }
  umask(027);
}

#endif

