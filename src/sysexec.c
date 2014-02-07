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
 *  Copyright (C) 2007-2014 Christian Pointner <equinox@anytun.org>
 *
 *  This file is part of uAnytun.
 *
 *  uAnytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  any later version.
 *
 *  uAnytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with uAnytun. If not, see <http://www.gnu.org/licenses/>.
 */

#include "datatypes.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sysexec.h"
#include "log.h"

int uanytun_exec(const char* script, char* const argv[], char* const evp[])
{
  if(!script)
    return -1;

  int pipefd[2];
  if(pipe(pipefd) == -1) {
    log_printf(ERROR, "executing script '%s' pipe() error: %s", script, strerror(errno));
    return -1;
  }

  pid_t pid;
  pid = fork();
  if(pid == -1) {
    log_printf(ERROR, "executing script '%s' fork() error: %s", script, strerror(errno));
    return -1;
  }

  if(!pid) {
    int fd;
    for (fd=getdtablesize();fd>=0;--fd) // close all file descriptors
      if(fd != pipefd[1]) close(fd);

    fd = open("/dev/null",O_RDWR);        // stdin
    if(fd == -1)
      log_printf(WARNING, "can't open stdin");
    else {
      if(dup(fd) == -1)   // stdout
        log_printf(WARNING, "can't open stdout");
      if(dup(fd) == -1)   // stderr
        log_printf(WARNING, "can't open stderr");
    }
    execve(script, argv, evp);
        // if execve returns, an error occurred, but logging doesn't work
        // because we closed all file descriptors, so just write errno to
        // pipe and call exit
    int ret = write(pipefd[1], (void*)(&errno), sizeof(errno));
    if(ret == -1) exit(-1);
    exit(-1);
  }
  close(pipefd[1]);

  int status = 0;
  waitpid(pid, &status, 0);

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(pipefd[0], &rfds);
  struct timeval tv = { 0 , 0 };
  if(select(pipefd[0]+1, &rfds, NULL, NULL, &tv) == 1) {
    int err = 0;
    if(read(pipefd[0], (void*)(&err), sizeof(err)) >= sizeof(err)) {
      log_printf(NOTICE, "script '%s' exec() error: %s", script, strerror(err));
      close(pipefd[0]);
      return -1;
    }
  }
  if(WIFEXITED(status))
    log_printf(NOTICE, "script '%s' returned %d", script, WEXITSTATUS(status));
  else if(WIFSIGNALED(status))
    log_printf(NOTICE, "script '%s' terminated after signal %d", script, WTERMSIG(status));
  else
    log_printf(ERROR, "executing script '%s': unknown error", script);

  close(pipefd[0]);
  return status;
}
