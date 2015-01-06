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
 *  message authentication based on the methods used by SRTP.  It is
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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>

#include "datatypes.h"
#include "options.h"

static int owrt_string(char** dest, char* start, char* end)
{
  if(!dest || start >= end)
    return -1;

  if(*dest) free(*dest);
  int n = end - start;
  *dest = malloc(n+1);
  if(!(*dest))
    return -2;

  memcpy(*dest, start, n);
  (*dest)[n] = 0;

  return 0;
}

%%{
  machine cfg_parser;

  action set_cpy_start  { cpy_start = fpc; }
  action set_local_addr { ret = owrt_string(&(opt->local_addr_), cpy_start, fpc); cpy_start = NULL; }
  action set_local_port { ret = owrt_string(&(opt->local_port_), cpy_start, fpc); cpy_start = NULL; }
  action set_remote_addr { ret = owrt_string(&(opt->remote_addr_), cpy_start, fpc); cpy_start = NULL; }
  action set_remote_port { ret = owrt_string(&(opt->remote_port_), cpy_start, fpc); cpy_start = NULL; }
  action logerror {
    if(fpc == eof)
      fprintf(stderr, "config file syntax error: unexpected end of file\n");
    else
      fprintf(stderr, "config file syntax error at line %d\n", cur_line);

    fgoto *cfg_parser_error;
  }

  newline = '\n' @{cur_line++;};
  ws = [ \t];
  comment = '#' [^\n]* newline;
  ign = ( ws | comment | newline | [\v\f\r] );

  number = [0-9]+;
  ipv4_addr = [0-9.]+;
  ipv6_addr = [0-9a-fA-F:]+;
  name = [a-zA-Z0-9\-]+;
  host_name = [a-zA-Z0-9\-.]+;

  host_or_addr = ( host_name | ipv4_addr | ipv6_addr );
  service = ( number | name );

  local_addr = ( '*' | host_or_addr >set_cpy_start %set_local_addr );
  local_port = service >set_cpy_start %set_local_port;
  remote_addr = host_or_addr >set_cpy_start %set_remote_addr;
  remote_port = service >set_cpy_start %set_remote_port;

  opt_laddr = "interface" ws* "=" ws* local_addr ign* newline;
  opt_lport = "port" ws* "=" ws* local_port ign* newline;
  opt_raddr = "remote-host" ws* "=" ws* remote_addr ign* newline;
  opt_rport = "remote-port" ws* "=" ws* remote_port ign* newline;

  option = ( opt_laddr | opt_lport | opt_raddr | opt_rport );

  section_head = '[' name ']';
  section_body = ( ign | option )+;

  main := ( section_head ign* section_body | ign+ )* $!logerror;
}%%


static int parse_options(char* p, char* pe, options_t* opt)
{
  int cs, ret = 0, cur_line = 1;

  %% write data;
  %% write init;

  char* cpy_start = NULL;
  char* eof = pe;
  %% write exec;

  if(cs == cfg_parser_error) {
        /* revert config updates */
    ret = -1;
  }
  else {
        /* TODO: apply config update */
    ret = 0;
  }

  return ret;
}

int read_configfile(const char* filename, options_t* opt)
{
  int fd = open(filename, 0);
  if(fd < 0) {
    fprintf(stderr, "config: open('%s') failed: %s\n", filename, strerror(errno));
    return -1;
  }

  struct stat sb;
  if(fstat(fd, &sb) == -1) {
    fprintf(stderr, "config: fstat() error: %s\n", strerror(errno));
    close(fd);
    return -1;
  }

  if(!sb.st_size) {
    fprintf(stderr, "config: '%s' is empty\n", filename);
    close(fd);
    return -1;
  }

  if(!S_ISREG(sb.st_mode)) {
    fprintf(stderr, "config: '%s' is not a regular file\n", filename);
    close(fd);
    return -1;
  }

  char* p = (char*)mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if(p == MAP_FAILED) {
    fprintf(stderr, "config: mmap() error: %s\n", strerror(errno));
    close(fd);
    return -1;
  }
  close(fd);

  fprintf(stderr, "config: mapped %ld bytes from file %s at address 0x%08lX\n", sb.st_size, filename, (unsigned long int)p);
  int ret = parse_options(p, p + sb.st_size, opt);

  if(munmap(p, sb.st_size) == -1) {
    fprintf(stderr, "config: munmap() error: %s\n", strerror(errno));
    return -1;
  }
  fprintf(stderr, "config: unmapped '%s'\n", filename);

  return ret;
}
