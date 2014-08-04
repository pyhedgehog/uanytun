#include <stdio.h>

#include "datatypes.h"

#include "plain_packet.h"
#include "encrypted_packet.h"
#include "packet_queue.h"

packet_queue_instantiate(4, plain_packet);
packet_queue_instantiate(4, encrypted_packet);

int main(int argc, char* argv[])
{
  packet_queue_init(plain_packet);
  packet_queue_init(encrypted_packet, 10);

  printf("acquire/release:\n");

  plain_packet_t* p1 = plain_packet_queue_get_next();
  printf("p1 acquire: %08lX\n", p1);
  plain_packet_t* p2 = plain_packet_queue_get_next();
  printf("p2 acquire: %08lX\n", p2);
  encrypted_packet_t* e1 = encrypted_packet_queue_get_next();
  printf("e1 acquire: %08lX\n", e1);
  encrypted_packet_t* e2 = encrypted_packet_queue_get_next();
  printf("e2 acquire: %08lX\n", e2);
  plain_packet_t* p3 = plain_packet_queue_get_next();
  printf("p3 acquire: %08lX\n", p3);

  printf("p1 release: %08lX\n", p1);
  plain_packet_queue_release(p1);
  printf("e2 release: %08lX\n", e2);
  encrypted_packet_queue_release(e2);
  printf("p2 release: %08lX\n", p2);
  plain_packet_queue_release(p2);

  encrypted_packet_t* e3 = encrypted_packet_queue_get_next();
  printf("e3 acquire: %08lX\n", p3);
  plain_packet_t* p4 = plain_packet_queue_get_next();
  printf("p4 acquire: %08lX\n", p4);
  encrypted_packet_t* e4 = encrypted_packet_queue_get_next();
  printf("e4 acquire: %08lX\n", e4);
  plain_packet_t* p5 = plain_packet_queue_get_next();
  printf("p5 acquire: %08lX\n", p5);
  plain_packet_t* p6 = plain_packet_queue_get_next();
  printf("p6 acquire: %08lX\n", p6);

  return 0;
}
