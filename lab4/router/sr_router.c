/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "vnscommand.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
    
  /* Lab4: Fill your code here */
  printf("------------------------Sending Packet------------------------- \n");
  print_hdr_eth(packet);

  if (ethertype(packet) == ethertype_arp){

    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)packet;
    sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
    struct sr_if* sr_interface = sr_get_interface(sr, interface);

    /* opcode determines if packet is request or response */
    uint16_t opcode = ntohs(arp_header->ar_op);

    if (opcode == arp_op_request){
      /* 1.a.i */
      struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);
      /* 1.a.ii [TODO] */
      print_hdr_arp(arp_header);
      /* 1.a.iii.1 */
      uint8_t* response = (uint8_t * )malloc(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));
      sr_ethernet_hdr_t* response_eth_hdr = (sr_ethernet_hdr_t*)response;
      sr_arp_hdr_t* response_arp_hdr = (sr_arp_hdr_t*)(response+sizeof(sr_ethernet_hdr_t)); 

      /* 1.a.iii.2 : Fill the ARP opcode, Sender IP, Sender MAC, Target IP, Target MAC in ARP header */
      response_arp_hdr->ar_op = htons(arp_op_reply);
      response_arp_hdr->ar_sip = sr_interface->ip;
      memcpy(response_arp_hdr->ar_sha, sr_interface->addr, ETHER_ADDR_LEN);
      response_arp_hdr->ar_tip = arp_header->ar_sip;
      memcpy(response_arp_hdr->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);

      response_arp_hdr->ar_hrd = arp_header->ar_hrd;
      response_arp_hdr->ar_pro = arp_header->ar_pro;
      response_arp_hdr->ar_hln = arp_header->ar_hln;
      response_arp_hdr->ar_pln = arp_header->ar_pln;

      /* 1.a.iii.3 : Fill the Source MAC Address, Destination MAC Address, Ethernet Type in the Ethernet header */
      memcpy(response_eth_hdr->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
      memcpy(response_eth_hdr->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
      response_eth_hdr->ether_type = ethernet_header->ether_type;

      /* 1.a.iv : Send this ARP response back to the Sender */
      sr_send_packet(sr, response, sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t), sr_interface->name);

    }
  /*Determines if packet type is IP*/
  else if (ethertype(packet) == ethertype_ip){
    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
    struct sr_if* sr_interface = sr_get_interface(sr, interface);
    
    uint16_t ip_checksum = ip_header->ip_sum;
    uint16_t check_checksum = 0;
    ip_header->ip_sum = 0; 
    check_checksum = cksum(ip_header,sizeof(sr_ip_hdr_t));
    /*2.a: Check whether the checksum in the IP header is correct. If incorrect, ignore packet and return*/
    if (ip_checksum != check_checksum){
      printf("Dropping Packet, Checksum test failed \n");
      return;
    }
    else{ 
      ip_header->ip_sum = ip_checksum;
    }
    /*2.b: If the destination IP of this packet is router's own IP*/
    struct sr_if* dest_interface = get_if_from_ip(sr, ip_header->ip_dst);
    if(dest_interface){
      /*2.b.i If this is an ICMP packet:*/
      if(ip_header->ip_p == ip_protocol_icmp){
        sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(((uint8_t*)packet + sizeof(ip_header)));
        uint8_t echo_request = 0x08; 
        /*2.b.i.1 If not an ICMP ECHO packet, ignore*/
        if(icmp_header->icmp_type == echo_request){
          return;
        }
        /*2.b.i.2 Generate a correct ICMP Reply Packet*/
        else{
          /*2.b.i.2.a Malloc a space to store ethernet header, IP header and ICMP header*/
          uint8_t* reply = (uint8_t * )malloc(ntohs(ip_header->ip_len) + sizeof(sr_ethernet_hdr_t));
          sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t*)reply;
          sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t*)(reply+sizeof(sr_ethernet_hdr_t));
          sr_icmp_t8_hdr_t* reply_icmp_hdr = (sr_icmp_t8_hdr_t*)(reply+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
           /*2.b.i.2.b Fill the ICMP code, type the ICMP header*/
          reply_icmp_hdr->icmp_type = 0x00;
          reply_icmp_hdr->icmp_code = 0x00;
          
          /*2.b.i.2.c Fill the source IP address, destination IP address, ttl, protocol, length, checksum in IP header*/
          reply_ip_hdr->ip_src = ip_header->ip_dst; 
          reply_ip_hdr->ip_dst = ip_header->ip_src; 
          reply_ip_hdr->ip_ttl = INIT_TTL; 
          reply_ip_hdr->ip_p = ip_protocol_icmp; 
          reply_ip_hdr->ip_len = ip_header->ip_len; 
          reply_ip_hdr->ip_sum = ip_header->ip_sum; 
           /*2.b.i.2.d.Fill the Source MAC Address, Destination MAC Address, Ethernet Type in ethernet header*/
          memcpy(reply_eth_hdr->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
          memcpy(reply_eth_hdr->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
          reply_eth_hdr->ether_type = ethernet_header->ether_type;
           /*2.b.i.2.e find the Destination MAC Address from the ARP cache which you have done in step 1.a.i*/
          /*2.b.i.3 : Send this ICMP reply back to the Sender */
          sr_send_packet(sr, reply, sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), sr_interface->name);
         }
      }
      /*2.b.ii send the ICMP Destination protocol unreachable back to the Sender*/
      else{
        uint8_t* reply = (uint8_t * )malloc(sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
        sr_ethernet_hdr_t* reply_eth_hdr = (sr_ethernet_hdr_t*)reply;
        sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t*)(reply+sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t* reply_icmp_hdr = (sr_icmp_t3_hdr_t*)(reply+sizeof(sr_ethernet_hdr_t));
        reply_icmp_hdr->icmp_type = 3;
        reply_icmp_hdr->icmp_code = 1;
        memcpy(reply_icmp_hdr->data, packet, ICMP_DATA_SIZE);
        reply_ip_hdr->ip_src = ip_header->ip_dst; 
        reply_ip_hdr->ip_dst = ip_header->ip_src; 
        reply_ip_hdr->ip_ttl = INIT_TTL; 
        reply_ip_hdr->ip_p = ip_protocol_icmp; 
        reply_ip_hdr->ip_len = ip_header->ip_len; 
        reply_ip_hdr->ip_sum = ip_header->ip_sum;
        memcpy(reply_eth_hdr->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
        memcpy(reply_eth_hdr->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
        reply_eth_hdr->ether_type = ethernet_header->ether_type;
        sr_send_packet(sr, reply, sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), sr_interface->name);
      }
    }
    /*2.c.i Check whether the TTL in the IP header equals 1. If TTL=1, your router should reply an ICMP Time Exceeded message back to the Sender*/
    else{
     if(ip_header->ip_ttl==1){
         return;
      }
    }
  }
}
}

}/* end sr_ForwardPacket */
