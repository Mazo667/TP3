#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

/* ugly shortcut -- Ethernet packet headers are 14 bytes */
#define ETH_HEADER_SIZE 14
#define AVS_HEADER_SIZE 64                 /* AVS capture header size */
#define DATA_80211_FRAME_SIZE 24           /* header for 802.11 data packet */
#define LLC_HEADER_SIZE 8                  /* LLC frame for encapsulation */

/* SNAP LLC header format */
struct snap_header           
{
  u_int8_t dsap; 
  u_int8_t ssap;
  u_int8_t ctl;
  u_int16_t org; 
  u_int8_t org2;
  u_int16_t ether_type;          /* ethernet type */              
} __attribute__ ((__packed_ ,_));

/* for the sake of clarity we'll use globals for a few things */
char *device;     /* device to sniff on */
int verbose = 0;    /* verbose output about device */
pcap_t *handle;     /* handle for the opened pcap session */
int wired=0;        /* flag for wired/wireless */

/* gracefully handle a Control C */
void
ctrl_c ( )
{
  printf ("Exiting\n");
  pcap_breakloop (handle);  /* tell pcap_loop or pcap_dispatch to stop capturing */
  pcap_close(handle);
  exit (0);
}

/* usage */
void
usage (char *name)
{
  printf ("%s - simple ARP sniffer\n", name);
  printf ("Usage: %s [-i interface] [-l] [-v]\n", name);
  printf ("    -i    interface to sniff on\n");
  printf ("    -l    list available interfaces\n");
  printf ("    -v    print verbose info\n\n");
  exit (1);
}

/* callback function to process a packet when captured */
void
process_packet (u_char * args, const struct pcap_pkthdr *header,
    const u_char * packet)
{
  struct ether_header *eth_header;  /* in ethernet.h included by if_eth.h */
  struct snap_header *llc_header;   /* RFC 1042 encapsulation header */
  struct ether_arp *arp_packet;     /* from if_eth.h */

  if (wired)     /* global flag - wired or wireless? */
  {
    eth_header = (struct ether_header *) packet;
    arp_packet = (struct ether_arp *) (packet + ETH_HEADER_SIZE);
    if (ntohs (eth_header->ether_type) != ETHERTYPE_ARP) return;
  } else {      /* wireless */
    llc_header = (struct snap_header *) 
          (packet + AVS_HEADER_SIZE + DATA_80211_FRAME_SIZE);
    arp_packet = (struct ether_arp *) 
          (packet + AVS_HEADER_SIZE + DATA_80211_FRAME_SIZE + LLC_HEADER_SIZE);
    if (ntohs (llc_header->ether_type) != ETHERTYPE_ARP) return;
  }

  printf ("Source: %d.%d.%d.%d\t\tDestination: %d.%d.%d.%d\n",
    arp_packet->arp_spa[0],
    arp_packet->arp_spa[1],
    arp_packet->arp_spa[2],
    arp_packet->arp_spa[3],
    arp_packet->arp_tpa[0],
    arp_packet->arp_tpa[1],
    arp_packet->arp_tpa[2],
    arp_packet->arp_tpa[3]);
}

int
main (int argc, char *argv[])
{
  char o;     /* for option processing */
  char errbuf[PCAP_ERRBUF_SIZE];  /* pcap error messages buffer */
  struct pcap_pkthdr header;  /* packet header from pcap */
  const u_char *packet;   /* packet */
  bpf_u_int32 netp;   /* ip address of interface */
  bpf_u_int32 maskp;    /* subnet mask of interface */
  char *filter = "arp";   /* filter for BPF (human readable) */
  struct bpf_program fp;  /* compiled BPF filter */
  int r;      /* generic return value */
  pcap_if_t *alldevsp;    /* list of interfaces */

  while ((o = getopt (argc, argv, "i:vl")) > 0)
    {
      switch (o)
  {
  case 'i':
    device = optarg;
        break;
  case 'l':
    if (pcap_findalldevs (&alldevsp, errbuf) < 0)
      {
        fprintf (stderr, "%s", errbuf);
        exit (1);
      }
    while (alldevsp != NULL)
      {
        printf ("%s\n", alldevsp->name);
        alldevsp = alldevsp->next;
      }
    exit (0);
  case 'v':
    verbose = 1;
    break;
  default:
    usage (argv[0]);
    break;
  }
    }

  /* setup signal handler so Control-C will gracefully exit */
  signal (SIGINT, ctrl_c);

  /* find device for sniffing if needed */
  if (device == NULL)   /* if user hasn't specified a device */
    {
      device = pcap_lookupdev (errbuf); /* let pcap find a compatible device */
            if (device == NULL) /* there was an error */
  {
    fprintf (stderr, "%s", errbuf);
    exit (1);
  }
    }

  /* set errbuf to 0 length string to check for warnings */
  errbuf[0] = 0;

  /* open device for sniffing */
  handle = pcap_open_live (device,  /* device to sniff on */
         BUFSIZ,  /* maximum number of bytes to capture per packet */
                  /* BUFSIZE is defined in pcap.h */
         1, /* promisc - 1 to set card in promiscuous mode, 0 to not */
         0, /* to_ms - amount of time to perform packet capture in milliseconds */
            /* 0 = sniff until error */
         errbuf); /* error message buffer if something goes wrong */

  if (handle == NULL)   /* there was an error */
    {
      fprintf (stderr, "%s", errbuf);
      exit (1);
    }

  if (strlen (errbuf) > 0)
    {
      fprintf (stderr, "Warning: %s", errbuf);  /* a warning was generated */
      errbuf[0] = 0;    /* re-set error buffer */
    }

  if (verbose)
    {
      printf ("Using device: %s\n", device);
      /* printf ("Using libpcap version %s", pcap_lib_version); */
    }

 /* find out the datalink type of the connection */
  if (pcap_datalink (handle) == DLT_EN10MB)
  {
    wired = 1;     /* ethernet link */
  } else {
    if (pcap_datalink (handle) == DLT_IEEE802_11_RADIO_AVS)
    {
      wired = 0;  /* wireless */
    } else {
      fprintf (stderr, "I don't support this interface type!\n");
      exit (1);
    }
  }

  /* get the IP subnet mask of the device, so we set a filter on it */
  if (pcap_lookupnet (device, &netp, &maskp, errbuf) == -1)
    {
      fprintf (stderr, "%s", errbuf);
            exit (1);
    }

  /* compile the filter, so we can capture only stuff we are interested in */
  if (pcap_compile (handle, &fp, filter, 0, maskp) == -1)
    {
      fprintf (stderr, "%s", pcap_geterr (handle));
      exit (1);
    }

  /* set the filter for the device we have opened */
  if (pcap_setfilter (handle, &fp) == -1)
    {
      fprintf (stderr, "%s", pcap_geterr (handle));
      exit (1);
    }

  /* we'll be nice and free the memory used for the compiled filter */
  pcap_freecode (&fp);

  if ((r = pcap_loop (handle, -1, process_packet, NULL)) < 0)
    {
      if (r == -1)    /* pcap error */
  {
    fprintf (stderr, "%s", pcap_geterr (handle));
    exit (1);
  }
      /* otherwise return should be -2, meaning pcap_breakloop has been called */
         }

  /* close our devices */
  pcap_close (handle);
}