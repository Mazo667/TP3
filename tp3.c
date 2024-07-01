// Compile: gcc -o tp3 tp3.c -lpcap

/* Libreria libpcap */
#include <pcap.h>

/* Librerias de C */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* Librerias de Red */
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ether.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Cabecera ethernet */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* Cabecera IP */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* Cabecera TCP */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

// Funcion que se ejecutara cada vez que se capture una trama
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


/* El programa tomara como parametro obligatorio de llamada el numero maximo de tramas que 
   capturara antes de finalizar. Si este parametro es 0, el programa se ejecutara indefinidimanete
   hasta que sea interrumpiudo por el usuario al pulsar ctrl-c  */

int main(int argc, char* argv[]){
    pcap_if_t *alldevs; // Lista de dispositivos
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer de error
    char *device; // Dispositivo
    int num_packets; // Numero de tramas a capturar

    bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

    char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */


    // Verifica si se ingreso el numero de tramas a capturar
    if(argc != 2){
        printf("Uso: %s <numero de tramas a capturar>\n", argv[0]);
        return 1;
    }

    // Asignar el numero de tramas a capturar
    num_packets = atoi(argv[1]);

    // Intenta encontrar todos los dispositivos
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error: %s\n", errbuf);
        return 1;
    }

    // Verifica si se encontraron dispositivos
    if (alldevs == NULL) {
        printf("No se encontraron dispositivos. Asegúrate de tener permisos adecuados.\n");
        return 1;
    }

    // Obtiene el nombre del primer dispositivo
    device = alldevs->name;

    // Imprime el primer dispositivo encontrado
    printf("Dispositivo: %s\n", device);

     /* Una vez que tenemos una interfaz, podemos abrir la interfaz para capturar paquetes */

    pcap_t *handle; // Descriptor de la interfaz

    handle = pcap_open_live (device,  /* device to sniff on */
                            BUFSIZ,  /* maximum number of bytes to capture per packet */
                            1, /* promisc - 1 to set card in promiscuous mode, 0 to not */
                            0, /* to_ms - amount of time to perform packet capture in milliseconds */
                                /* 0 = sniff until error */
                            errbuf); /* error message buffer if something goes wrong */

    if (handle == NULL) { // Verifica si hubo un error al abrir la interfaz
        fprintf (stderr, "%s", errbuf);
        exit (1);
    }

    if (strlen (errbuf) > 0) { // Verifica si hubo un warning
        fprintf (stderr, "Warning: %s", errbuf);  /* a warning was generated */
        errbuf[0] = 0;    /* reset error buffer */
    }

    if (pcap_datalink (handle) != DLT_EN10MB) { // Verifica si la interfaz es Ethernet
        fprintf (stderr, "This program only supports Ethernet cards!\n");
        exit (1);
    }


	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

    /* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}


/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");
    

    return 0;



}