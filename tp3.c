// Compile: gcc tp3.c -o tp3 -lpcap

/* Libreria libpcap */
#include <pcap.h>

/* libreria de Hilos */
#include <pthread.h>

/* Libreria de señales */
#include <signal.h>

/* Librerias de C */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

/* Liberias de Red */
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>


/* Variables globales para contar paquetes */ 
int arp_count = 0, icmp_count = 0, ip_count = 0, udp_count = 0, tcp_count = 0;
pthread_mutex_t count_mutex;

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

// Función que se ejecutará cada vez que se capture una trama
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Primero, obtenemos la cabecera Ethernet
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    // Verificamos el tipo de protocolo (IP, ARP, etc.)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("\n-----Paquete IP capturado-----\n");
        // Obtenemos la cabecera IP que sigue a la cabecera Ethernet
        struct iphdr *ip_header;
        ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
        // Imprime información de la cabecera IP, como la dirección IP de origen y destino
        printf("   De: %d.%d.%d.%d, ", ip_header->saddr & 0xFF, (ip_header->saddr >> 8) & 0xFF, (ip_header->saddr >> 16) & 0xFF, (ip_header->saddr >> 24) & 0xFF);
        printf("a: %d.%d.%d.%d\n", ip_header->daddr & 0xFF, (ip_header->daddr >> 8) & 0xFF, (ip_header->daddr >> 16) & 0xFF, (ip_header->daddr >> 24) & 0xFF);

        ip_count++; // Incrementa el contador de paquetes IP

        /* TCP Y UDP estan encapusulados dentro de IP */
        if (ip_header->protocol == IPPROTO_TCP) {
            printf("   Paquete TCP capturado\n");
            // Obtenemos la cabecera TCP que sigue a la cabecera IP
            struct tcphdr *tcp_header;
            tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            
            // Imprime cabecera TCP
            printf("     Puerto de origen: %d, ", ntohs(tcp_header->source));
            printf("     Puerto de destino: %d\n", ntohs(tcp_header->dest));
            printf("     Numero de secuencia: %d\n", tcp_header->seq);
            printf("     Numero de ACK: %d\n", tcp_header->ack_seq);
            printf("     Data Offset: %d\n", tcp_header->doff);
            printf("     Flags: %d | %d | %d | %d | %d | %d\n", tcp_header->urg, tcp_header->ack, tcp_header->psh, tcp_header->rst, tcp_header->syn, tcp_header->fin);
            printf("     Ventana: %d\n", ntohs(tcp_header->window));
            printf("     Checksum: %d\n", ntohs(tcp_header->check));
            printf("     Puntero urgente: %d\n", tcp_header->urg_ptr);
            printf("     Opciones: %ld\n", tcp_header->doff * 4 - sizeof(struct tcphdr));
            printf("     Datos (Longitud): %ld\n", header->len - (sizeof(struct ether_header) + sizeof(struct iphdr) + tcp_header->doff * 4));

            tcp_count++; // Incrementa el contador de paquetes TCP
        } else if (ip_header->protocol == IPPROTO_UDP) {
            printf("   Paquete UDP capturado\n");
            // Obtenemos la cabecera UDP que sigue a la cabecera IP
            struct udphdr *udp_header;
            udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            // Imprime la cabecera UDP
            printf("     Puerto de origen: %d, ", ntohs(udp_header->source));
            printf("     Puerto de destino: %d\n", ntohs(udp_header->dest));
            printf("     Longitud: %d\n", ntohs(udp_header->len));
            printf("     Checksum: %d\n", ntohs(udp_header->check));
            printf("     Datos (Longitud): %ld\n", header->len - (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)));

            udp_count++; // Incrementa el contador de paquetes UDP
        } else if (ip_header->protocol == IPPROTO_ICMP){
            printf("   Paquete ICMP capturado\n");
            // Obtenemos la cabecera ICMP que sigue a la cabecera IP
            struct icmphdr *icmp_header;
            icmp_header = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            // Imprime la cabecera ICMP
            printf("     Tipo: %d, ", icmp_header->type);
            printf("     Codigo: %d\n", icmp_header->code);
            printf("     Checksum: %d\n", ntohs(icmp_header->checksum));
            printf("     Identificador: %d, ", ntohs(icmp_header->un.echo.id));
            printf("     Secuencia: %d\n", ntohs(icmp_header->un.echo.sequence));
            printf("     Datos (Longitud): %ld\n", header->len - (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)));

            icmp_count++; // Incrementa el contador de paquetes ICMP
        }
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        
        printf("\n-----Paquete ARP capturado-----\n");
        struct ether_arp *arp_packet;
        arp_packet = (struct ether_arp *)(packet + sizeof(struct ether_header));
       
        printf("   De: %s, ", ether_ntoa((struct ether_addr *)arp_packet->arp_sha));
        printf("a: %s\n", ether_ntoa((struct ether_addr *)arp_packet->arp_tha));
        
        // Imprimir la cabecera ARP
        printf("     Tipo de hardware: %d\n", ntohs(arp_packet->arp_hrd));
        printf("     Tipo de protocolo: %d\n", ntohs(arp_packet->arp_pro));
        printf("     Longitud de hardware: %d\n", arp_packet->arp_hln);
        printf("     Longitud de protocolo: %d\n", arp_packet->arp_pln);
        printf("     Operación: %s\n", (ntohs(arp_packet->arp_op) == ARPOP_REQUEST) ? "Solicitud" : "Respuesta");
        printf("     Dirección MAC de origen: %s, ", ether_ntoa((struct ether_addr *)arp_packet->arp_sha));
        printf("     Dirección IP de origen: %s\n", inet_ntoa(*(struct in_addr *)arp_packet->arp_spa));
        printf("     Direccion MAC de destino: %s, ", ether_ntoa((struct ether_addr *)arp_packet->arp_tha));
        printf("     Dirección IP de destino: %s\n", inet_ntoa(*(struct in_addr *)arp_packet->arp_tpa));

        arp_count++; // Incrementa el contador de paquetes ARP
    } else {
        printf("\n-----Tipo de paquete no solicitado-----\n");
    }
}

// Definición del manejador de señales
void sig_int(int sig) {
    printf("\n---Señal de interrupción recibida---\n");
    printf("Datos Estadisticos Finales: \n");
    printf("   Tramas capturadas de tipo ARP: %d\n", arp_count);
    printf("   Tramas capturadas de tipo IP: %d\n", ip_count);
    printf("   Tramas capturadas de tipo ICMP: %d\n", icmp_count);
    printf("   Tramas capturadas de tipo UDP: %d\n", udp_count);
    printf("   Tramas capturadas de tipo TCP: %d\n", tcp_count);

    pthread_mutex_destroy(&count_mutex); // Destruye el mutex
    exit(0); // Usamos _exit aquí para terminar inmediatamente el proceso
}


/* El programa tomara como parametro obligatorio de llamada el numero maximo de tramas que 
   capturara antes de finalizar. Si este parametro es 0, el programa se ejecutara indefinidimanete
   hasta que sea interrumpiudo por el usuario al pulsar ctrl-c  */

int main(int argc, char* argv[]){
    pcap_if_t *alldevs; // Lista de dispositivos
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer de error
    int num_packets; // Numero de tramas a capturar

    // Verifica si se ingreso el numero de tramas a capturar
    if(argc != 2){
        printf("Para ejecutar correctamente ingrese: <numero de tramas a capturar>\n");
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

    char *device; // Dispositivo

    // Obtiene el nombre del primer dispositivo
    device = alldevs->name;

    // Imprime el primer dispositivo encontrado
    printf("Dispositivo: %s\n", device);

    //Una vez que tenemos una interfaz, podemos abrir la interfaz para capturar paquetes
    pcap_t *handle; // Descriptor de la interfaz

    handle = pcap_open_live (device,  // Dispositivo a capturar
                            BUFSIZ,   // Numero maximo de bytes a capturar por trama
                            1,        // 1 modo Promiscuo y 0 modo no promiscuo
                            0,        // 1 = tiempo de espera en milisegundos, 0 = infinito
                            errbuf);  // Buffer de error si paso algo mal

    if (handle == NULL) { // Verifica si hubo un error al abrir la interfaz
        fprintf (stderr, "%s", errbuf);
        exit (1);
    }

    if (strlen (errbuf) < 1) { // Verifica si hubo un warning
        fprintf (stderr, "Warning: %s", errbuf);  /* a warning was generated */
        errbuf[0] = 0;    /* reset error buffer */
    }

    if (pcap_datalink (handle) != DLT_EN10MB) { // Verifica si la interfaz de tipo Ethernet
        fprintf (stderr, "This program only supports Ethernet cards!\n");
        exit (1);
    }

    /* Declaro variables para imprimir la Direccion de Red y de Mascara */
    bpf_u_int32 net;		/* ip */
    bpf_u_int32 mask;		/* Mascara */
    char *net_addr;        
    struct in_addr addr;

    // Obtiene la direccion de red y la mascara
    if (pcap_lookupnet (device, &net, &mask, errbuf) == -1){
      fprintf (stderr, "%s", errbuf);
      exit (1);
    }
    
    // Imprime la direccion de red y la mascara
    printf("Direccion de red: %s\n", inet_ntoa(*(struct in_addr *)&net));
    printf("Mascara Subred: %s\n", inet_ntoa(*(struct in_addr *)&mask));

    /* HILOS */

    // Inicializar el mutex
    pthread_mutex_init(&count_mutex, NULL);

    // Crear un hilo para mostrar las estadísticas en tiempo real
    pthread_t stats_thread;
    pthread_create(&stats_thread, NULL, print_stats, NULL);


    signal(SIGINT, sig_int); // Manejador de señales



    // Verifica si el parametro es 0, si es 0 se ejecutara indefinidamente si no se ejecutara el numero de tramas ingresado
    if(strlen(argv[1]) == 0){
        pcap_loop(handle, -1 , got_packet, NULL);
    }else{
        pcap_loop(handle, num_packets, got_packet, NULL);
    }

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("Datos Estadisticos Finales: \n");
    printf("Tramas capturadas de tipo ARP: %d\n", arp_count);
    printf("Tramas capturadas de tipo ICMP: %d\n", icmp_count);
    printf("Tramas capturadas de tipo IP: %d\n", ip_count);
    printf("Tramas capturadas de tipo UDP: %d\n", udp_count);
    printf("Tramas capturadas de tipo TCP: %d\n", tcp_count);
    

    return 0;
}