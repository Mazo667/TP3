// Compile: gcc tp3.c -o tp3 -lpcap

/* Libreria libpcap */
#include <pcap.h>

/* libreria de Hilos */
#include <pthread.h>
#include <unistd.h>

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

void got_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void *print_stats(void *arg);
void print_devices(pcap_if_t *alldevs);


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

// Definición de la función para contar dispositivos
int pcap_count_devices(pcap_if_t *alldevs) {
    int count = 0;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        count++;
    }
    return count;
}

/* El programa tomara como parametro obligatorio de llamada el numero maximo de tramas que 
   capturara antes de finalizar. Si este parametro es 0, el programa se ejecutara indefinidimanete
   hasta que sea interrumpiudo por el usuario al pulsar ctrl-c  */

int main(int argc, char* argv[]){
    pcap_if_t *alldevs; // Lista de dispositivos
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer de error
    int num_packets; // Numero de tramas a capturar
    pcap_t *handle; // Descriptor de la interfaz

    // Verifica si se ingreso el numero de tramas a capturar
    if(argc != 2){
        printf("Para ejecutar correctamente ingrese: <numero de tramas a capturar>\n");
        return 1;
    } else if (atoi(argv[1]) > 10 || atoi(argv[1]) < 0){
        printf("El numero de tramas a capturar debe ser un numero positivo menor o igual a 10\n");
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

    print_devices(alldevs); // Imprimo todos los dispositivos

    // El usuario selecciona un dispositivo
    int selection;
    printf("Seleccione un dispositivo (ingrese el número correspondiente): ");
    scanf("%d", &selection);

    // Verifica si la selección está dentro del rango válido
    if (selection < 1 || selection > pcap_count_devices(alldevs)) {
        printf("Selección inválida\n");
        return 1;
    }

    // Obtener el dispositivo seleccionado
    pcap_if_t *selected_device = alldevs;
    for (int i = 1; i < selection; i++) {
        selected_device = selected_device->next;
    }

    // Asignar el nombre del dispositivo seleccionado
    device = selected_device->name;

    /* Nombres de dispositivos comunes en Linux: eth0, eth1, enp0s3, wlp2s0 */	

    // Validar que el dispositivo seleccionado sea de tipo Ethernet
    if (strncmp(device, "eth", 3) != 0 && strncmp(device, "enp", 3) != 0 && strncmp(device, "wlp", 3) != 0){
        printf("No se puede seleccionar un dispositivo que no sea de tipo Ethernet\n");
        return 1;
    }

    // Imprime el  dispositivo seleccionado
    printf("Dispositivo seleccionado: (%s)\n", device);

    //Una vez que tenemos una interfaz, podemos abrir la interfaz para capturar paquetes
    handle = pcap_open_live (device,  // Dispositivo a capturar
                            BUFSIZ,   // Numero maximo de bytes a capturar por trama
                            1,        // 1 modo Promiscuo y 0 modo no promiscuo
                            1000,     // 1 = tiempo de espera en milisegundos, 0 = infinito
                            errbuf);  // Buffer de error si paso algo mal


    /* Declaro variables para imprimir la Direccion de Red y de Mascara */
    bpf_u_int32 net;		/* ip */
    bpf_u_int32 mask;		/* Mascara */

    // Obtiene la direccion de red y la mascara
    if (pcap_lookupnet (device, &net, &mask, errbuf) == -1){
      fprintf (stderr, "%s", errbuf);
      exit (1);
    }
    
    // Imprime la direccion de red y la mascara
    printf("Direccion de red: %s\n", inet_ntoa(*(struct in_addr *)&net));
    printf("Mascara Subred: %s\n", inet_ntoa(*(struct in_addr *)&mask));

    signal(SIGINT, sig_int); // Manejador de señales

    /* HILOS */

    // Inicializar el mutex
    pthread_mutex_init(&count_mutex, NULL);

    // Crear un hilo para mostrar las estadísticas en tiempo real
    pthread_t stats_thread;
    pthread_create(&stats_thread, NULL, print_stats, NULL);

    // Verifica si el parametro es 0, si es 0 se ejecutara indefinidamente si no se ejecutara el numero de tramas ingresado
    if(strlen(argv[1]) == 0){
        pcap_loop(handle, 0 , got_packet, NULL);
    }else if (strlen(argv[1]) <= 10 || strlen(argv[1]) >= 1){
        pcap_loop(handle, num_packets, got_packet, NULL);
    }

	printf("\nDatos Estadisticos Finales: \n");
    printf("Tramas capturadas de tipo ARP: %d\n", arp_count);
    printf("Tramas capturadas de tipo ICMP: %d\n", icmp_count);
    printf("Tramas capturadas de tipo IP: %d\n", ip_count);
    printf("Tramas capturadas de tipo UDP: %d\n", udp_count);
    printf("Tramas capturadas de tipo TCP: %d\n", tcp_count);
    
    pcap_close(handle); // Cierra el descriptor de la interfaz

    pthread_mutex_destroy(&count_mutex); // Destruye el mutex

    return 0;
}


// Función que se ejecutará cada vez que se capture una trama
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Primero, obtenemos la cabecera Ethernet
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    // Bloquea el mutex para evitar condiciones de carrera
    pthread_mutex_lock(&count_mutex);

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

    pthread_mutex_unlock(&count_mutex); // Desbloquea el mutex
}

// Función que se ejecutará cada vez que se capture una trama en tiempo real
void *print_stats(void *arg) {
    while (1) {
        sleep(1);
        pthread_mutex_lock(&count_mutex);
        printf("-------------------------------------------\n");
        printf("ARP: %d, ICMP: %d, IP: %d, UDP: %d, TCP: %d\n", arp_count, icmp_count, ip_count, udp_count, tcp_count);
        printf("-------------------------------------------\n");
        pthread_mutex_unlock(&count_mutex);
    }
    return NULL;
}

// Función para imprimir los dispositivos de red
void print_devices(pcap_if_t *alldevs) {
    pcap_if_t *device;
    int i = 0;
    for (device = alldevs; device; device = device->next) {
        printf("%d: %s\n", ++i, device->name);
    }
}
