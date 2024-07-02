#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>

// Variables globales para contar paquetes
int arp_count = 0, icmp_count = 0, ip_count = 0, udp_count = 0, tcp_count = 0;
pthread_mutex_t count_mutex;

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void *print_stats(void *arg);

int main(int argc, char *argv[]) {
    char *dev = NULL; // Nombre del dispositivo de captura
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Encontrar un dispositivo de captura si no se proporciona uno
    if (argc < 2) {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "No se pudo encontrar un dispositivo de captura: %s\n", errbuf);
            return 1;
        }
    } else {
        dev = argv[1];
    }

    // Abrir el dispositivo de captura
    handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "No se pudo abrir el dispositivo %s: %s\n", dev, errbuf);
        return 1;
    }

    // Inicializar el mutex
    pthread_mutex_init(&count_mutex, NULL);

    // Crear un hilo para mostrar las estadísticas en tiempo real
    pthread_t stats_thread;
    pthread_create(&stats_thread, NULL, print_stats, NULL);

    // Iniciar la captura de paquetes
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    pthread_mutex_destroy(&count_mutex);
    return 0;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    pthread_mutex_lock(&count_mutex);

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        arp_count++;
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        ip_count++;
        if (ip_header->ip_p == IPPROTO_ICMP) {
            icmp_count++;
        } else if (ip_header->ip_p == IPPROTO_TCP) {
            tcp_count++;
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            udp_count++;
        }
    }

    pthread_mutex_unlock(&count_mutex);
}

void *print_stats(void *arg) {
    while (1) {
        sleep(1);
        pthread_mutex_lock(&count_mutex);
        printf("ARP: %d, ICMP: %d, IP: %d, UDP: %d, TCP: %d\n", arp_count, icmp_count, ip_count, udp_count, tcp_count);
        pthread_mutex_unlock(&count_mutex);
    }
    return NULL;
}
