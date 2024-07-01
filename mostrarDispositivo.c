// Compile: gcc -o mostrarDispositivo mostrarDispositivo.c -lpcap

/*
struct pcap_if{           //Estructura de una interfaz
    struct pcap_if *next;
    char *name;             //interface name
    char *description;      //human-readable description of interface, or NULL
    struct pcap_addr *addresses;
    bpf_u_int32 flags;      //PCAP_IF_LOOPBACK if a loopback interface
};
*/

/*
struct pcap_addr{      //Estructura de una dirección
    struct pcap_addr *next;
    struct sockaddr *addr;          // interface address
    struct sockaddr *netmask;       // netmask for that address
    struct sockaddr *broadaddr;     // broadcast address
    struct sockaddr *dstaddr;       // point-to-point destination or NULL
};
*/

/*
Funcion usada para abrir una interfaz para capturar paquetes
pcap_t *pcap_open_live(const char *device,
                        int snaplen,
                        int promisc,
                        int to_ms,
                        char *errbuf)
*/

/*
La función pcap_datalink devuelve el tipo de capa de enlace subyacente desde el identificador pcap_t pasado.
int pcap_datalink(pcap_t *p)
Esta funcion generara un error si la interfaz de red no es Ethernet (10mb, 100mb, 1000mb, o mas..)
*/

/*
Usando libpcap, podemos generar un filtro BPF (Berkeley Packet Filter) para capturar solo los paquetes que nos interesan.
int pcap_compile(pcap_t *p,
                struct bpf_program *fp,
                char *str,
                int optimize,
                bpf_u_int32 netmask)
*/

/*
Una vez que se ha compilado el filtro, se puede aplicar a la interfaz con la función pcap_setfilter.
int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
*/


/*
Lee el siguiente paquete de sesion de caputra y retornando exito o fallo.
1 paquete fue leido con exito,
0  timeout vencido
-1 ha ocurrido un error
-2 paquetes son leidos desde un archivo guardado y no hay mas paquetes para leer.
Si el paquete fue leido, los punteros pkt_header y pkt_data son seteados a la cabecera del paquete y los datos del paquete respectivamente.
int pcap_next_ex (pcap_t *p,
                struct pcap_pkthdr **pkt_header,
                const u_char **pkt_data)
*/

/*
Lee un cnt de paquetes de la sesion de captura y llama a la funcion callback para cada paquete.
Retorna el numero de paquetes leidos o -1 si ha ocurrido un error.
int pcap_dispatch(pcap_t *p,
                    int cnt,
                    pcap_handler callback,
                    u_char *user)
*/

/*
Lee paquetes cnt de la sesion de captura. pcap_loop usa una funcion de callback para procesar paquetes, entra en un bucle infinito hasta que 
todos los paquetes son leidos o un error ocurre. Retorna los siguientes numeros:
0 paquetes cnt fueron leidos
-1 ha ocurrido un error
-2 el bucle termino usando pcap_breakloop
int pcap_loop(pcap_t *p,
                int cnt,
                pcap_handler callback,
                u_char *user)
*/

/*
Este es un contenedor para la función pcap_dispatch con un cnt de 1.
const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
pcap_next funcion no soporta mensajes de error, deberia ser usada pcap_next_ex en su lugar para capturar paquetes individuales.
*/



#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    pcap_if_t *alldevs; // Lista de dispositivos
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer de error
    char *device; // Dispositivo

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

    if (strlen (errbuf) > 0) {
        fprintf (stderr, "Warning: %s", errbuf);  /* a warning was generated */
        errbuf[0] = 0;    /* reset error buffer */
    }

    if (pcap_datalink (handle) != DLT_EN10MB) {
        fprintf (stderr, "This program only supports Ethernet cards!\n");
        exit (1);
    }

    int *dlt_buf;         /* array of supported data link types */
    int num;              /* number of supported link type */
    int i;                /* counter for for loop */

    num = pcap_list_datalinks(handle, &dlt_buf);

    // Imprime los tipos de capa de enlace soportados
    for (i=0; i<num; i++){
        printf("%d - %s - %s\n",dlt_buf[i],
        pcap_datalink_val_to_name(dlt_buf[i]),
        pcap_datalink_val_to_description(dlt_buf[i]));
    }

    /* Una vez que determinamos que el tipo de capa de enlace que estamos capturando es de tipo Ethernet,
       podemos asumir que la interfaz tiene una direccion IP y una mascara. */

    bpf_u_int32 netp;     /* ip address of interface */
    bpf_u_int32 maskp;    /* subnet mask of interface */

    if (pcap_lookupnet (device, &netp, &maskp, errbuf) == -1){
      fprintf (stderr, "%s", errbuf);
      exit (1);
    }

    /* Ahora podemos imprimir la dirección IP y la máscara de subred de la interfaz */

    char *net_addr;
    struct in_addr addr;
    addr.s_addr = netp;
    net_addr = inet_ntoa(addr);
    

    printf("IP address: %s\n", net_addr);
    printf("Subnet mask: %s\n", inet_ntoa(*(struct in_addr *)&maskp));

    char *filter = "arp";   /* filter for BPF (human readable) */
    struct bpf_program fp;  /* compiled BPF filter */
    
    // Compilar el filtro
    if (pcap_compile (handle, &fp, filter, 0, maskp) == -1){
      fprintf (stderr, "%s", pcap_geterr (handle));
      exit (1);
    }

    printf("Filter: %s\n", filter);

    // Aplicar el filtro
    if (pcap_setfilter (handle, &fp) == -1){
      fprintf (stderr, "%s", pcap_geterr (handle));
      exit (1);
    }

    

    // Liberar la memoria utilizada por el filtro
    pcap_freecode (&fp);

    // Cerrar la interfaz  
    pcap_close(handle);


    // Liberar la lista de dispositivos cuando ya no sea necesaria
    pcap_freealldevs(alldevs);

    return 0;
}