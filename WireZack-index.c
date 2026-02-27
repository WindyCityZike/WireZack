#include <sys/types.h> // for pcap_if_t
#include <stdio.h> // for printf
#include <stdlib.h> // for exit
#include <pcap.h>  // for pcap functions
#include <errno.h> // for errno
#include <sys/socket.h> // for socket
#include <netinet/ip.h> // for IP header
#include <netinet/in.h> // for IPPROTO_TCP, IPPROTO_UDP, etc.
#include <arpa/inet.h> // for inet_ntoa
#include <string.h> // for strcpy
#include <time.h> // for ctime

// Global variables
pcap_if_t *alldevs = NULL, *device = NULL;
// IP struct to hold the IP header data
struct ip
{
    unsigned char ip_hl:4, ip_v:4; // header length and version
    unsigned short ip_len;         // total length
    unsigned char ip_ttl;          // time to live
    unsigned char ip_p;            // protocol
    struct in_addr ip_src, ip_dst; // source and destination address
} iphdr;
char errbuf[PCAP_ERRBUF_SIZE];
#define ETHERNET_HEADER_SIZE 14

// Function declarations
void IntroductionArt();
void PresentMenu();
pcap_if_t *SelectNetworkInterface();
void SniffNetworkPackets();
void callBackFunction(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

int main(int argc, char *argv[])
{
    IntroductionArt();
    // introduction
    printf("\n\nWelcome to WireZack!\n\nScan your network and sniff packets.\n\n");
    printf("If you wish to do a live capture, you must select a Network Interface...\n\n");
    printf("\n\n\n#################################################\n");

    // Get all network devices once at startup
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    device = SelectNetworkInterface();
    // if no device is selected, exit the program
    if (device == NULL) {
        printf("Failed to select a network interface. Exiting...\n");
        pcap_freealldevs(alldevs);
        return 0;
    }
    // else, present the menu again.
    while (1) {
        PresentMenu();
    }

    return 0;
}

void IntroductionArt() {
    // ASCII art for the introduction
    printf(
        " __          ___          ______          _    \n"
        " \\ \\        / (_)        |___  /         | |   \n"
        "  \\ \\  /\\  / / _ _ __ ___   / / __ _  ___| | __\n"
        "   \\ \\/  \\/ / | | '__/ _ \\ / / / _` |/ __| |/ /\n"
        "    \\  /\\  /  | | | |  __// /_| (_| | (__|   < \n"
        "     \\/  \\/   |_|_|  \\___/_____\\__,_|\\___|_|\\_\\\n"
        "                                               \n"
        "                                               \n");                          
    printf("\n\n\n#################################################");
    printf("NETWORK INTERFACE SCANNER\n");
    printf("#################################################\n");
}

// Function to display the menu and handle user interaction
void PresentMenu()
{
    printf("\n\n1. Scan Network Interfaces\n");
    printf("2. Sniff Network Packets\n");
    printf("3. Exit\n");
    printf("Select an option: ");

    int selection = getchar();
    while (getchar() != '\n'); // clear input buffer

    printf("\n\n");
// switch function to handle user input
    switch (selection) {
    case '1':
        printf("You selected to select a network interface...\n\n");
        device = SelectNetworkInterface();
        break;
    case '2':
        printf("You selected Sniff Network Packets.\n");
        SniffNetworkPackets();
        break;
    case '3':
        printf("Exiting...\n");
        pcap_freealldevs(alldevs);
        exit(0);
        break;
    default:
        printf("Invalid option.\n");
        break;
    }
}

pcap_if_t *SelectNetworkInterface()
{
    pcap_if_t *d;
    int i = 0, selection;

    printf("\n\n\n\nPrimary network interfaces:\n\n");
// prints the network interfaces on the device.
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }

    if (i == 0) {
        printf("No interfaces found. Run with sudo?\n");
        return NULL;
    }
// prompts the user to select a network interface
    printf("Select an interface (1-%d): ", i);
    // user input
    scanf("%d", &selection);
    while (getchar() != '\n'); // clear input buffer
    // user input validation
    if (selection < 1 || selection > i) {
        printf("Invalid selection.\n");
        return NULL;
    }

    d = alldevs;
    for (int j = 1; j < selection; j++) {
        d = d->next;
    }
    // d->name is the name of the selected device
    printf("Selected device: %s\n", d->name);
    return d;
}

// Function to sniff network packets
void SniffNetworkPackets()
{
    // Checks if a device is selected
    if (device == NULL || device->name == NULL) {
        printf("No valid device selected. Cannot sniff.\n");
        return;
    }

    printf("\n\n\n##################################################\n");
    printf("Sniffing Network Packets from %s...\n", device->name);
    printf("Press '0' and Enter to stop sniffing.\n");
    printf("##################################################\n");
    // 65535 is the maximum packet size, 1 is for promiscuous mode, 1000 is the timeout in milliseconds
    pcap_t *handle = pcap_open_live(device->name, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening device %s: %s\n", device->name, errbuf);
        return;
    }
    // Prints the table for the sniffed packets
    printf("\n%-24s | %-15s | %-15s | %-8s | %-6s\n", 
           "Time", "Source", "Destination", "Protocol", "Length");
    printf("-------------------------------------------------------------------------------\n");

    // Continuously capture packets until '0' is pressed
    int stop_sniffing = 0;
    while (!stop_sniffing) {
        // Capture packets (process up to 10 packets at a time)
        pcap_dispatch(handle, 10, callBackFunction, NULL);

        // Check if the user pressed '0'
        printf("Press '0' and Enter to stop sniffing, or press Enter to continue: \n");
        char input[2];
        fgets(input, sizeof(input), stdin);
        if (input[0] == '0') {
            stop_sniffing = 1;
        }
    }
    // closes the pcap handle
    pcap_close(handle);

    printf("##################################################\n");
    printf("Sniffing finished.\n");
}


void callBackFunction(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    char timebuf[64];
    time_t local_time = header->ts.tv_sec;

    // Skip the Ethernet header
    const struct ip *iphdr = (const struct ip *)(packet + ETHERNET_HEADER_SIZE);

    // Convert the IP addresses to string format
    const char *source_ip = inet_ntoa(iphdr->ip_src);
    const char *dest_ip = inet_ntoa(iphdr->ip_dst);

    // Determine the protocol name or number, if unknown it displays the protocol number
    char protocol_name[16];
    switch (iphdr->ip_p) {
        // Check the protocol number and assign a name
        // IPPROTO_TCP = 6, IPPROTO_UDP = 17, IPPROTO_ICMP = 1, IPPROTO_IGMP = 2
        // IPPROTO_IP = 0, IPPROTO_IPV6 = 41, IPPROTO_GRE = 47, IPPROTO_ESP = 50, IPPROTO_AH = 51
        case IPPROTO_TCP:
            strcpy(protocol_name, "TCP");
            break;
        case IPPROTO_UDP:
            strcpy(protocol_name, "UDP");
            break;
        case IPPROTO_ICMP:
            strcpy(protocol_name, "ICMP");
            break;
        case IPPROTO_IGMP:
            strcpy(protocol_name, "IGMP");
            break;
        case IPPROTO_IP:
            strcpy(protocol_name, "IP");
            break;
        case IPPROTO_IPV6:
            strcpy(protocol_name, "IPv6");
            break;
        case IPPROTO_GRE:
            strcpy(protocol_name, "GRE");
            break;
        case IPPROTO_ESP:
            strcpy(protocol_name, "ESP");
            break;
        case IPPROTO_AH:
            strcpy(protocol_name, "AH");
            break;
        default:
            snprintf(protocol_name, sizeof(protocol_name), "%d", iphdr->ip_p); // Use protocol number
            break;
    }

    // Format the timestamp and remove the newline character
    strncpy(timebuf, ctime((const time_t *)&header->ts.tv_sec), sizeof(timebuf));
    timebuf[strcspn(timebuf, "\n")] = '\0'; // Remove the newline character

    // Print the packet details
    printf("%-24s | %-15s | %-15s | %-8s | %-6d\n",
           timebuf, source_ip, dest_ip, protocol_name, ntohs(iphdr->ip_len));

}
