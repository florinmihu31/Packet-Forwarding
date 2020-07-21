#include "skel.h"
#define DEFAULT_TTL 32

int interfaces[ROUTER_NUM_INTERFACES]; // Interfetele routerului

struct rtable_entry *rtable; // Tabela de rutare
int rtable_size; // Lungimea tabelei de rutare

struct arp_entry *arp_table; // Tabela ARP
int arp_table_len; // Lungime atabelei ARP

// Functie ce face suma de control pentru headerele IP
uint16_t ip_checksum(void* vdata, size_t length) {
	char* data = (char*)vdata;

	uint64_t acc = 0xffff;

	unsigned int offset = ((uintptr_t)data)&3;

	if (offset) {
		size_t count = 4 - offset;
		if (count>length) count = length;
		uint32_t word = 0;
		memcpy(offset + (char*)&word, data, count);
		acc += ntohl(word);
		data += count;
		length -= count;
	}

	char* data_end = data + (length&~3);

	while (data != data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc += ntohl(word);
		data += 4;
	}

	length &= 3;

	if (length) {
		uint32_t word = 0;
		memcpy(&word, data, length);
		acc += ntohl(word);
	}

	acc = (acc & 0xffffffff) + (acc >> 32);
	while (acc >> 16) {
		acc=(acc & 0xffff) + (acc >> 16);
	}

	if (offset & 1) {
		acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
	}

	return htons(~acc);
}

// Functie ce face suma de control pentru headerele ICMP
uint16_t checksum(void * vdata, size_t length) {
	char* data = (char*)vdata;

	uint64_t acc = 0xffff;

	unsigned int offset = ((uintptr_t)data) & 3;

	if (offset) {
		size_t count = 4 - offset;
		if (count > length) count = length;
		uint32_t word = 0;
		memcpy(offset + (char*)&word, data, count);
		acc += ntohl(word);
		data += count;
		length -= count;
	}

	char* data_end = data + (length&~3);

	while (data != data_end) {
		uint32_t word;
		memcpy(&word, data, 4);
		acc += ntohl(word);
		data += 4;
	}

	length &= 3;

	if (length) {
		uint32_t word = 0;
		memcpy(&word, data, length);
		acc += ntohl(word);
	}

	acc = (acc & 0xffffffff) + (acc >> 32);

	while (acc >> 16) {
		acc = (acc & 0xffff) + (acc >> 16);
	}

	if (offset & 1) {
		acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
	}

	return htons(~acc);
}

/*
 *  Functie de comparatie folosita de qsort.
 * 	Aceasta sorteaza intrarile din tabela de rutare dupa prefix, iar daca 
 * 	prefixele sunt egale, acestea vor fi ordonate dupa masca.
 */ 
int comparator(const void *entry1, const void *entry2) {
	uint32_t prefix1 = ((struct rtable_entry *) entry1)->prefix;
	uint32_t prefix2 = ((struct rtable_entry *) entry2)->prefix;

	if (prefix1 > prefix2) {
		return 1;
	} else if (prefix1 < prefix2) {
		return -1;
	}

	uint32_t mask1 = ((struct rtable_entry *) entry1)->mask;
	uint32_t mask2 = ((struct rtable_entry *) entry2)->mask;

	if (mask1 > mask2) {
		return 1;
	} else if (mask1 < mask2) {
		return -1;
	}

	return 0;
}

// Functie de cautare binara ce cauta un anumit IP in tabela de rutare
int binary_search(struct rtable_entry *rtable, __u32 dest_ip, 
					int left, int right) {

	if (left > right) {
		return -1;
	}

	int mid = (left + right) / 2;

	if ((dest_ip & rtable[mid].mask) == rtable[mid].prefix) {
		return mid;
	} else if ((dest_ip & rtable[mid].mask) < rtable[mid].prefix) {
		return binary_search(rtable, dest_ip, left, mid - 1);
	}

	return binary_search(rtable, dest_ip, mid + 1, right);
}

// Functie ce intoarce cea mai buna ruta pentru un IP, dat ca parametru
struct rtable_entry *get_route(__u32 dest_ip) {
	int index = binary_search(rtable, dest_ip, 0, rtable_size - 1);
	int current_index = index;

	// Se avanseaza pana la indexul ce are intrarea cu masca cea mai mare
	while (rtable[index].prefix == rtable[index + 1].prefix) {
		if ((dest_ip & rtable[index + 1].mask) == rtable[index + 1].prefix) {
			current_index = index + 1;
		}
		index++;
	}

	// Daca nu se gaseste o ruta, functia intoarce NULL
	if (index == -1) {
		return NULL;
	}

	return &rtable[current_index];
}

/*
 *  Functie ce intoarce intrarea din tabela ARP, in functie de IP-ul dat ca 
 * 	parametru
 */
struct arp_entry *get_arp_entry(__u32 ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}

    return NULL;
}

// Functie de parsare a tabelei ARP
void parse_arp_table() {
	FILE *f = fopen("arp_table.txt", "r");

	if (f == NULL) {
		fprintf(stderr, "Eroare la deschiderea fisierului");
	}

	char line[100];
	int i = 0;
	
	for (i = 0; fgets(line, sizeof(line), f); i++) {
		char ip_str[50], mac_str[50];
		
		sscanf(line, "%s %s", ip_str, mac_str);
		fprintf(stderr, "IP: %s MAC: %s\n", ip_str, mac_str);
		
		arp_table[i].ip = inet_addr(ip_str);
		int rc = hwaddr_aton(mac_str, arp_table[i].mac);
		
		if (rc < 0) {
			fprintf(stderr, "Adresa MAC invalida");
		}
	}

	arp_table_len = i;

	fclose(f);
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	rtable = malloc(sizeof(struct rtable_entry) * 100);

	setvbuf(stdout, NULL, _IONBF, 0);
	init();

	FILE *file = fopen("rtable.txt", "r");
	char delimiter[] = " ";
	char line[200];
	int current_element = 0;
	int current_entry = 0;
	int table_size = 100;

	// Citirea linie cu linie din fisier
	while (fgets(line, sizeof(line), file)) {
		/*
		 *	Daca tabela de rutare a ramas fara spatiu suficient, se realoca 
		 * 	memorie
		 */
		if (current_entry == table_size) {
			table_size += 100;
			rtable = realloc(rtable, sizeof(struct rtable_entry) * table_size);
		}
		
		// Despartirea liniei in functie de spatiu
		char *word = strtok(line, delimiter);

		while (word) {
			switch (current_element) {
				// Punerea in intrarea din tabela a prefixului
				case 0:
					inet_pton(AF_INET, word, &rtable[current_entry].prefix);
					current_element++;
					break;
				
				// Punerea in intrarea din tabela a next-hop-ului
				case 1:
					inet_pton(AF_INET, word, &rtable[current_entry].next_hop);
					current_element++;
					break;

				// Punerea in intrarea din tabela a mastii
				case 2:
					inet_pton(AF_INET, word, &rtable[current_entry].mask);
					current_element++;
					break;

				// Punerea in intrarea din tabela a interfetei
				case 3:
					rtable[current_entry].interface = atoi(word);
					current_element = 0;
					break;
			}
			word = strtok(NULL, delimiter);
		}

		current_entry++;
	}

	// Actualizarea marimii tabelei de rutare
	rtable_size = current_entry;

	// Sortarea tabelei de rutare in functie de comparator
	qsort(rtable, rtable_size, sizeof(struct rtable_entry), comparator);

	// Alocarea spatiului pentru tabela ARP si parsarea acesteia
	arp_table = malloc(sizeof(struct arp_entry) * 100);
	parse_arp_table();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		/* Students will write code here */
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct 
								ether_header));
		struct icmphdr *icmp_hdr = (struct icmphdr *) (m.payload + sizeof
								(struct ether_header) + sizeof(struct iphdr));

		// Verificarea checksum-ului headerului IP
		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
			fprintf(stderr, "Eroare la checksum\n");
			continue;
		}

		/*
		 * Daca ttl <= 1 se trimite un nou pachet de tip ICMP_TIME_EXCEEDED 
		 * catre adresa de la care a venit
		 */
		if (ip_hdr->ttl <= 1) {
			fprintf(stderr, "Eroare la ttl\n");

			packet pack;
			
			// Initializarea lungimii si a interfetei
			memset(pack.payload, 0, sizeof(pack.payload));
			pack.len = sizeof(struct ether_header) + sizeof(struct iphdr) + 
					sizeof(struct icmphdr);
			pack.interface = m.interface;

			struct ether_header *eth_header 
										= (struct ether_header *) pack.payload;
			struct iphdr *ip_header = (struct iphdr *) (pack.payload + sizeof
									(struct ether_header));
			struct icmphdr *icmp_header = (struct icmphdr *) (pack.payload + 
							sizeof(struct ether_header) + sizeof(struct iphdr));

			// Interschimbarea adresei sursa si destinatie
			ip_header->daddr = ip_hdr->saddr;
			ip_header->saddr = ip_hdr->daddr;
			ip_header->ttl = DEFAULT_TTL;
			ip_header->id = ip_hdr->id;
			ip_header->ihl = 5;
			ip_header->version = 4;
			ip_header->tos = 0;
			ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
			ip_header->frag_off = htons(0);
			ip_header->protocol = IPPROTO_ICMP;
			// Verificarea checksum-ului headerului IP
			ip_header->check = 0;
			ip_header->check = checksum(ip_header, sizeof(struct iphdr));

			// Interschimbarea adresei sursa si destinatie
			memcpy(eth_header->ether_dhost, eth_hdr->ether_shost, sizeof
					(eth_hdr->ether_shost));
			memcpy(eth_header->ether_shost, eth_hdr->ether_dhost, sizeof
					(eth_hdr->ether_dhost));
			eth_header->ether_type = htons(ETHERTYPE_IP);

			// Setarea tipului ICMP_TIME_EXCEEDED
			icmp_header->type = ICMP_TIME_EXCEEDED;
			icmp_header->code = 0;
			icmp_header->un.echo.id = htons(icmp_hdr->un.echo.id);
			// Verificarea checksum-ului headerului ICMP
			icmp_header->checksum = 0;
			icmp_header->checksum = checksum(icmp_header, sizeof(struct icmphdr));

			// Trimiterea pachetului
			send_packet(pack.interface, &pack);

			continue;
		}

		// Cautarea rutei cele mai bune
		struct rtable_entry *route = get_route(ip_hdr->daddr);

		/*
		 * Daca nu se gaseste o ruta se trimite un nou pachet de tip 
		 * ICMP_DEST_UNREACH catre adresa de la care a venit
		 */
		if (route == NULL) {
			fprintf(stderr, "Eroare la gasirea rutei\n");

			packet pack;
			
			// Initializarea lungimii si a interfetei
			memset(pack.payload, 0, sizeof(pack.payload));
			pack.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
			pack.interface = m.interface;

			struct ether_header *eth_header = (struct ether_header *) pack.payload;
			struct iphdr *ip_header = (struct iphdr *) (pack.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_header = (struct icmphdr *) (pack.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

			// Interschimbarea adresei sursa si destinatie
			ip_header->daddr = ip_hdr->saddr;
			ip_header->saddr = ip_hdr->daddr;
			ip_header->ttl = DEFAULT_TTL;
			ip_header->id = ip_hdr->id;
			ip_header->ihl = 5;
			ip_header->version = 4;
			ip_header->tos = 0;
			ip_header->tot_len = htons(sizeof(struct iphdr) 
								+ sizeof(struct icmphdr));
			ip_header->frag_off = htons(0);
			ip_header->protocol = IPPROTO_ICMP;
			// Verificarea checksum-ului headerului IP
			ip_header->check = 0;
			ip_header->check = checksum(ip_header, sizeof(struct iphdr));

			// Interschimbarea adresei sursa si destinatie
			memcpy(eth_header->ether_dhost, eth_hdr->ether_shost, sizeof
					(eth_hdr->ether_shost));
			memcpy(eth_header->ether_shost, eth_hdr->ether_dhost, sizeof
					(eth_hdr->ether_dhost));
			eth_header->ether_type = htons(ETHERTYPE_IP);

			// Setarea tipului ICMP_DEST_UNREACH
			icmp_header->type = ICMP_DEST_UNREACH;
			icmp_header->code = 0;
			icmp_header->un.echo.id = htons(icmp_hdr->un.echo.id);
			// Verificarea checksum-ului headerului ICMP
			icmp_header->checksum = 0;
			icmp_header->checksum = checksum(icmp_header, sizeof(struct icmphdr));

			// Trimiterea pachetului
			send_packet(pack.interface, &pack);

			continue;
		}

		/*
		 *	Variabila in care retinem daca trebuie trimis un pachet de tip 
		 *	ICMP_ECHOREPLY
		 */
		int is_reply = 0;

		for (int i = 0; i < ROUTER_NUM_INTERFACES && is_reply == 0; i++) {
			uint32_t current_ip;
			inet_pton(AF_INET, get_interface_ip(i), &current_ip);

			/*
		 	 * Daca nu este o interfata a routerului se trimite un nou pachet 
			 * de tip ICMP_ECHOREPLY catre adresa de la care a venit
		 	 */
			if (current_ip == ip_hdr->daddr) {
				packet pack;
				
				// Initializarea lungimii si a interfetei
				memset(pack.payload, 0, sizeof(pack.payload));
				pack.len = sizeof(struct ether_header) + sizeof(struct iphdr) + 
						sizeof(struct icmphdr);
				pack.interface = m.interface;

				struct ether_header *eth_header = 
										(struct ether_header *) pack.payload;
				struct iphdr *ip_header = (struct iphdr *) (pack.payload 
									+ sizeof(struct ether_header));
				struct icmphdr *icmp_header = (struct icmphdr *) (pack.payload 
						+ sizeof(struct ether_header) + sizeof(struct iphdr));

				// Interschimbarea adresei sursa si destinatie
				ip_header->daddr = ip_hdr->saddr;
				ip_header->saddr = ip_hdr->daddr;
				ip_header->ttl = DEFAULT_TTL;
				ip_header->id = ip_hdr->id;
				ip_header->ihl = 5;
				ip_header->version = 4;
				ip_header->tos = 0;
				ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_header->frag_off = htons(0);
				ip_header->protocol = IPPROTO_ICMP;
				// Verificarea checksum-ului headerului IP
				ip_header->check = 0;
				ip_header->check = checksum(ip_header, sizeof(struct iphdr));

				// Interschimbarea adresei sursa si destinatie
				memcpy(eth_header->ether_dhost, eth_hdr->ether_shost, sizeof
						(eth_hdr->ether_shost));
				memcpy(eth_header->ether_shost, eth_hdr->ether_dhost, sizeof
						(eth_hdr->ether_dhost));
				eth_header->ether_type = htons(ETHERTYPE_IP);

				// Setarea tipului ICMP_ECHOREPLY
				icmp_header->type = ICMP_ECHOREPLY;
				icmp_header->code = 0;
				icmp_header->un.echo.id = htons(icmp_hdr->un.echo.id);
				// Verificarea checksum-ului headerului ICMP
				icmp_header->checksum = 0;
				icmp_header->checksum = checksum(icmp_header, 
									sizeof(struct icmphdr));

				// Trimiterea pachetului
				send_packet(pack.interface, &pack);

				// Salvam faptul ca am trimit un pachet de tip ICMP_ECHOREPLY
				is_reply = 1;
			}
		}

		// Verficam daca am trimis un pachet de tip ICMP_ECHOREPLY
		if (is_reply) {
			continue;
		}

		// Decrementarea ttl-ului
		ip_hdr->ttl--;
		// Verificarea sumei de control
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

		// Cautarea adresei MAC potrivite
		struct arp_entry *mac_addr = get_arp_entry(ip_hdr->daddr);

		// Verificam daca s-a gasit o adresa MAC
		if (mac_addr == NULL) {
			fprintf(stderr, "Eroare la gasirea adresei MAC");
			continue;
		}

		// Punerea in ether_hdr a adresei MAC gasite
		memcpy(eth_hdr->ether_dhost, mac_addr->mac, sizeof(mac_addr->mac));

		// Trimiterea pachetului
		send_packet(route->interface, &m);
	}
}
