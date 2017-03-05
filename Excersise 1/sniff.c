#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define NUM_OF_PACKETS 5


//returns device name
char *Find_Device(char* errB)
{
    char *dev;

    //Auto search for default device.
    dev = pcap_lookupdev(errB);
    if(dev == NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errB);
			return(2);
    }
    printf("Device found: %s\n",dev);

    return dev;
}

//Print content of packet
void show_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){


	//printf("packet length: %d\n", (*header).len);
	printf("Trying to print packet\n");
	//printf("PACKET: %x\n",packet[1]);

	// print full packet in Hexadecimal
	//header.caplen is length of the packet
	int i;
	for(i = 1; i <= (*header).caplen; i++){
		
		//0.2x to print in hexadecimal with 2 numbers each
		printf(" %.2x",packet[i - 1]);
		if((i % 16) == 0){
			printf("\n");
		}
	
	}
	printf("\nEND of PACKET\n\n\n");

}








//Remove all this to read live packets and save to file.
// Number of packets to read is written in #define.
int main()
{
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	int status;
	pcap_dumper_t *dumper;
/*this
	//I'm working with pcap 0.8 so i have to use pcap_open_live.
	handle = pcap_open_live(Find_Device(errbuf), BUFSIZ, 1, 1000, errbuf);
	
	if(handle == NULL){
		fprintf(stderr, "Couldn't open device: %s\n", errbuf);
		return(2);
	}

*/
	//Open file to write to.
/*this	dumper = pcap_dump_open(handle,"packets.pcap");
	if(dumper == NULL){
		printf("Error pcap_dump_open");
		return(2);
	}
*/
	
/*
	//Get one packet 
	packet = pcap_next(handle, &header);
	if(packet == NULL){
		fprintf(stderr, "Couldn't get packet or there where no packets to sniff: %s\n", errbuf);
		return(2);
	}

	printf("packet lenght:%d\n", header.len);
*/

/*this
	//Write to file until no more packets or NUM_OF_PACKETS exhausted 
	status = pcap_loop(handle, NUM_OF_PACKETS, pcap_dump, (char*) dumper);
	switch(status){
		case 0:
			printf("cnt is exhausted or no more packets available\n");
		break;
		
		case -1:
			printf("ERROR in pcap_loop\n");
		break;
		
		case -2:
			printf("pcap_breakloop was called\n");
		break;

	}


	// END session
	pcap_dump_close(dumper);
	pcap_close(handle);
*/	
	printf("START READING FROM FILE\n");

	//Read from file
	handle = pcap_open_offline("dnssample.pcap", errbuf);
	if(handle == NULL){
		fprintf(stderr, "Error when trying to read from file: %s\n", errbuf);
		return(2);
	}
	
	status = pcap_loop(handle, NUM_OF_PACKETS, show_packet, (char*) dumper);
	switch(status){
		case 0:
			printf("cnt is exhausted or no more packets available\n");
		break;
		
		case -1:
			printf("ERROR in pcap_loop\n");
		break;
		
		case -2:
			printf("pcap_breakloop was called\n");
		break;

	}

    return 0;
}
