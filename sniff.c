#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define NUM_OF_PACKETS 6


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
	printf("PACKET: %d\n",packet[11]);

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


 void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	u_char macDes[6], macSour[6], eType[2],ipHLength, udp[8], *dns;
	int i,sPort, dPort,dnsLen, udpLen, udpBeg,udpEnd;

	udpBeg = 3000;
	udpEnd = 3000;
		printf("headerLenght: %d\n", (*header).caplen);
	for(i = 0; i < (*header).caplen; i++){
		
		if(i == 0){
		
			printf("macDes: ");

		}

		if(i < 6){

			macDes[i] = packet[i];
			
			printf("%.2x:",macDes[i]);
		}

		if(i == 6){

			printf("\n macSour: ");
			
		}
	
		if((i >= 6) && (i < 12)){

			macSour[i - 6] = packet[i];

			printf("%.2x:",macSour[i - 6]);
		}

		if(i == 12){

			printf("\n ethernet type: ");
			
		}

		if((i >= 12) && (i < 14)){

			eType[i - 12] = packet[i];

			printf("%.2x",eType[i - 12]);
		}

		if(i == 14){

			// & to get only first part and *4 to get number of bytes.
			ipHLength = (packet[i] & 0b1111) * 4;
			//skip IP header
			i = i + ipHLength;
			udpBeg = i;
			udpEnd = i + 8;
			printf("\nIP header length: %d, %d\n",ipHLength, i);
			
			
		}

		//udpbeg because ip can be bigger then 20 byts
		// + 8 because udp is 8 byts
		if((i >= (udpBeg)) && (i < udpEnd)){

			udp[i-udpBeg]  = packet[i];

		}

		if( i == (udpEnd)){

			sPort = (udp[0] << 8) | udp[1];
			dPort = (udp[2] << 8) | udp[3];
			udpLen = (udp[4] << 8) | udp[5];
			dnsLen = (udp[4] << 8) | udp[5] - 8;
			printf("upd source port: %d\n",sPort);
			printf("upd destination port: %d\n",dPort);
			printf("upd data length: %d\n",udpLen);

			// intialize dns array
			dns = (u_char *) malloc(dnsLen);

		}		

		// udp stopt here 
		// 53 is DNS ADD CHECK FOR DNS
		if((i >= udpEnd) && ((sPort == 53) || (dPort == 53))){
			
			dns[i - udpEnd] = packet[i];
		}

		if( i == (*header).caplen - 1){

			printf("dns first part: %.2x\n", dns[0]);
		}

		

	}
	
	unsigned int tID,flags, QR;

	if((sPort == 53) || (dPort == 53)){

		printf("DNS PARSE\n");
		for(i = 0; i < dnsLen; i++){
	
			if(i == 0){

				tID = (dns[0] << 8) | dns[1];
				printf("Transaction ID: 0x%.4x\n",tID);

				flags = tID = (dns[2] << 8) | dns[3];
				printf("Flags: 0x%.4x\n", flags);

				QR = (flags & 0x80) >> 7 ;

				if(QR == 1){
				
					printf("QR: 0x%.4x = Reponse",QR);

				}else{
				
					printf("QR: 0x%.4x = Query",QR);
				}

				
			}			

		}

		
	
	}

	
	free(dns);
	printf("\n\n");


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
	
	status = pcap_loop(handle, NUM_OF_PACKETS, parse_packet, (char*) dumper);
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
