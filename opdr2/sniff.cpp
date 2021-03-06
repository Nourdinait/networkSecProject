/*
*Packet sniffer
*Advanced network security project assigment 1
*Nourdin Ait el Mehdi, 4276825
*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>

//returns device name
char *Find_Device(char* errB)
{
    char *dev;

    //Auto search for default device.
    dev = pcap_lookupdev(errB);
    if(dev == NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errB);
			return((char *) 2);
    }
    printf("Device found: %s\n",dev);

    return dev;
}


//Print content of packet
void show_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){


	//printf("packet length: %d\n", (*header).len);
	printf("Packet\n");

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

//Parse packet
 void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	u_char macDes[6], macSour[6], eType[2],ipHLength, udp[8], *dns,dName[255];
	int i, j,sPort, dPort,dnsLen, udpLen, udpBeg,udpEnd;
	unsigned int tID,flags, QR, opCode, AA, TC, RD, RA,SA,RCode,numQ,numAns,numAuth,numAdd,qType, qClass, TTL, rdLength;

	//Just random values
	udpBeg = 3000;
	udpEnd = 3000;
	
	printf("Parsing packet\n");
	for(i = 0; i < (*header).caplen; i++){
		
		if(i == 0){
		
			printf("macDes: ");

		}

		if(i < 6){

			macDes[i] = packet[i];
			
			printf("%.2x:",macDes[i]);
		}

		if(i == 6){

			printf("\nmacSour: ");
			
		}
	
		if((i >= 6) && (i < 12)){

			macSour[i - 6] = packet[i];

			printf("%.2x:",macSour[i - 6]);
		}

		if(i == 12){

			printf("\nethernet type: ");
			
		}

		if((i >= 12) && (i < 14)){

			eType[i - 12] = packet[i];

			printf("%.2x",eType[i - 12]);
		}


		//For ethernet type IP4 parse UDP and dns
		if(((etype[0] << 8) | etype[1]) == 0x0800){

			if(i == 14){


				// & to get only first part and *4 to get number of bytes.
				ipHLength = (packet[i] & 0b1111) * 4;
				//skip IP header
				i = i + ipHLength;
				udpBeg = i;
				udpEnd = i + 8;
				printf("\nIP header length: %d\n",ipHLength);
			
			
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
				printf("udp source port: %.4x\n",sPort);
				printf("udp destination port: %d\n",dPort);
				printf("udp data length: %d\n",udpLen);

				// intialize dns array
				dns = (u_char *) malloc(dnsLen);

			}		

			// 53 is DNS
			if((i >= udpEnd) && ((sPort == 53) || (dPort == 53))){
			
				dns[i - udpEnd] = packet[i];
			}
		}//End UDP parse and DNS put into  variable 

	}
	
	
	//Only parse if it is DNS
	if((sPort == 53) || (dPort == 53)){

		
		tID = (dns[0] << 8) | dns[1];
		printf("Transaction ID: 0x%.4x\n",tID);

		flags = tID = (dns[2] << 8) | dns[3];
		printf("Flags: 0x%.4x\n", flags);

		QR = (flags & 0x8000) >> 15 ;

		if(QR == 1){
		
			printf("QR: %d = Reponse\n",QR);

		}else if( QR == 0){
		
			printf("QR: %d = Query\n",QR);
		}else{
			printf("QR: %d = UNKNOWN\n",QR);

		}

		opCode = (flags & 0x7800) >> 11 ;

		if(opCode == 0){
	
			printf("Opcode: %d = Standard Query\n",opCode);
		}else if(opCode == 4){
			printf("Opcode: %d = Inverse\n",opCode);
		}else{
			printf("Opcode: %d = UNKNOWN\n",opCode);
		}

		
		AA = (flags & 0x0400) >> 10;

		if(AA == 0){

			printf("AA: %d = Non-authorative DNS answer\n",AA);
		}else if(AA == 1){

			printf("AA: %d = Authorative DNS answer\n",AA);
		}else{

			printf("AA: %d = UNKNOWN\n",AA);
		}
		
		TC = (flags & 0x0200) >> 9;

		if(TC == 0){

			printf("TC: %d = Message not truncated\n",TC);
		}else if(TC == 1){

			printf("TC: %d = Message truncated\n",TC);
		}else{

			printf("TC: %d = UNKNOWN\n",TC);
		}

		RD = (flags & 0x0100) >> 8;

		if(RD == 0){

			printf("RD: %d = Non-recursive query\n",RD);
		}else if(RD == 1){

			printf("RD: %d = Recursive query\n",RD);
		}else{

			printf("RD: %d = UNKNOWN\n",RD);
		}

		if(QR == 1){
			RA = (flags & 0x0080) >> 7;

			if(RA == 0){

				printf("RA: %d = Recursion not available\n",RA);
			}else if(RD == 1){

				printf("RA: %d = Recursion available\n",RA);
			}else{

				printf("RA: %d = UNKNOWN\n",RA);
			}

			SA = (flags & 0x0020) >> 5;

			if(SA == 0){

				printf("SA: %d = Answer/Authority portion was NOT authenticated by server\n",SA);
			}else if(SA == 1){

				printf("SA: %d = Answer/Authority portion was  authenticated by server\n",SA);
			}else{

				printf("SA: %d = UNKNOWN\n",SA);
			}
		
			RCode = (flags & 0x000F);

			if(RCode == 0){

				printf("RCode: %d = No error\n",RCode);
			}else if(RCode == 4){

				printf("RCode: %d = Format error in query\n",RCode);
			}else if(RCode == 2){
		
				printf("RCode: %d = Server failure\n",RCode);
			}else if(RCode == 1){
				printf("RCode: %d = Name does not exist\n", RCode);
		
			}else{

				printf("RCode: %d = UNKNOWN\n",RCode);
			}
		}

		//parsing numQ,numAns,numAuth,numAdd

		numQ = (dns[4] << 8) | dns[5];
		numAns = (dns[6] << 8) | dns[7];
		numAuth = (dns[8] << 8) | dns[9];
		numAdd = (dns[10] << 8) | dns[11];
		
		printf("Questions: %d\n",numQ);
		printf("Answer RR's: %d\n",numAns);
		printf("Authority RR's: %d\n",numAuth);
		printf("Additional RR's: %d\n",numAdd);

		
		printf("...Queries...\n\nQueryName: ");
		//start of Qname data
		j = 13;

		for(i = 0; i < numQ + numAns + numAuth + numAdd; i++){

			
			
			while((dns[j] != 0) && (dns[j] != 0xc0)){
				
				if(!isalpha(dns[j])){
					printf(".");
					dName[j - 13] = '.';
				}else{

					printf("%c",dns[j]);
					dName[j-13] = dns[j];
				} 

				j++;
			}			
			
			printf("\n");

			if(dns[j] == 0xc0){
				printf("%s\n",dName);
				j++;
			}
			
			qType = (dns[j + 1] << 8) | dns[j + 2];
			switch(qType){

				case(1): printf("Type: A\n");
					break;

				case(2): printf("Type: NS\n");
					break;

				case(5): printf("Type: CNAME\n");
					break;

				case(6): printf("Type: SOA\n");
					break;

				case(12): printf("Type: PTR\n");
					break;

				case(15): printf("Type: MX\n");
					break;

				case(16): printf("Type: TXT\n");
					break;

				default: printf("Type: UNKNOWN\n");
			}

			qClass = (dns[j + 3] << 8) | dns[j + 4];

			if(qClass == 0x0001){

				printf("Class: IN\n");
			}

			//Here the querries stop 
			if(i < numQ){

				j = j + 5;
				
				if(numAns != 0){

				printf("...Answers...\n");
				}
				continue;

			}
			
			TTL =  (dns[j + 5] << 24) | (dns[j + 6] << 16) | (dns[j + 7] << 8) | dns[j + 8];
			printf("TTL: %d\n",TTL);
			
			rdLength = (dns[j + 9] << 8) | dns[j + 10];

			printf("Data length: %d\n",rdLength);
						
			j = j + rdLength + 11;

			if((i < numQ + numAns + numAuth) && (numAuth != 0)){
			
				printf("...Autoritative nameservers...\n\n");
			}

			if((i < numQ + numAns + numAuth + numAdd) && (numAdd != 0)){
			
				printf("...Additional records...\n\n");
			}


		}
						
	}

	
	free(dns);
	printf("\n\n");


}

int main()
{
	
	char errbuf[PCAP_ERRBUF_SIZE],file;
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	int status, chose;
	pcap_dumper_t *dumper;

	while(1){
		printf("Welcome choose one of the following options\n");
		printf("1). Sniff live and print\n");
		printf("2). Sniff live and write to packets.pcap\n");
		printf("3). Sniff from file\n");
		printf("4). Exit\n");
		scanf("%d",&chose);
		printf("chose: %d\n",chose);
		
		switch(chose){
			case 1 :
				printf("How many packets to sniff?\n");
				scanf("%d",&chose);

				//I'm working with pcap 0.8 so i have to use pcap_open_live.
				handle = pcap_open_live(Find_Device(errbuf), BUFSIZ, 1, 1000, errbuf);
	
				if(handle == NULL){
					fprintf(stderr, "Couldn't open device: %s\n", errbuf);
					return(2);
				}

				status = pcap_loop(handle, chose, parse_packet, NULL);
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

				chose = 4;
				pcap_close(handle);
				break;

			case 2 : printf("How many packets to sniff?\n");
				scanf("%d",&chose);
				//I'm working with pcap 0.8 so i have to use pcap_open_live.
				handle = pcap_open_live(Find_Device(errbuf), BUFSIZ, 1, 1000, errbuf);
	
				if(handle == NULL){
					fprintf(stderr, "Couldn't open device: %s\n", errbuf);
					return(2);
				}


				//Open file to write to.
				dumper = pcap_dump_open(handle,"packets.pcap");
				if(dumper == NULL){
					printf("Error pcap_dump_open");
					return(2);
				}

				printf("Sniffing\n");

				//Write to file until no more packets or NUM_OF_PACKETS exhausted 
				status = pcap_loop(handle, chose, pcap_dump, (u_char *) dumper);
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

				printf("Packets written to packets.pcap\n");
				pcap_dump_close(dumper);
				pcap_close(handle);

				chose = 4;
				break;

			case 3 :
				printf("Enter file name followed by .pcap\n");
				scanf("%s",&file);
				printf("START READING FROM FILE\n");

				//Read from file
				handle = pcap_open_offline(&file, errbuf);
				if(handle == NULL){
					fprintf(stderr, "Error when trying to read from file: %s\n", errbuf);
					return(2);
				}
	
				status = pcap_loop(handle, 0, parse_packet, (u_char*) dumper);
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
				pcap_close(handle);
				chose = 4;
				break;
			case 4 : 
				break;
			default: printf("Wrong input, try again\n");
				

		}

		if(chose == 4){
			printf("Goodbye\n");
			break;
		}

	}

    return 0;
}
