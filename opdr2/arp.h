#include <stdio.h>
#include <ctype.h>

class arp{

	static int ID;
	public:
	unsigned char hType[2],pType[2],sMac[6],sIP[4],dMac[6],dIP[4];
	int hwLen, prLen,oper;
		
	arp(){
		ID++;

	}

	//Decreaser ID if arp is not added to the table
	~arp(){
		ID--;
	{
	
	

};
