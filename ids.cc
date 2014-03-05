#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>
#include <vector>

using namespace std; 

/*
 * Current processing packet
 */
int CURRENT_PACKET;
// for processing payload
int payload_left = 0;

/*
 * Header type
 */
#define ERR -1
#define TIME 0
#define IPADDR 1
#define PACKET_IP 2
#define PACKET_ARP 3
#define HEXXXD 4

/*
 * IP type
 */

#define IPV4 1
#define IPV6 2

/*
 * ARP packet type
 */

#define REQUEST 1
#define REPLY 2

struct ARP_PACKET {
  string interface; // eth0, ethernet, etc
  int interface_len;
  int ip_type; // ipv4 / ipv6
  int ip_len; // ipv4/ipv6 segment length
  int packet_type; // request / reply
  string from_ip; // IP addr from
  string action; // tell / is-at
  string to_ip; // IP address
  int payload_size; // payload size
  string payload; // hex decimal payloads 
};
vector<ARP_PACKET> arp_packet_list;// store captured ARP packets

int check_token(string token){
  if(token.find("0x") != string::npos && token.size() == 7) return HEXXXD;

  int count1 = std::count(token.begin(), token.end(), '.');
  if(count1 == 4) return IPADDR;
  
  if(count1 == 1){
    int count2 = std::count(token.begin(), token.end(), ':');
    if(count2 == 2) return TIME;
    else return ERR;
  }

  if(token.compare("IP") == 0) return PACKET_IP;
  if(token.compare("ARP,") == 0) return PACKET_ARP;
}

int main(){
  string line;
  while(getline(cin, line)){
    struct ARP_PACKET arp_pk;
    
    stringstream ss;
    ss << line;
    string first_token, second_token;
    ss >> first_token;

    if(check_token(first_token) == HEXXXD){
      // proceed payload
      string token;

      if(CURRENT_PACKET == PACKET_ARP){
	//	arp_pk.payload += token;
	while(!ss.eof()){
	  ss >> token;
	  arp_pk.payload += token;
	}
	ss.clear();

	payload_left--;
	if(payload_left == 0){
	  // reset stuff for processing next packet
	  CURRENT_PACKET = 0;
	  arp_packet_list.push_back(arp_pk);
	}
      }
      else if(CURRENT_PACKET == PACKET_IP){

      }

      continue;
    }

    ss >> second_token;
    if(check_token(second_token) == PACKET_IP){
      /*
       * handle IP packet
       */

      
    }
    else if(check_token(second_token) == PACKET_ARP){
      /* 
       * handle ARP packet
       */
      cout<<"PACKET TYPE = ARP"<<endl;
      CURRENT_PACKET = PACKET_ARP;

      stringstream temp_ss; // for converting purposes

      string token;
      ss >> token;
      
      // determine interface
      if(token.compare("Ethernet") == 0){ 
	arp_pk.interface = token;
	cout<<arp_pk.interface<<endl;
      }

      ss >> token;
      ss >> token;
      token.erase(token.size() - 2, string::npos);
      temp_ss << token;
      temp_ss >> arp_pk.interface_len;
      temp_ss.clear();
      cout<< arp_pk.interface_len << endl;

      // determine IP type
      ss >> token;
      if(token.compare("IPv4") == 0){
	arp_pk.ip_type = IPV4;
      }
      else if(token.compare("IPv6") == 0){
	arp_pk.ip_type = IPV6;
      }

      ss >> token;
      ss >> token;
      token.erase(token.size() - 2, string::npos);
      temp_ss << token;
      temp_ss >> arp_pk.ip_len;
      temp_ss.clear();
      cout<< arp_pk.ip_len  <<endl; // IPv4/v6 len

      // determine ARP packet type
      ss >> token;
      cout<<token<<endl; // reply/request
      if(token.compare("Request") == 0){
	arp_pk.packet_type = REQUEST;
	ss >> token; // skip "who-has" segment
      }
      else if(token.compare("Reply") == 0){
	arp_pk.packet_type = REPLY;
      }

      // determine ip addr from
      ss >> token;
      arp_pk.from_ip = token; // ip addr from
      cout<<arp_pk.from_ip<<endl;
      
      // ip addr action
      ss >> token;
      arp_pk.action = token; // action, e.g. is-at, tell, etc
      cout<<arp_pk.action<<endl;

      // determine ip addr to
      ss >> token;
      token.erase(token.size() - 1, string::npos);
      arp_pk.to_ip = token; // ip addr to
      cout<<arp_pk.to_ip<<endl; 

      // determine payload size
      ss >> token; // skip "length" string
      ss >> token;
      temp_ss << token;
      temp_ss >> arp_pk.payload_size;
      cout<<arp_pk.payload_size<<endl;

      // determine number of lines of payload
      int num_payload_line = (arp_pk.payload_size + arp_pk.interface_len + arp_pk.ip_len + 4)/16 + 1;
      cout<<"line of payload = "<<num_payload_line<<endl;
      payload_left = num_payload_line; // count when processing payload line by line

    }
  }


  cout<<arp_packet_list.size()<<endl;
  return 0;
}
