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

#define BAD_CHECKSUM 0
#define GOOD_CHECKSUM 1
struct DNS_record {
  int second; // [5s]
  string type; // A? 
  string ip;
  string target;
};
struct IP_PACKET {
  int tos;
  int ttl;
  int id;
  int offset;
  string flags;
  string proto;// protocol UDP/TCP/... etc
  int length;
  // second line of IP packet
  string from_ip; 
  string to_ip;
  // need to add more parameters 
  int checksum; // good/bad checksum
  string wrong_cksum; 
  string right_cksum;
  string errno; // 40414+ / 41305
  DNS_record query; // microsoft.com, google.ca, etc
  vector<DNS_record> routes; // DNS resolve path
  string end_value; // I don't know what it is. Need to consult manpage
  string payload;
};
vector<IP_PACKET> ip_packet_list; // store captured IP packets


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
  string line, payload;
  struct ARP_PACKET arp_pk;
  struct DNS_record dns_pk;
  struct IP_PACKET ip_pk;

  // proceed stdin
  while(getline(cin, line)){
    
    stringstream ss;
    ss << line;
    string first_token, second_token;
    ss >> first_token;

    if(check_token(first_token) == HEXXXD){
      // proceed payload
      string token;

      if(CURRENT_PACKET == PACKET_ARP && payload_left > 0){
	while(!ss.eof()){
	  string tempstring;
	  ss >> tempstring;
	  if(tempstring.find(".") == string::npos) token += tempstring;

	}
	payload += token;
	payload_left--;
	if(payload_left == 0){
	  // reset stuff for processing next packet
	  CURRENT_PACKET = 0;
	  arp_pk.payload = payload;
	  payload.clear();

	  struct ARP_PACKET temp_arp;
	  temp_arp.interface = arp_pk.interface;
	  temp_arp.interface_len = arp_pk.interface_len;
	  temp_arp.ip_type = arp_pk.ip_type;
	  temp_arp.ip_len = arp_pk.ip_len;
	  temp_arp.packet_type = arp_pk.packet_type;
	  temp_arp.from_ip = arp_pk.from_ip;
	  temp_arp.action = arp_pk.action;
	  temp_arp.to_ip = arp_pk.to_ip;
	  temp_arp.payload_size = arp_pk.payload_size;
	  temp_arp.payload = arp_pk.payload;

	  cout<<"payload size = "<<temp_arp.payload.size()<<endl;
	  cout<<"payload = "<<temp_arp.payload<<endl;
	  arp_packet_list.push_back(temp_arp);

	}
      }
      else if(CURRENT_PACKET == PACKET_IP && payload_left > 0){
	while(!ss.eof()){
	  string tempstr;
	  ss >> tempstr;
	  if(tempstr.find(".") == string::npos) token += tempstr;
	}
	payload += token;
	payload_left--;

	if(payload_left == 0){
	  CURRENT_PACKET = 0;
	  ip_pk.payload = payload;
	  payload.clear();

	  struct IP_PACKET temp_ip;
	  temp_ip.tos = ip_pk.tos;
	  temp_ip.tos = ip_pk.ttl;
	  temp_ip.id = ip_pk.id;
	  temp_ip.offset = ip_pk.offset;
	  temp_ip.flags = ip_pk.flags;
	  temp_ip.proto = ip_pk.proto;
	  temp_ip.length = ip_pk.length;
	  temp_ip.from_ip = ip_pk.from_ip;
	  temp_ip.to_ip = ip_pk.to_ip;
	  temp_ip.checksum = ip_pk.checksum;
	  temp_ip.wrong_cksum = ip_pk.wrong_cksum;
	  temp_ip.right_cksum = ip_pk.right_cksum;
	  temp_ip.errno = ip_pk.errno;
	  temp_ip.query.second = ip_pk.query.second;
	  temp_ip.query.type = ip_pk.query.type;
	  temp_ip.query.ip = ip_pk.query.ip;
	  temp_ip.query.target = ip_pk.query.target;
	  temp_ip.routes = ip_pk.routes;
	  temp_ip.end_value = ip_pk.end_value;
	  temp_ip.payload = ip_pk.payload;
	  
	  ip_pk.routes.clear();

	  cout<<"payload size = "<<temp_ip.payload.size()<<endl;
	  cout<<"payload = "<<temp_ip.payload<<endl;
	  ip_packet_list.push_back(temp_ip);
	}
      }

    }
    else if(check_token(first_token) == IPADDR){
      /*
       * handle IP packet(Second half of the header)
       */

      string token;
      ss >> token;
      ss >> token;

      ip_pk.from_ip = first_token; // from_ip
      token.erase(token.size()-1, string::npos);
      ip_pk.to_ip = token; // to_ip

      ss >> token;
      if(token.compare("[bad") == 0){
	// process bad checksum
	ip_pk.checksum = BAD_CHECKSUM;
	ss >> token;
	ss >> token;
	ss >> token;
	ip_pk.wrong_cksum = token;
	ss >> token;
	ss >> token;
	token.erase(token.size() - 2, string::npos);
	ip_pk.right_cksum = token;
	ss >> token;
	ip_pk.errno = token;

	ip_pk.query.second = 0;
	ss >> token;
	ip_pk.query.type = token;
	ss >> token;
	ip_pk.query.target = token;

	ss >> token;
	ip_pk.end_value = token;

      }
      else if(token.compare("[udp") == 0){
	// process good udp checksum
	ip_pk.checksum = GOOD_CHECKSUM;

	ss >> token;
	ss >> token;
	ss >> token;
	ip_pk.errno = token;
	ss >> token;
	ss >> token;
	ip_pk.query.second = 0;
	ip_pk.query.type = token;
	ss >> token;
	ip_pk.query.target = token;

	int pos, num1, num2, num3; // 2/0/0, 5/0/0
	// need to figure out these numbers.
	ss >> token;
	string delimiter = "/";
	pos = token.find("/");
	num1 = atoi(token.substr(0,pos).c_str());
	token.erase(0,pos+1);

	pos = token.find("/");
	num2 = atoi(token.substr(0,pos).c_str());
	token.erase(0,pos+1);

	pos = token.find("/");
	num3 = atoi(token.substr(0,pos).c_str());
	token.erase(0,pos+1);
	ss >> token;

	for(int i=0;i<num1;i++){
	  ss >> token;
	  token.erase(0,1);
	  token.erase(token.size()-2, string::npos);
	  dns_pk.second = atoi(token.c_str());
	  ss >> token;
	  dns_pk.type = token;
	  ss >> token;
	  dns_pk.ip = token;
	  ss >> token;
	  dns_pk.target = token;
	  ip_pk.routes.push_back(dns_pk);
	}

	ss >> token;
	ip_pk.end_value = token;

	// need to compute # lines of payload
      }


    }

    ss >> second_token;
    if(check_token(second_token) == PACKET_IP){
      /*
       * handle IP packet(First half of the header)
       */
      cout<<"PACKET TYPE = IP"<<endl;
      CURRENT_PACKET = PACKET_IP;
      int temp_value;

      stringstream temp_ss2;
      
      string token;
      ss >> token;
      
      // tos
      ss >> token; 
      token.erase(token.size()-1, string::npos);
      temp_ss2 << token;
      temp_ss2 >> ip_pk.tos;

      // ttl
      ss >> token;
      ss >> token;
      token.erase(token.size()-1, string::npos);
      ip_pk.ttl = atoi(token.c_str());

      // id
      ss >> token;
      ss >> token;
      token.erase(token.size()-1, string::npos);
      ip_pk.id = atoi(token.c_str());

      // offset
      ss >> token;
      ss >> token;
      token.erase(token.size()-1, string::npos);
      ip_pk.offset = atoi(token.c_str());

      // flags
      ss >> token;
      ss >> token;
      token.erase(token.size()-1, string::npos);
      ip_pk.flags = token;

      // proto
      ss >> token;
      ss >> token;
      string temptoken = token;
      ss >> token;
      token.erase(token.size()-1, string::npos);
      temptoken += token;
      ip_pk.proto = temptoken;

      // length
      ss >> token;
      ss >> token;
      token.erase(token.size()-1, string::npos);
      ip_pk.length = atoi(token.c_str());
      

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
      }

      ss >> token;
      ss >> token;
      token.erase(token.size() - 2, string::npos);
      temp_ss << token;
      temp_ss >> arp_pk.interface_len;
      temp_ss.clear();

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

      // determine ARP packet type
      ss >> token;
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
      
      // ip addr action
      ss >> token;
      arp_pk.action = token; // action, e.g. is-at, tell, etc

      // determine ip addr to
      ss >> token;
      token.erase(token.size() - 1, string::npos);
      arp_pk.to_ip = token; // ip addr to

      // determine payload size
      ss >> token; // skip "length" string
      ss >> token;
      temp_ss << token;
      temp_ss >> arp_pk.payload_size;

      // determine number of lines of payload
      int num_payload_line = (arp_pk.payload_size + arp_pk.interface_len + arp_pk.ip_len + 4)/16 + 1;
      cout<<"line of payload = "<<num_payload_line<<endl;
      payload_left = num_payload_line; // count when processing payload line by line

    }
  }


  return 0;
}
