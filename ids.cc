#include <iostream>
#include <sstream>
#include <fstream>
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
  string time;
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
  string time;
  int tos;
  int ttl;
  int id;
  int offset;
  string flags;
  string proto;// protocol UDP/TCP/ICMP etc
  int length;
  // second line of IP packet
  string second_line;
  string payload;
};
vector<IP_PACKET> ip_packet_list; // store captured IP packets


int check_token(string token){
  if(token.find("0x") != string::npos && token.size() == 7) return HEXXXD;

  int count1 = std::count(token.begin(), token.end(), '.');
  if(count1 == 4 || count1 == 3) return IPADDR;
  
  if(count1 == 1){
    int count2 = std::count(token.begin(), token.end(), ':');
    if(count2 == 2) return TIME;
    else return ERR;
  }

  if(token.compare("IP") == 0) return PACKET_IP;
  if(token.compare("ARP,") == 0) return PACKET_ARP;
}

/*
 * Analyze if a given IP packet is an attack
 */
int check_malicious_host(string host){
  ifstream domain_file("domains.txt");
  
  string line;
  int err = 0;

  while(getline(domain_file, line)){
    string temp = line;
    line.erase(line.size() - 1, string::npos);
    if(line == host){
      err = 1;
      break;
    }
  }

  domain_file.close();
  return err;
}

vector<IP_PACKET> ack_list, syn_list, rst_list;// elements are from/to unique address
void Analyze_IP(IP_PACKET ip_packet){
  if(ip_packet.proto.find("TCP") != string::npos){
    stringstream sst;
    string token;
    sst << ip_packet.second_line;
    
    // IP address check
    string from_ip, to_ip;
    sst >> from_ip;
    sst >> token;
    sst >> to_ip;
    to_ip.erase(to_ip.size()-1, string::npos);
    if(from_ip.compare(0,2,"10") != 0 && to_ip.compare(0,2,"10") != 0 ){
      // Spoofed IP address
      cout<<"[Spoofed IP address]: src:"<<from_ip<<", dst:"<<to_ip<<endl;
      cout.flush();
    }
    else if(from_ip.compare(0,2,"10") != 0 && to_ip.compare(0,2,"10") == 0){
      // unauthorized servers

      cout<<"[Attempted server connection]: rem:"<<from_ip<<", srv:"<<to_ip<<endl;
      cout.flush();

      sst >> token;
      sst >> token;
      sst >> token;
      sst >> token;
      sst >> token;
      sst >> token;
      sst >> token;
      sst >> token;
      sst >> token;
      token.erase(token.size()-1, string::npos);
      int ack_value = atoi(token.c_str());
      if(ack_value == 1){
	cout<<"[Established server connection]: rem:"<<from_ip<<", srv:"<<to_ip<<endl;
	cout.flush();
      }
    }
    else if(from_ip.compare(0,2,"10") == 0 && to_ip.compare(0,2,"10") == 0){
      // network scan: SYN, ACK
      sst >> token;
      sst >> token;
      if(token.compare("[S],") == 0){
	// add it to syn_list
	int unique = 0;
	vector<IP_PACKET>::iterator it;
	for(it = syn_list.begin(); it != syn_list.end(); it++){
	  // go through list to make sure uniqueness
	  string second_line = (*it).second_line, token;
	  stringstream tempss;
	  tempss << second_line;
	  tempss >> token;
	  tempss >> token;
	  tempss >> token;
	  token.erase(token.size()-1, string::npos);

	  if(token.compare(to_ip) != 0) unique++;
	}
	if(unique == syn_list.size()) syn_list.push_back(ip_packet);

	if(syn_list.size() == 10){
	  // validate time difference
	   
	}

      }
      else if(token.compare("[.],") == 0){
	int unique = 0;
        vector<IP_PACKET>::iterator it;
        for(it = ack_list.begin(); it != ack_list.end(); it++){
          // go through list to make sure uniqueness
          string second_line = (*it).second_line, token;
          stringstream tempss;
          tempss << second_line;
          tempss >> token;
          tempss >> token;
          tempss >> token;
          token.erase(token.size()-1, string::npos);

          if(token.compare(to_ip) != 0) unique++;
        }
        if(unique == syn_list.size()) ack_list.push_back(ip_packet);

	if(ack_list.size() == 10 && rst_list.size() == 1){
	  // validate time difference

	}

      }
      else if(token.compare("[R],") == 0){
	int validate = 0;
	vector<IP_PACKET>::iterator it;
	for(it=ack_list.begin(); it!=ack_list.end(); it++){
	  string second_line = (*it).second_line, token;
	  stringstream tempss;
	  tempss << second_line;
	  tempss >> token;
	  tempss >> token;
	  tempss >> token;
	  token.erase(token.size()-1, string::npos);
	  if(token.compare(to_ip) == 0) validate++;
	}
	if(validate != 0) rst_list.push_back(ip_packet);
      }


    }
    
  }
  // UDP
  else if(ip_packet.proto.find("UDP") != string::npos){
    stringstream sst;
    string token;
    sst << ip_packet.second_line;

    // UDP address check
    string from_ip, to_ip;
    sst >> from_ip;
    sst >> token;
    sst >> to_ip;
    to_ip.erase(to_ip.size()-1, string::npos); 

    if(from_ip.compare(0,2,"10") != 0 && to_ip.compare(0,2,"10") != 0 ){
      // Spoofed IP address
      cout<<"[Spoofed IP address]: src:"<<from_ip<<", dst:"<<to_ip<<endl;
      cout.flush();
    }
    else if(from_ip.compare(0,2,"10") != 0 && to_ip.compare(0,2,"10") == 0){
      /*
       * Note: There is no such thing as ACK segment for UDP    
       */
    }
    else if(from_ip.compare(0,2,"10") == 0 && to_ip.compare(0,2,"10") == 0){
      // check if looking up to malicious hosts

      sst >> token;
      if(token.find("[udp") != string::npos){
	// valid DNS lookup
	sst >> token;
	sst >> token;
	sst >> token;
	sst >> token;
	sst >> token;
	sst >> token;
	token.erase(token.size()-1, string::npos);
	// check if website is malicious
	int err = check_malicious_host(token);
	if(err == 1){
	  cout<<"[Malicious name lookup]: src:"<<to_ip<<", host:"<<token<<endl;
	  cout.flush();
	}
      }
      
    }

  }
  // ICMP
  else if(ip_packet.proto.find("ICMP") != string::npos){

  }
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
    string first_token, second_token, time;
    ss >> first_token;

    if(check_token(first_token) == TIME){
      time = first_token;
    }
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
	  temp_arp.time = time;
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

	  /*
	   * ARP packet analysis
	   */

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
	  temp_ip.time = ip_pk.time;
	  temp_ip.tos = ip_pk.tos;
	  temp_ip.tos = ip_pk.ttl;
	  temp_ip.id = ip_pk.id;
	  temp_ip.offset = ip_pk.offset;
	  temp_ip.flags = ip_pk.flags;
	  temp_ip.proto = ip_pk.proto;
	  temp_ip.length = ip_pk.length;
	  temp_ip.payload = ip_pk.payload;
	  temp_ip.second_line = ip_pk.second_line;

	  cout<<"payload size = "<<temp_ip.payload.size()<<endl;
	  cout<<"payload = "<<temp_ip.payload<<endl;
	  ip_packet_list.push_back(temp_ip);
	  ip_pk.payload.clear();

	  /*
	   * IP packet analysis
	   */
	  Analyze_IP(temp_ip);
	}
      }

    }
    else if(check_token(first_token) == IPADDR){
      /*
       * handle IP packet(Second half of the header) 
       */

      string second_line = first_token;
      second_line += " ";
      while(!ss.eof()){
	string temps;
	ss >> temps;
	second_line += temps;
	second_line += " ";
      }

      cout<<second_line<<endl;
      ip_pk.second_line = second_line;
      
      // need to compute # lines of payload
      int num_payload_line = (ip_pk.length + 14)/16 + 1;
      payload_left = num_payload_line;

    }

    ss >> second_token;
    if(check_token(second_token) == PACKET_IP){
      /*
       * handle IP packet(First half of the header)
       */
      cout<<"PACKET TYPE = IP"<<endl;
      ip_pk.time = time; // update current packet received time

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
