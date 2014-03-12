#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <algorithm>
#include <vector>
#include <map>
#include <ctime>
#include <cmath>
#include <cstdlib>
#include <cstdio>

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
  string from_mac;
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
 * Also analyze if there's a cryptolocker
 */
#define CRYPTOLOCKER 2
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
  if(err == 1){
    return err;
  }
  else if(err == 0){
    // check if the domain is cryptolocker
    
    /*
     * Generate all possible cryptolocker domain name
     */

    // get today's date
    time_t theTime = time(NULL);
    struct tm *aTime = localtime(&theTime);

    unsigned int day = aTime->tm_mday;
    unsigned int month = aTime->tm_mon + 1; // Month is 0 - 11, add 1 to get a jan-dec 1-12 concept
    unsigned int year = aTime->tm_year + 1900; // Year is # years since 1900

    unsigned int key = 0; // key can be correctly generated with time(NULL);

    ofstream cryptolocker_domain("cryptolocker_domain.txt");
    string tldlist[7] = { "com", "net", "biz", "ru", "org", "co.uk", "info" };

    int miss_count = 0;
    for(int i=0;i<1000;i++){
      unsigned int newkey = (key+i)%1000;
      // compute daykey, monthkey and yearkey
      unsigned int daykey = (day<<0x10) ^ day;
      if(daykey <= 1){
	daykey = day << 0x18;
      }
      unsigned int monthkey = (month << 0x10) ^ month;
      if(monthkey <= 7){
	monthkey = month<<0x18;
	if(monthkey<=7) monthkey = !(monthkey);
      }
      unsigned int yearkey = ((year+newkey)<<0x10) ^ (year+newkey);
      if(yearkey <= 0xF) yearkey = ((year+newkey)<<0x18);
      
      unsigned int strlength = 
	(((daykey ^ ((yearkey ^ 8 * yearkey ^ ((daykey ^ ((monthkey ^ 4 * monthkey) >> 6)) >> 8)) >> 5)) >> 6) & 3)+0xC;
      
      //char *domain_name = (char*)malloc(strlength * sizeof(char));// domain name
      string domain_name;

      unsigned int index = 0;
      do{
	monthkey = ((monthkey ^ 4 * monthkey) >> 0x19) ^ 0x10 * (monthkey & 0xFFFFFFF8);
	daykey = (daykey >> 0x13) ^ ((daykey >>6) ^ (daykey << 0xC)) & 0x1FFF ^ (daykey << 0xC);
	yearkey = ((yearkey ^ (8 * yearkey)) >> 0xB) ^ ((yearkey & 0xFFFFFFF0) << 0x11);
	index = index + 1;
	//	domain_name[index - 1] = (daykey ^ monthkey ^ yearkey) % 0x19 + 'a'; // year key is wrong
	char temp[1];
        temp[0] = (daykey ^ monthkey ^ yearkey) % 0x19 + 'a';
	temp[1] = '\0';
	domain_name.append(temp);
      }while(index < strlength);

      domain_name[strlength] = '\0';
      string domain_s(domain_name);
      domain_s.append(".");
      domain_s.append(tldlist[newkey % 7]);

      if(host == domain_s){
	err = CRYPTOLOCKER;
	break;
      }
      else if (host != domain_s){
	miss_count++;
      }
      
      cryptolocker_domain << domain_s ;
      cryptolocker_domain << endl;

    }

    cryptolocker_domain.close();
    return err;
  }

}

double string_time_to_double(string time){
  // e.g. 17:41:55.234567

  string shour = time.substr(0, 2);

  string sminute = time.substr(3, 2);

  string ssecond = time.substr(6, 2);

  string smillsecond = time.substr(9, 6);

  
  double hour = (double)atoi(shour.c_str());
  hour = hour * 3600;
  double minute = (double)atoi(sminute.c_str());
  minute = minute * 60;
  double second = (double)atoi(ssecond.c_str());
  double msec = (double)atoi(smillsecond.c_str());
  second = second + msec / 1000000;

  return hour+minute+second;
}

// Note: <key, value> = <src ip, target ip list>

map< string, vector<string> > ack_list, syn_list, rst_list, icmp_list;// elements are from/to unique address
string syn_start_time="start", syn_end_time;
string ack_start_time="start", ack_end_time;
string icmp_start_time="start", icmp_end_time;
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
      /*
       * Network Scan: SYN, ACK
       */
      sst >> token;
      sst >> token;
      if(token.compare("[S],") == 0){
	int dll = from_ip.find_last_of(".");
	string fromaddr = from_ip.erase(dll, string::npos);
	if(syn_start_time == "start"){
	  syn_start_time = ip_packet.time;
	}
	else syn_end_time = ip_packet.time;
	
	if(syn_list.find(fromaddr) == syn_list.end()){
	  // this src ip doesn't exist, insert it
	  vector<string> temp;
	  temp.push_back(to_ip);
	  syn_list.insert( pair< string, vector<string> >(fromaddr, temp) );
	}
	  else{
	    // update its value if key exists
	    map< string, vector<string> >::iterator ir;
	    for(ir=syn_list.begin(); ir != syn_list.end(); ir++){
	      if(ir->first == fromaddr){
		vector<string> temp = ir->second;
		if(find(temp.begin(), temp.end(), to_ip) == temp.end())temp.push_back(to_ip);

		ir->second = temp;
		break;
	      }
	    }
	  }
       
	  // check if any entry has 10+ scans
	  map< string, vector<string> >::iterator it;
	  for(it=syn_list.begin(); it != syn_list.end(); it++){
	    if(it->second.size() == 10 && string_time_to_double(syn_end_time) - string_time_to_double(syn_start_time) <= 2){
	      cout<<"[Potential network scan]: att:"<<it->first<<endl;
	    }
	  }
      }
      else if(token.compare("[.],") == 0){
	int dll = from_ip.find_last_of(".");
        string fromaddr = from_ip.erase(dll, string::npos);
        if(ack_start_time == "start"){
          ack_start_time = ip_packet.time;
        }
        else ack_end_time = ip_packet.time;

        if(ack_list.find(fromaddr) == ack_list.end()){
          // this src ip doesn't exist, insert it
          vector<string> temp;
          temp.push_back(to_ip);
          ack_list.insert( pair< string, vector<string> >(fromaddr, temp) );
        }
	else{
	  // update its value if key exists
	  map< string, vector<string> >::iterator ir;
	  for(ir=ack_list.begin(); ir != ack_list.end(); ir++){
	    if(ir->first == fromaddr){
	      vector<string> temp = ir->second;
	      if(find(temp.begin(), temp.end(), to_ip) == temp.end())temp.push_back(to_ip);

	      ir->second = temp;
	      break;
	    }
	  }
	}

	// check if any entry has 10+ scans
	map< string, vector<string> >::iterator it;
	for(it=ack_list.begin(); it != ack_list.end(); it++){
	  if(it->second.size() == 10 && string_time_to_double(ack_end_time) - string_time_to_double(ack_start_time) <= 2){
	    // Don't forget to check RST segment 
	    if(rst_list.find(it->first) != rst_list.end())    cout<<"[Potential network scan]: att:"<<it->first<<endl;
	  }
	}

      }
      else if(token.compare("[R],") == 0){
	int dll = from_ip.find_last_of(".");
        string fromaddr = from_ip.erase(dll, string::npos);
       
        if(rst_list.find(fromaddr) == rst_list.end()){
          // this src ip doesn't exist, insert it
          vector<string> temp;
          temp.push_back(to_ip);
          rst_list.insert( pair< string, vector<string> >(fromaddr, temp) );
        }
	else{
	  // update its value if key exists
	  map< string, vector<string> >::iterator ir;
	  for(ir=rst_list.begin(); ir != rst_list.end(); ir++){
	    if(ir->first == fromaddr){
	      vector<string> temp = ir->second;
	      if(find(temp.begin(), temp.end(), to_ip) == temp.end()) temp.push_back(to_ip);

	      ir->second = temp;
	      break;
	    }
	  }
	}

      }


    }
    /*
     * Examine payload for code red worm
     */
    string temp_payload = ip_packet.payload;
    int last_dot = to_ip.find_last_of(".");
    string port_s = to_ip.substr(last_dot+1, string::npos);
    if(port_s == "80"){
      // HTTP 
      // Check payload for malicious code
      int first_GET = temp_payload.find("GET");
      int first_HTTP = temp_payload.find("HTTP");
      if(first_GET < first_HTTP){
	string temptoken = temp_payload.substr(first_GET, first_HTTP);

	if(temptoken.find("/default.ida?") != string::npos && temptoken.find("%u") != string::npos){
	  cout<<"[Code Red exploit]: src:"<<from_ip<<", dst:"<<to_ip<<endl;
	  cout.flush();
	}
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
	if(err == CRYPTOLOCKER){
	  cout<<"[CryptoLocker key request]: src:"<<to_ip<<endl;
	  cout.flush();
	}
      }
      
    }

  }
  // ICMP
  else if(ip_packet.proto.find("ICMP") != string::npos){
    stringstream sst;
    string token;
    sst << ip_packet.second_line;

    string from_ip, to_ip;
    sst >> from_ip;
    sst >> token;
    sst >> to_ip;
    to_ip.erase(to_ip.size()-1, string::npos);

    if(icmp_start_time == "start"){
      icmp_start_time = ip_packet.time;
    }
    else icmp_end_time = ip_packet.time;

    if(icmp_list.find(from_ip) == icmp_list.end()){
      vector<string> temp;
      temp.push_back(to_ip);
      icmp_list.insert( pair< string, vector<string> >(from_ip, temp) );
    }
    else{
      map< string, vector<string> >::iterator ir;
      for(ir=icmp_list.begin(); ir!=icmp_list.end(); ir++){
	if(ir->first == from_ip){
	  vector<string> temp = ir->second;
	  if(find(temp.begin(), temp.end(), to_ip) == temp.end())	  temp.push_back(to_ip);

	  ir->second = temp;
	  break;
	}
      }
    }

      // check if any entry has 10+ scans
      map< string, vector<string> >::iterator it;
      for(it=icmp_list.begin(); it!=icmp_list.end(); it++){
	if(it->second.size() == 10 && string_time_to_double(icmp_end_time) - string_time_to_double(icmp_start_time) <= 2) cout<<"[Potential network scan]: att:"<<it->first<<endl;
      }

  }
}

  /*
   * Analyze ARP packet
   */
  vector<string> arp_list;
  string arp_start_time="start", arp_end_time;

  void Analyze_ARP(ARP_PACKET arp_packet){
    if(arp_start_time == "start"){
      arp_start_time = arp_packet.time;
    }
    else arp_end_time = arp_packet.time;

    if(find(arp_list.begin(), arp_list.end(), arp_packet.from_ip) == arp_list.end()) arp_list.push_back(arp_packet.from_ip);

    if(arp_list.size() == 10){
      cout<<"[Potential network scan]: att:"<<arp_packet.to_ip<<endl;
      cout.flush();
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
	if(payload_left > 1){
	  string temptoken;
	  for(int i = 0;i<8; i++){
	    ss >> temptoken;
	  }
	  ss >> temptoken;
	  token = temptoken;
	}
	else if(payload_left == 1){
	  string temptoken;
	  int last_line_token = ((arp_pk.payload_size + 14)/2)%8;
	  for(int i=0;i<last_line_token;i++){
	    ss >> temptoken;
	  }
	  ss >> token;
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

	  arp_pk.payload.clear();
	  arp_packet_list.push_back(temp_arp);

	  /*
	   * ARP packet analysis
	   */
	  Analyze_ARP(temp_arp);
	}
      }
      else if(CURRENT_PACKET == PACKET_IP && payload_left > 0){
	if(payload_left > 1){
          string temptoken;
          for(int i = 0;i<8; i++){
            ss >> temptoken;
          }
          ss >> token;

        }
        else if(payload_left == 1){
          string temptoken;
          int last_line_token = ((ip_pk.length+14)/2)%8;
	  for(int i = 0;i<last_line_token;i++){
	    ss >> temptoken;
	  }
	  ss >> token;
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

	  //	  cout<<"payload size = "<<temp_ip.payload.size()<<endl;
	  //	  cout<<"payload = "<<temp_ip.payload<<endl;
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

      //      cout<<second_line<<endl;
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
      //      cout<<"PACKET TYPE = IP"<<endl;
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
      //      cout<<"PACKET TYPE = ARP"<<endl;
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
      if(token.find("tell") == string::npos){
	arp_pk.from_mac = token;
	ss >> token;
      }
      else {
	arp_pk.action = token; // action, e.g. is-at, tell, etc
      }

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
      int num_payload_line = (arp_pk.payload_size + 14)/16 + 1;
      //      cout<<"line of payload = "<<num_payload_line<<endl;
      payload_left = num_payload_line; // count when processing payload line by line

    }
  }


  return 0;
}
