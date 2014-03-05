#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>

using namespace std; 

#define ERR -1
#define TIME 0
#define IPADDR 1
#define PACKET_IP 2
#define PACKET_ARP 3
#define HEXXXD 4

struct ARP_PACKET {
  string interface; // eth0, ethernet, etc
  int len;
  int ip_type; // ipv4 / ipv6
  int packet_type; // request / reply
  string from; // IP addr from
  string action; // tell / is-at
  string to; // IP address
  int payload_size; // payload size
};

int check_token(string token){
  if(token.find("0x") != string::npos && token.size() == 6) return HEXXXD;

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
    stringstream ss;
    ss << line;
    string first_token, second_token;
    ss >> first_token;
    if(check_token(first_token) == TIME){
      //      cout<<"TIME = "<<first_token<<endl;
    }

    ss >> second_token;
    if(check_token(second_token) == PACKET_IP){
      /*
       * handle IP packet
       */
      //      cout<<"PACKET TYPE = IP"<<endl;
      
    }
    else if(check_token(second_token) == PACKET_ARP){
      /* 
       * handle ARP packet
       */
      cout<<"PACKET TYPE = ARP"<<endl;

      string token;
      ss >> token;
      
      // determine interface
      if(token.compare("Ethernet") == 0) cout<<"On Ethernet"<<endl;

      ss >> token;
      ss >> token;
      token.erase(token.size() - 2,string::npos);
      cout<<token<<endl; // Ethernet's len

      // determine IP type
      ss >> token;
      cout<<token<<endl;

      ss >> token;
      ss >> token;
      token.erase(token.size() - 2,string::npos);
      cout<<token<<endl; // IPv4/v6 len

      // determine ARP packet type
      ss >> token;
      cout<<token<<endl; // reply/request
      if(token.compare("Request") == 0) ss>>token; // who-has segment

      // determine ip addr from
      ss >> token;
      cout<<token<<endl; // ip addr from


    }
  }
  return 0;
}
