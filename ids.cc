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
    string first_token;
    ss >> first_token;
    if(check_token(first_token) == TIME){
      cout<<"TIME = "<<first_token<<endl;
    }
  }
  return 0;
}
