#include <iostream>
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h> 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cctype>
#include <vector>
#include <string>
#include <pthread.h>
#include <iomanip>

#define BUFF_SIZE 1024
#define BACKLOG 5

using namespace std;
// *********** Global variables *********** //
//char *END = nullptr; // use to stop thread
const string LOGIN_FAIL = "220 AUTH_FAIL";
int *server_sockfd; 
// ************ Enum & Struct ************ //
enum Action{
	REGISTER, LOGIN, LIST, TRANSACTION, EXIT, UNKNOWN
};
struct MyAddr
{
	string user_Name;
	string user_IP;
	string user_PORT;
};
// ********** Utility function ********** //
bool 				is_number(string &str);
Action 				checkCmd(string str);
static void 		usage();
std::vector<string> parsing(string str,string deli);
void* 				listeningThread(void *pName);
bool 				outputList(string listInfo);
// ********** Command function ********** //
bool Register(int sockfd,string userAccountName, string depositAmount);
bool Login(int sockfd,string userAccountName,string portName,vector<MyAddr> &v,string &cName,bool &loginOrNot,pthread_t &tid);
bool List(int sockfd,vector<MyAddr> &v);
bool Exit(int sockfd);
bool Transaction(string userAccountName,string payAmount,string payeeAccountName,vector<MyAddr> &v);




int main(int argc , char *argv[])
{
	// ********** Variables ********** //
	string         	str;
	bool           	exits = false;
	Action         	action = Action::UNKNOWN;
	char           	tmpBuffer[BUFF_SIZE] = {0};
	vector<MyAddr> 	vec;
	pthread_t  		tid_child;
	bool 	  		loginOrNot = false;
	string			clientName;
	int sockfd = 0;
	int server_port = 0;
	string server_ip ; 
	// ******************************* //
	if(argc != 3){
		cerr<<": usage:  ./client <portName>"<<endl;
		cerr <<": portName is an integer between 1024~65535"<<endl;
		return 0;
	}
	else{
		string tmp = argv[2];
		if(!is_number(tmp)){
			cerr <<": portName is an integer between 1024~65535"<<endl;
			return 0;
		}
		if(stoi(tmp)< 1024 || stoi(tmp)>65536){
			cerr <<": portName is an integer between 1024~65535"<<endl;
			return 0;
		}
		server_port = stoi(tmp);
	}
	server_ip = argv[1];
	cout<<": server IP   "<<server_ip<<endl;
	cout<<": server port "<<server_port<<endl;
	// ******************************* //
	
	// socket
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){ 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
    // Convert IPv4 and IPv6 addresses from text to binary form
    struct sockaddr_in server_addr;
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET; 
    server_addr.sin_port = htons(server_port);  
    if(inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr)<=0){ 
        cout <<"\nInvalid address/ Address not supported \n"; 
        return -1; 
    } 
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){ 
        cout << "\nConnection Failed \n"; 
        return -1; 
    } 
    else{
    	recv(sockfd,tmpBuffer,BUFF_SIZE,0);
    	cout << "-> server: " << std::string(tmpBuffer) << endl;
    }
    usage();
    server_sockfd = new int(sockfd);
	// busy waiting for command
	while(!cin.eof()){
		getline(std::cin,str);
		// parsing
		vector<string> parsed = parsing(str," ");
		action = checkCmd(parsed[0]);
		// action
		switch(action){
			case Action::REGISTER:
				if(!Register(sockfd,parsed[1],parsed[2]))
					cerr<<": register fail"<<endl;
				break;
			case Action::LOGIN:
				if(!Login(sockfd,parsed[1],parsed[2],vec,clientName,loginOrNot,tid_child))
					cerr<<": login fail(not register yet)"<<endl;
				break;
			case Action::LIST:
				if(!List(sockfd,vec))
					cerr<<": list fail"<<endl;
				break;
			case Action::TRANSACTION:
				if(!Transaction(clientName,parsed[1],parsed[2],vec))
					cerr<<": transaction fail"<<endl;
				break;
			case Action::EXIT:
				if(!Exit(sockfd))
					cerr<<": exit fail"<<endl;
				else
					exits = true;
				break;
			default:
				cerr << ": unknown command !!" << endl;
				usage();

		}
		// exits
		if(exits) break;				
	}
    return 0;
}
// ************************************************** //
Action checkCmd(string str)
{
	Action res;

	if(str == "reg")
		res = Action::REGISTER;
	else if(str == "login")
		res = Action::LOGIN;
	else if(str == "list")
		res = Action::LIST;
	else if(str == "trans")
		res = Action::TRANSACTION;
	else if(str == "exit")
		res = Action::EXIT;
	else
		res = Action::UNKNOWN;
	
	return res;
}


static void usage()
{
   cout << "******************** Usage ********************" << endl;
   cout << "Register   : reg <UserAccountName> <depositAmount>" << endl;
   cout << "Log in     : login <UserAccountName> <portName>" << endl;
   cout << "List       : list" << endl;
   cout << "Transaction: trans <payAmount> <PayeeAccountName>" << endl;
   cout << "Exit       : exit" << endl;
   cout << "***********************************************" << endl;
}


std::vector<string> parsing(string str,string deli)
{
	std::vector<string> res;
	char *cstr = new char[str.size()+1];
	strcpy(cstr,str.c_str());
	// 
	char *cdeli = new  char[deli.size()];
	strcpy(cdeli,deli.c_str());
	char *ptr;
	ptr= strtok(cstr,cdeli);
	while(ptr != nullptr){
		string tmp = ptr;
		res.push_back(tmp);
		ptr = strtok(nullptr,cdeli);
	}
	return res;
}


void* listeningThread(void *pName)
{
	string portName = (char*)pName;
	int  *client_sockfd;
	client_sockfd = new int(0); // initialize
	struct sockaddr_in address; 
    int addrlen = sizeof(address); 
    int new_socket = 0; 
    
    // Creating socket file descriptor 
    if ((*client_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0){ 
        cerr << ": socket failed" << endl; 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( stoi(portName) ); 
    
    if(::bind(*client_sockfd, (struct sockaddr *)&address, sizeof(address))<0){ 
        cerr << ": bind failed" << endl; 
        exit(EXIT_FAILURE); 
    }
    if (listen(*client_sockfd, BACKLOG) < 0) { 
        cerr << ": listen" << endl; 
        exit(EXIT_FAILURE); 
    } 
    // ******************
    char*  grateful[2] = {0};
    grateful[0] = "Thank you !";
    grateful[1] = "m(_ _)m";
    while(true){
    	//cout <<"where r you"<<endl;
    	if ((new_socket = accept(*client_sockfd, (struct sockaddr *)&address,(socklen_t*)&addrlen))<0){ 
        	cerr << "accept" <<endl; 
        	exit(EXIT_FAILURE); 
    	}
    	// cout <<"where r you2"<<endl;
    	char cbuffer[BUFF_SIZE] = {0};
    	recv( new_socket , cbuffer, BUFF_SIZE,0);
    	string buffer = cbuffer;
    	cout << "-> msg: "<< buffer << endl;
    	int i = rand()%2;
    	send(new_socket,grateful[i],strlen(grateful[i]),0);
    	// send ack to server (phase II)
    	char cbuffer2[BUFF_SIZE] = {0};
    	string server_req = std::string("CONFIRM#")+buffer;
    	send(*server_sockfd,server_req.c_str(),strlen(server_req.c_str()),0);
    	recv(*server_sockfd,cbuffer2,BUFF_SIZE,0);
    	cout <<"-> server: "<<std::string(cbuffer2);
    	// 
    	// 
    }
}
bool is_number(string &str)
{
	if(str.size() == std::string::npos)
		return false;
	for(int i = 0; i<str.size();i++)
		if(!std::isdigit(str[i]))
			return false;
	return true;
}

bool outputList(string listInfo)
{
	vector<string> vtmp = parsing(listInfo," #\r\n");
	string spacing = "    ";
	int name_offset = 10;
	int ip_offset  = 20;
	for(int i = 0; i < (vtmp.size()-2)/3; i++){
		if(vtmp[3*i+2].size() > name_offset)
			name_offset = vtmp[3*i+2].size();
		if(vtmp[3*i+2+1].size() > ip_offset)
			ip_offset = vtmp[3*i+2+1].size();
	}

	cout << spacing << "Account balance: " << vtmp[0] << endl;
	cout << spacing << "Online users   : " << vtmp[1] << endl;
	cout << spacing << "Online list    : " << endl;
	// draw table
	cout << spacing << std::string(name_offset+ip_offset+4+6,'-') << endl;
	cout << spacing+"|" << setw(name_offset) << "Name" << "|" << setw(ip_offset) << "IP address" << "|" << setw(6) << "Port" << "|" << endl;
	cout << spacing << std::string(name_offset+ip_offset+4+6,'-') << endl;
	for(int i = 0; i < (vtmp.size()-2)/3; i++)
		cout << spacing+"|" << setw(name_offset) << vtmp[3*i+2] << "|" << setw(ip_offset) << vtmp[3*i+2+1] << "|" << setw(6) << vtmp[3*i+2+2] << "|" << endl;
	cout << spacing << std::string(name_offset+ip_offset+4+6,'-') << endl;

	return true;
}
// ******************************************************************************* //
bool Register(int sockfd,string userAccountName, string depositAmount)
{
	if(!is_number(depositAmount)){
		cerr << ": depositAmount is not a number !"<<endl;
		return  false;
	}
	char cbuffer[BUFF_SIZE] = {0};
	string msg = std::string("REGISTER")+"#"+userAccountName+"#"+depositAmount;

	send(sockfd,msg.c_str(),strlen(msg.c_str()),0); // send request
	recv(sockfd,cbuffer,BUFF_SIZE,0); // get response
	string buffer = cbuffer;
	cout << "-> server: " << buffer;
	// pasrse response
	char *ptr  = strtok(cbuffer," \n");
	string statusCode = ptr;

	if(statusCode == "100")
		return true;
	else
		return false;

}
bool Login(int sockfd,string userAccountName,string portName,vector<MyAddr> &v,string &cName,bool &loginOrNot,pthread_t &tid)
{
	if(!is_number(portName)){
		cerr << ": portName is not a number!"<<endl;
		return  false;
	}
	if(stoi(portName)<1024 || stoi(portName)>65536){
		cerr << ": portName is not a number betweeb 1024~65535!"<<endl;
		return  false;
	}
	char cbuffer[BUFF_SIZE] = {0};

	string msg = userAccountName + "#" + portName;
	
	send(sockfd,msg.c_str(),strlen(msg.c_str()),0); // send request
	recv(sockfd,cbuffer,BUFF_SIZE,0); // get response
	string buffer = cbuffer;
	if(buffer.find(LOGIN_FAIL) != std::string::npos) 
		return false; // catch login error
	if(loginOrNot) {
		cout << "-> server: " << buffer << endl;
		return true; // check already login 
	}
	
	// update vector
	vector<string> parsed_list = parsing(buffer," #\r\n");
	v.clear();
	for(int i =0;i < (parsed_list.size()-2)/3;i++){
		MyAddr tmp = {
			.user_Name = parsed_list[2+3*i],
			.user_IP = parsed_list[2+3*i+1],
			.user_PORT = parsed_list[2+3*i+2]
		};
		v.push_back(tmp);
	}
	char *pName = new char[portName.size()];
	strcpy(pName,portName.c_str());
	pthread_create(&tid,NULL,listeningThread,pName); // threading 

	cout << "-> server:\n";
	outputList(buffer); // output list
	loginOrNot = true;
	cName = userAccountName;
	return true;
}

bool List(int sockfd,vector<MyAddr> &v)
{
	string msg = "List";
	char cbuffer[BUFF_SIZE] = {0};
	send(sockfd,msg.c_str(),strlen(msg.c_str()),0); // send request
	recv(sockfd,cbuffer,BUFF_SIZE,0); // get response
	string buffer = cbuffer;
	cout <<"-> server:\n";
	outputList(buffer);
	// update vector
	vector<string> parsed_list = parsing(buffer," #\r\n");
	v.clear();
	for(int i =0;i < (parsed_list.size()-2)/3;i++){
		MyAddr tmp = {
			.user_Name = parsed_list[2+3*i],
			.user_IP = parsed_list[2+3*i+1],
			.user_PORT = parsed_list[2+3*i+2]
		};
		v.push_back(tmp);
	}

	return true;
}


bool Exit(int sockfd)
{
	string msg = "Exit";
	char cbuffer[BUFF_SIZE] = {0};
	send(sockfd,msg.c_str(),strlen(msg.c_str()),0); // send request
	recv(sockfd,cbuffer,BUFF_SIZE,0); // get response
	string buffer = cbuffer;
	cout <<"-> server: "<< buffer;

	return true;
}


bool Transaction(string userAccountName,string payAmount,string payeeAccountName,vector<MyAddr> &v){
	if(!is_number(payAmount)){
		cerr << ": payAmount is not a number !"<<endl;
		return  false;
	}
	string payee_IP;
	string payee_PORT;
	vector<MyAddr>::iterator it= v.begin();
	for(it;it != v.end();it++){
		if(it->user_Name == payeeAccountName){
			payee_IP = it->user_IP;
			payee_PORT = it->user_PORT;
		}
	}
	if(payee_IP.size() == string::npos){
		cerr << "user not found" << endl;
		return false;
	}
	// connectdo!
	char cbuffer[BUFF_SIZE] = {0};
	int payee_sockfd = 0;
	if ((payee_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){ 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
    struct sockaddr_in server_addr;
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET; 
    server_addr.sin_port = htons(stoi(payee_PORT));  
    if(inet_pton(AF_INET, payee_IP.c_str(), &server_addr.sin_addr)<=0){ 
        cout <<"\nInvalid address/ Address not supported \n"; 
        return -1; 
    } 
    if (connect(payee_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){ 
        cout << "\nConnection Failed \n"; 
        return -1; 
    } 
    string msg = userAccountName + "#" + payAmount +"#"+payeeAccountName+"\r\n";
	
	send(payee_sockfd,msg.c_str(),strlen(msg.c_str()),0); // send request
	recv(payee_sockfd,cbuffer,BUFF_SIZE,0); // get response
	cout <<"-> "<<payeeAccountName<<": "<<std::string(cbuffer)<<endl;
	// do something phase II
	char cbuffer2[BUFF_SIZE] = {0};
    recv(*server_sockfd,cbuffer2,BUFF_SIZE,0);
    cout <<"-> server: "<<std::string(cbuffer2);
	// 
	// 
	return true;
}