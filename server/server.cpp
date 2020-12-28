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
#include <unordered_map>
#include <assert.h>
#include "threadpool.h"

#define BUFF_SIZE 1024
#define THREAD 32
#define QUEUE  256
#define BACKLOG 5

using namespace std;
// ************* Enum & Struct ************* //
enum Action{
	REGISTER, LOGIN, LIST, TRANSACTION, EXIT, UNKNOWN
};
struct MyAddr
{
	string user_Name;
	string user_IP;
	string user_PORT;
};
// *********** Global variables *********** //
const string REG_SUC = "100 OK\r\n";
const string REG_FAIL = "200 FAIL\r\n";
const string LOGIN_FAIL = "220 AUTH_FAIL\r\n";
const string LOGIN_TWICE = "You have logged in already\r\n!";
const string LISTANDEXIT_FAIL = "Please login first!\r\n";
const string BYE = "Bye\r\n"; 
const string CONFIRM = "Confirm!\r\n";
pthread_mutex_t mutexX;
std::unordered_map<std::string,int> reg_deposit;
std::unordered_map<std::string,MyAddr> login_list;
std::unordered_map<std::string,int> name_sockfd; // only login
// ********** Utility function *********** //
bool 				is_number(string &str);
std::vector<string> parsing(string str,string deli);
Action 				Decide(vector<string> &v);
string 				getList(string user_name);
// *********** thread function *********** //
void				user_thread(void*socket_ptr);
bool 				Register(string userAccountName,string depositAmount);
bool 				Login(string userAccountName,string portNum);
bool 				Exit(string user_name);
bool 				ConfirmTransaction(string sander,string payAmount,string receiver);

int main(int argc, char* argv[])
{
	string portNum;
	cout << "Enter Port for server to listening: ";
	cin >> portNum;
	// initialize
	int server_sockfd = 0;
	struct sockaddr_in address; 
	address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( stoi(portNum) ); 
    int addrlen = sizeof(address); 
    char buffer[BUFF_SIZE] = {0}; 
    std::vector<pthread_t> tid_vec;
    pthread_mutex_init(&mutexX,NULL);
    //
    threadpool_t *pool;
    assert((pool = threadpool_create(THREAD, QUEUE, 0)) != NULL);
    cout << "Pool started with " << THREAD << " threads and queue size of " << QUEUE <<'\n';
    // constant string 
    const string greeting = "connection accepted!\r\n";
    // Creating socket file descriptor 
    if ((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0){ 
        cerr << ": socket failed" << endl; 
        exit(EXIT_FAILURE); 
    } 
    if(::bind(server_sockfd, (struct sockaddr *)&address, sizeof(address))<0){ 
        cerr << ": bind failed" << endl; 
        exit(EXIT_FAILURE); 
    }
    if (listen(server_sockfd, BACKLOG) < 0) { 
        cerr << ": listen failed" << endl; 
        exit(EXIT_FAILURE); 
    } 
    // ******************
    while(true){
    	//cout << "@"<<endl;
    	int *new_socket = new int(0);
    	if ((*new_socket = accept(server_sockfd, (struct sockaddr *)&address,(socklen_t*)&addrlen))<0){ 
        	cerr << "accept failed" <<endl; 
        	exit(EXIT_FAILURE); 
    	}
    	send(*new_socket,greeting.c_str(),strlen(greeting.c_str()),0); // send greeting
    	// create thread for this user
    	//pthread_t  tid;
    	//tid_vec.push_back(tid);
    	//pthread_create(&tid_vec[tid_vec.size()-1],NULL,user_thread,new_socket);
    	threadpool_add(pool, &user_thread, new_socket, 0);
    	
    	
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
void user_thread(void*socket_ptr)
{
	int sockfd = *(int*)socket_ptr; // socker to listen
	string user_name ; // if login 
	bool login_yet = false;
	bool end = false;
	// get user IP
	struct sockaddr_in user_addr;
	int addrlen = sizeof(user_addr); 
	getpeername (sockfd,(struct sockaddr *)&user_addr,(socklen_t *)&addrlen);
	string user_ip = inet_ntoa (user_addr.sin_addr);



	while(!end){
		char cbuffer[BUFF_SIZE] = {0};
		int checkpoint = recv(sockfd,cbuffer,BUFF_SIZE,0);
		if(checkpoint <= 0){
			cerr<<": A user disconnected unexpectedly :("<<endl;
			end=true;
			break;
			//pthread_exit(NULL);
		}
		// parsing
		string buffer = cbuffer;
		cout <<"msg: "<< buffer << endl;
		std::vector<string> vec = parsing(buffer,"#\r\n");
		Action action = Decide(vec);
		//
		switch(action){
			case Action::REGISTER:
				if(Register(vec[1],vec[2]))
					send(sockfd,REG_SUC.c_str(),strlen(REG_SUC.c_str()),0);
				else
					send(sockfd,REG_FAIL.c_str(),strlen(REG_FAIL.c_str()),0);

				break;
			case Action::LOGIN:
				if(login_yet){
					send(sockfd,LOGIN_TWICE.c_str(),strlen(LOGIN_TWICE.c_str()),0);
				}
				else{
					if(Login(vec[0],vec[1])){
						// write login_list
						MyAddr tmp = {
							.user_Name = vec[0],
							.user_IP = user_ip,
							.user_PORT = vec[1]
						};
						login_list.insert(std::pair<string, MyAddr>(vec[0], tmp));
						//
						login_yet = true;
						user_name = vec[0];
						name_sockfd.insert(std::pair<string,int>(vec[0],sockfd));
						string res = getList(user_name);
						send(sockfd,res.c_str(),strlen(res.c_str()),0);
					}
					else
						send(sockfd,LOGIN_FAIL.c_str(),strlen(LOGIN_FAIL.c_str()),0);
				}
				break;
			case Action::LIST:
				if(!login_yet){
					send(sockfd,LISTANDEXIT_FAIL.c_str(),strlen(LISTANDEXIT_FAIL.c_str()),0);
				}
				else{
					string res = getList(user_name);
					//cout <<res<<endl;
					send(sockfd,res.c_str(),strlen(res.c_str()),0);
				}
				break;
			case Action::TRANSACTION:
				//cout <<"not implement yet QQ"<<endl;
				ConfirmTransaction(vec[1], vec[2], vec[3]);
				send(sockfd,CONFIRM.c_str(),strlen(CONFIRM.c_str()),0); // send to payee
				send(name_sockfd.find(vec[1])->second,CONFIRM.c_str(),strlen(CONFIRM.c_str()),0); // send to giver
				break;
			case Action::EXIT:
				if(!login_yet){
					send(sockfd,LISTANDEXIT_FAIL.c_str(),strlen(LISTANDEXIT_FAIL.c_str()),0);
				}
				else{
					Exit(user_name);
					send(sockfd,BYE.c_str(),strlen(BYE.c_str()),0);	
				}
				//pthread_exit(NULL);	
				end = true;
				break;
			default:
				cerr << ": unknown command !!" << endl;

		}
	}
}
// read reg_deposit login_list
string getList(string user_name)
{
	unordered_map<string,int>::iterator it = reg_deposit.find(user_name);
	string accountBalance = std::to_string(it->second)+"\r\n";
	string onlineCount = std::to_string(login_list.size())+"\r\n";
	string onlineList;
	unordered_map<string,MyAddr>::iterator jt = login_list.begin();
	for(jt;jt!= login_list.end();jt++){
		onlineList += jt->second.user_Name+"#"+jt->second.user_IP+"#"+jt->second.user_PORT+"\r\n";
	}

	return accountBalance + onlineCount + onlineList;
}
Action Decide(vector<string> &v)
{
	if(v.size() == 1 && v[0] == "Exit")
		return Action::EXIT;
	else if(v.size() == 1 && v[0] == "List")
		return Action::LIST;
	else if(v.size() == 2)
		return Action::LOGIN;
	else if(v.size() == 3 && v[0] == "REGISTER")
		return Action::REGISTER;
	else if(v.size() == 4 && v[0] =="CONFIRM")
		return Action::TRANSACTION;
	return Action::UNKNOWN;
}
// read reg_deposit
// write reg_deposit
bool Register(string userAccountName,string depositAmount)
{
	unordered_map<string,int>::iterator it = reg_deposit.find(userAccountName);
	if(it != reg_deposit.end())
		return false;
	reg_deposit.insert(std::pair<string, int>(userAccountName, stoi(depositAmount)));
	// debug section
	//cout << "reg list"<<endl;
	//for(it=reg_deposit.begin() ;it != reg_deposit.end();it++)
	//	cout << it->first <<" / "<<it->second<<endl;
	return true;
}
// read reg_deposit
// 
bool Login(string userAccountName,string portNum)
{
	unordered_map<string,int>::iterator it = reg_deposit.find(userAccountName);
	unordered_map<string, MyAddr>::iterator jt = login_list.find(userAccountName);
	bool reg_yet = false;
	bool login_yet = false;
	if(it != reg_deposit.end())
		reg_yet = true;
	if(jt != login_list.end())
		login_yet = true;
	return (reg_yet && !login_yet);
}
// write login_list
// 
bool Exit(string user_name)
{
	login_list.erase(user_name);
	return true;
}
// write reg_deposit
bool ConfirmTransaction(string sander,string payAmount,string receiver)
{
	unordered_map<string,int>::iterator it = reg_deposit.find(sander);
	unordered_map<string,int>::iterator jt = reg_deposit.find(receiver);
	if(it == reg_deposit.end()){
		cerr<<"sender not found"<<endl;
		return false;
	}
	if(jt == reg_deposit.end()){
		cerr<<"receiver not found"<<endl;
		return false;
	}
	it->second -= stoi(payAmount);
	jt->second += stoi(payAmount);
	return true;
	
}







