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
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#define BUFF_SIZE 1024
#define THREAD 32
#define QUEUE 256
#define BACKLOG 5

using namespace std;
// ************* Enum & Struct ************* //
SSL_CTX *InitServerCTX()
{
	SSL_CTX *ctx;
	/* SSL 庫初始化 */
	SSL_library_init();
	/* 載入所有 SSL 演算法 */
	OpenSSL_add_all_algorithms();
	/* 載入所有 SSL 錯誤訊息 */
	SSL_load_error_strings();
	/* 以 SSL V2 和 V3 標準相容方式產生一個 SSL_CTX ，即 SSL Content Text */
	ctx = SSL_CTX_new(SSLv23_server_method());
	/* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 單獨表示 V2 或 V3標準 */
	if (ctx == NULL)
	{
		ERR_print_errors_fp(stdout);
		abort();
	}
	return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* 載入使用者的數字證書， 此證書用來發送給客戶端。 證書裡包含有公鑰 */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 載入使用者私鑰 */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 檢查使用者私鑰是否正確 */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("Digital certificate information:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Certificate: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificate information！\n");
}
enum Action
{
	REGISTER,
	LOGIN,
	LIST,
	TRANSACTION,
	EXIT,
	UNKNOWN
};
struct SSl_sockfd{
	SSL * ssl;
	int sockfd;
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
const string CONFIRM = "Confirm!_O\r\n";
const string CONFIRMX = "Confirm!_X\r\n";
pthread_mutex_t mutexX;
std::unordered_map<std::string, int> reg_deposit;
std::unordered_map<std::string, MyAddr> login_list;
std::unordered_map<std::string, int> name_sockfd; // only login
std::unordered_map<std::string,SSL*> name_ssl;
std::unordered_map<std::string,RSA*> name_rsa;
// ********** Utility function *********** //
bool is_number(string &str);
std::vector<string> parsing(string str, string deli);
Action Decide(vector<string> &v);
string getList(string user_name);
// *********** thread function *********** //
//void user_thread(void *socket_ptr);
void user_thread(void *sock_ptr);
bool Register(string userAccountName, string depositAmount);
bool Login(string userAccountName, string portNum);
bool Exit(string user_name);
bool ConfirmTransaction(string sander, string payAmount, string receiver,SSL* ssl);

int main(int argc, char *argv[])
{
	SSL_CTX *ctx = InitServerCTX();
	LoadCertificates(ctx,"server.crt","server.key");
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);// 要求 sender's certificate
    SSL_CTX_load_verify_locations(ctx, "../client/client.crt", NULL);
	// *******************************
	string portNum;
	cout << "Enter Port for server to listening: ";
	cin >> portNum;
	// initialize
	int server_sockfd = 0;
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(stoi(portNum));
	int addrlen = sizeof(address);
	char buffer[BUFF_SIZE] = {0};
	std::vector<pthread_t> tid_vec;
	pthread_mutex_init(&mutexX, NULL);
	//
	threadpool_t *pool;
	assert((pool = threadpool_create(THREAD, QUEUE, 0)) != NULL);
	cout << "Pool started with " << THREAD << " threads and queue size of " << QUEUE << '\n';
	// constant string
	const string greeting = "connection accepted!\r\n";
	// Creating socket file descriptor
	if ((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		cerr << ": socket failed" << endl;
		exit(EXIT_FAILURE);
	}
	if (::bind(server_sockfd, (struct sockaddr *)&address, sizeof(address)) < 0)
	{
		cerr << ": bind failed" << endl;
		exit(EXIT_FAILURE);
	}
	if (listen(server_sockfd, BACKLOG) < 0)
	{
		cerr << ": listen failed" << endl;
		exit(EXIT_FAILURE);
	}
	// ******************
	while (true)
	{
		//cout << "@"<<endl;
		int *new_socket = new int(0);
		if ((*new_socket = accept(server_sockfd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
		{
			cerr << "accept failed" << endl;
			exit(EXIT_FAILURE);
		}
		else{
			/* 將連線使用者的 socket 加入到 SSL */
			SSl_sockfd *tmp  = new SSl_sockfd;
			//cerr<<"line 185" <<endl;
        	SSL *ssl = SSL_new(ctx);
        	SSL_set_fd(ssl, *new_socket);
        	/* 建立 SSL 連線 */
        	if (SSL_accept(ssl) == -1)
        	{
            	ERR_print_errors_fp(stderr);
            	close(*new_socket);
            	//continue;
        	}
        	//ShowCerts(ssl);
			SSL_write(ssl,greeting.c_str(),strlen(greeting.c_str()));
			//send(*new_socket, greeting.c_str(), strlen(greeting.c_str()), 0); // send greeting


			// ***** create thread for this user  ***** //

			// using threadpool ~~
			//pthread_t  tid;
			//tid_vec.push_back(tid);
			//pthread_create(&tid_vec[tid_vec.size()-1],NULL,user_thread,new_socket);
			//cerr<<"line 206"<<endl;
			// using ssl
			//cerr<<"line 209"<<endl;
			tmp->ssl = ssl;
			//cerr<<"line 210"<<endl;
			tmp->sockfd = *new_socket;
			//cerr<<"line 211"<<endl;
			threadpool_add(pool, &user_thread, tmp, 0);
			//cerr<<"line 212"<<endl;
			//threadpool_add(pool,&user_thread, ssl,0);
		}
		
	}
}

bool is_number(string &str)
{
	if (str.size() == std::string::npos)
		return false;
	for (int i = 0; i < str.size(); i++)
		if (!std::isdigit(str[i]))
			return false;
	return true;
}

std::vector<string> parsing(string str, string deli)
{
	std::vector<string> res;
	char *cstr = new char[str.size() + 1];
	strcpy(cstr, str.c_str());
	//
	char *cdeli = new char[deli.size()];
	strcpy(cdeli, deli.c_str());
	char *ptr;
	ptr = strtok(cstr, cdeli);
	while (ptr != nullptr)
	{
		string tmp = ptr;
		res.push_back(tmp);
		ptr = strtok(nullptr, cdeli);
	}
	return res;
}
void user_thread(void *ssl_sockfd)
{	
	//cerr<<"line 248"<<endl;
	SSl_sockfd *cur = (SSl_sockfd *)ssl_sockfd; 
	SSL* ssl = cur->ssl;
	int sockfd = cur->sockfd;
	//int sockfd = *(int *)socket_ptr; // socker to listen
	string user_name;				 // if login
	bool login_yet = false;
	bool end = false;
	// get user IP
	struct sockaddr_in user_addr;
	int addrlen = sizeof(user_addr);
	getpeername(sockfd, (struct sockaddr *)&user_addr, (socklen_t *)&addrlen);
	string user_ip = inet_ntoa(user_addr.sin_addr);

	while (!end)
	{
		//cerr<<"line 264"<<endl;
		char cbuffer[256] = {0};
		int checkpoint = SSL_read(ssl,cbuffer,256);
		//int checkpoint = recv(sockfd, cbuffer, BUFF_SIZE, 0);
		if (checkpoint <= 0)
		{
			cerr << ": A user disconnected unexpectedly :(" << endl;
			end = true;
			break;
			//pthread_exit(NULL);
		}
		//cerr<<"line 275"<<endl;
		// parsing
		string buffer = cbuffer;
		cout << "msg: " << buffer << endl;
		std::vector<string> vec;
		vec = parsing(buffer, "#\r\n");
		//for(int i = 0 ; i< vec.size();i++){
		//	cerr<<i<<" "<<vec[i]<<endl;
		//}
		Action action = Decide(vec);
		//
		switch (action)
		{
		case Action::REGISTER:
			if (Register(vec[1], vec[2])){
				SSL_write(ssl,REG_SUC.c_str(), strlen(REG_SUC.c_str()));
				//send(sockfd, REG_SUC.c_str(), strlen(REG_SUC.c_str()), 0);
			}
			else{
				SSL_write(ssl,REG_SUC.c_str(), strlen(REG_SUC.c_str()));
				//send(sockfd, REG_FAIL.c_str(), strlen(REG_FAIL.c_str()), 0);
			}
			break;
		case Action::LOGIN:
			if (login_yet)
			{
				SSL_write(ssl, LOGIN_TWICE.c_str(), strlen(LOGIN_TWICE.c_str()));
				//send(sockfd, LOGIN_TWICE.c_str(), strlen(LOGIN_TWICE.c_str()), 0);
			}
			else
			{
				if (Login(vec[0], vec[1]))
				{
					// write login_list
					MyAddr tmp = {
						.user_Name = vec[0],
						.user_IP = user_ip,
						.user_PORT = vec[1]};
					login_list.insert(std::pair<string, MyAddr>(vec[0], tmp));
					//
					login_yet = true;
					user_name = vec[0];
					name_sockfd.insert(std::pair<string, int>(vec[0], sockfd));
					// phase III store crt
					name_ssl.insert(std::pair<string,SSL*>(vec[0],ssl));
					X509* client_crt = SSL_get_peer_certificate(ssl);
					EVP_PKEY * sender_public = X509_get_pubkey(client_crt);
					name_rsa.insert(std::pair<string,RSA*>(vec[0],EVP_PKEY_get1_RSA(sender_public)));

					string res = getList(user_name);
					SSL_write(ssl,res.c_str(),strlen(res.c_str()));
					//send(sockfd, res.c_str(), strlen(res.c_str()), 0);
				}
				else{
					SSL_write(ssl,LOGIN_FAIL.c_str(),strlen(LOGIN_FAIL.c_str()));
					//send(sockfd, LOGIN_FAIL.c_str(), strlen(LOGIN_FAIL.c_str()), 0);
				}
			}
			break;
		case Action::LIST:
			if (!login_yet)
			{
				SSL_write(ssl, LISTANDEXIT_FAIL.c_str(), strlen(LISTANDEXIT_FAIL.c_str()));
				//send(sockfd, LISTANDEXIT_FAIL.c_str(), strlen(LISTANDEXIT_FAIL.c_str()), 0);
			}
			else
			{
				string res = getList(user_name);
				//cout <<res<<endl;
				SSL_write(ssl,res.c_str(),strlen(res.c_str()));
				//send(sockfd, res.c_str(), strlen(res.c_str()), 0);
			}
			break;
		case Action::TRANSACTION:
			//cout <<"not implement yet QQ"<<endl;
			
			if(ConfirmTransaction(vec[1], vec[2], vec[3],ssl)){
				SSL_write(ssl,CONFIRM.c_str(),strlen(CONFIRM.c_str()));
				SSL_write(name_ssl.find(vec[1])->second,CONFIRM.c_str(),strlen(CONFIRM.c_str()));
			}
			else{
				SSL_write(ssl,CONFIRMX.c_str(),strlen(CONFIRMX.c_str()));
				SSL_write(name_ssl.find(vec[1])->second,CONFIRMX.c_str(),strlen(CONFIRMX.c_str()));
			}
			
			//send(sockfd, CONFIRM.c_str(), strlen(CONFIRM.c_str()), 0);							 // send to payee
			//send(name_sockfd.find(vec[1])->second, CONFIRM.c_str(), strlen(CONFIRM.c_str()), 0); // send to giver
			break;
		case Action::EXIT:
			if (!login_yet)
			{
				SSL_write(ssl,LISTANDEXIT_FAIL.c_str(), strlen(LISTANDEXIT_FAIL.c_str()));
				//send(sockfd, LISTANDEXIT_FAIL.c_str(), strlen(LISTANDEXIT_FAIL.c_str()), 0);
			}
			else
			{
				Exit(user_name);
				SSL_write(ssl,BYE.c_str(), strlen(BYE.c_str()));
				//send(sockfd, BYE.c_str(), strlen(BYE.c_str()), 0);
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
	unordered_map<string, int>::iterator it = reg_deposit.find(user_name);
	string accountBalance = std::to_string(it->second) + "\r\n";
	string onlineCount = std::to_string(login_list.size()) + "\r\n";
	string onlineList;
	unordered_map<string, MyAddr>::iterator jt = login_list.begin();
	for (jt; jt != login_list.end(); jt++)
	{
		onlineList += jt->second.user_Name + "#" + jt->second.user_IP + "#" + jt->second.user_PORT + "\r\n";
	}

	return accountBalance + onlineCount + onlineList;
}
Action Decide(vector<string> &v)
{
	if (v.size() == 1 && v[0] == "Exit")
		return Action::EXIT;
	else if (v.size() == 1 && v[0] == "List")
		return Action::LIST;
	else if (v.size() == 2)
		return Action::LOGIN;
	else if (v.size() == 3 && v[0] == "REGISTER")
		return Action::REGISTER;
	else if (v.size() == 4 && v[0] == "CONFIRM")
		return Action::TRANSACTION;
	return Action::UNKNOWN;
}
// read reg_deposit
// write reg_deposit
bool Register(string userAccountName, string depositAmount)
{
	unordered_map<string, int>::iterator it = reg_deposit.find(userAccountName);
	if (it != reg_deposit.end())
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
bool Login(string userAccountName, string portNum)
{
	unordered_map<string, int>::iterator it = reg_deposit.find(userAccountName);
	unordered_map<string, MyAddr>::iterator jt = login_list.find(userAccountName);
	bool reg_yet = false;
	bool login_yet = false;
	if (it != reg_deposit.end())
		reg_yet = true;
	if (jt != login_list.end())
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
bool ConfirmTransaction(string sander, string payAmount, string receiver,SSL* ssl)
{
	unordered_map<string, int>::iterator it = reg_deposit.find(sander);
	unordered_map<string, int>::iterator jt = reg_deposit.find(receiver);
	if (it == reg_deposit.end())
	{
		cerr << "sender not found" << endl;
		return false;
	}
	if (jt == reg_deposit.end())
	{
		cerr << "receiver not found" << endl;
		return false;
	}
	char cypher1[256], cypher2[256],plain1[256], plain2[256],o_plain[256], t_mesg[256];
	SSL_read(ssl, cypher1, 256); 
    SSL_read(ssl, cypher2, 256);
	cerr<<"cypher1 "<<std::string(cypher1)<<endl;
	cerr<<"cypher2 "<<std::string(cypher2)<<endl;
	int err1 = RSA_public_decrypt(256, (unsigned char *)cypher1, (unsigned char *)plain1, name_rsa.find(receiver)->second, RSA_PKCS1_PADDING);
	int err2 = RSA_public_decrypt(256, (unsigned char *)cypher2, (unsigned char *)plain2, name_rsa.find(receiver)->second, RSA_PKCS1_PADDING);
	cerr<<"err test 1 : "<<err1<<" "<<err2<<endl;
	for(int i = 0; i < 128; i++)
        plain1[i+128] = plain2[i];
	int err3 = RSA_public_decrypt(256, (unsigned char *)plain1, (unsigned char *)o_plain, name_rsa.find(sander)->second, RSA_PKCS1_PADDING);
	cerr<<"err test 2"<<err3<<endl;
	string signature= std::string(o_plain);
	cerr<<"signature " <<signature<<"..."<<endl;
	std::vector<string> vec = parsing(signature, "#\r\n");
	if((vec[0] == sander)&&(vec[1] == payAmount) && (vec[2] == receiver)){
		cerr<<"signature valid!" <<endl;
	}
	else{
		cerr<<"wrong "<<vec[0]<<" "<<vec[1]<<" "<<vec[2]<<endl;
		return false;
	}
	int tmp = stoi(payAmount);
	if(it->second < tmp){
		tmp = it->second;
	}
	it->second -= tmp;
	jt->second += tmp;
	return true;
}
