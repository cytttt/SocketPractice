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

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#define BUFF_SIZE 1024
#define BACKLOG 5

using namespace std;
// *********** Global variables *********** //
//char *END = nullptr; // use to stop thread
const string LOGIN_FAIL = "220 AUTH_FAIL";
const int CYPHER_MAX = 256;
const int CONFIRM_MAX = 13;
const int CYPHER_MAX_PADDING = 244;
int *server_sockfd;
SSL * server_ssl;
const SSL_METHOD      *meth;
X509   *client_cert = NULL;

// private key and certificate
RSA *rsa_private;

// --------------------------
// ************ Enum & Struct ************ //
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
SSL_CTX *InitClientCTX()
{
	SSL_CTX *ctx;
	/* SSL 庫初始化 */
	SSL_library_init();
	/* 載入所有 SSL 演算法 */
	OpenSSL_add_all_algorithms();
	/* 載入所有 SSL 錯誤訊息 */
	SSL_load_error_strings();
	/* 以 SSL V2 和 V3 標準相容方式產生一個 SSL_CTX ，即 SSL Content Text */
	ctx = SSL_CTX_new(SSLv23_client_method());
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
struct MyAddr
{
	string user_Name;
	string user_IP;
	string user_PORT;
};
// ********** Utility function ********** //
bool is_number(string &str);
Action checkCmd(string str);
static void usage();
std::vector<string> parsing(string str, string deli);
void *listeningThread(void *pName);
bool outputList(string listInfo);
// ********** Command function ********** //
bool Register(int sockfd, string userAccountName, string depositAmount,SSL* ssl);
bool Login(int sockfd, string userAccountName, string portName, vector<MyAddr> &v, string &cName, bool &loginOrNot, pthread_t &tid,SSL* ssl);
bool List(int sockfd, vector<MyAddr> &v,SSL* ssl);
bool Exit(int sockfd,SSL* ssl);
bool Transaction(string userAccountName, string payAmount, string payeeAccountName, vector<MyAddr> &v,SSL* ssl);

int main(int argc, char *argv[])
{
	// FILE *fp1; // crt
	// FILE *fp2; // key
	// if((fp1=fopen("client.crt","r"))==NULL){
    //       printf("open file error!!\n");
    //       system("PAUSE");
    //       exit(0);
    // }  
	// if((fp2=fopen("client.key","r"))==NULL){
    //       printf("open file error!!\n");
    //       system("PAUSE");
    //       exit(0);
    // }  
	SSL_CTX *ctx = InitClientCTX();
	SSL *ssl;
	LoadCertificates(ctx,"client.crt","client.key");
	FILE *p_key = fopen("client.key", "r");
    rsa_private = PEM_read_RSAPrivateKey(p_key, 0, 0, 0);
	// ********** Variables ********** //
	string str;
	bool exits = false;
	Action action = Action::UNKNOWN;
	char tmpBuffer[BUFF_SIZE] = {0};
	vector<MyAddr> vec;
	pthread_t tid_child;
	bool loginOrNot = false;
	string clientName;
	int sockfd = 0;
	int server_port = 0;
	string server_ip;
	// ******************************* //
	if (argc != 3)
	{
		cerr << ": usage:  ./client <portName>" << endl;
		cerr << ": portName is an integer between 1024~65535" << endl;
		return 0;
	}
	else
	{
		string tmp = argv[2];
		if (!is_number(tmp))
		{
			cerr << ": portName is an integer between 1024~65535" << endl;
			return 0;
		}
		if (stoi(tmp) < 1024 || stoi(tmp) > 65536)
		{
			cerr << ": portName is an integer between 1024~65535" << endl;
			return 0;
		}
		server_port = stoi(tmp);
	}
	server_ip = argv[1];
	cout << ": server IP   " << server_ip << endl;
	cout << ": server port " << server_port << endl;
	// ******************************* //

	// socket
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}
	// Convert IPv4 and IPv6 addresses from text to binary form
	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port);
	if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0)
	{
		cout << "\nInvalid address/ Address not supported \n";
		return -1;
	}
	if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		cout << "\nConnection Failed \n";
		return -1;
	}
	else
	{
		// TODO
		ssl = SSL_new(ctx);
    	SSL_set_fd(ssl, sockfd);
   		/* 建立 SSL 連線 */
    	if (SSL_connect(ssl) == -1)
    	{
        	ERR_print_errors_fp(stderr);
        	//continue;
    	}
    	else
    	{
        	printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        	ShowCerts(ssl);
    	}
		SSL_read(ssl, tmpBuffer, BUFF_SIZE);
		//recv(sockfd, tmpBuffer, BUFF_SIZE, 0);
		cout << "-> server: " << std::string(tmpBuffer) << endl;
	}
	server_ssl=ssl;
	usage();
	server_sockfd = new int(sockfd);
	// busy waiting for command
	while (!cin.eof())
	{
		getline(std::cin, str);
		// parsing
		vector<string> parsed = parsing(str, " ");
		action = checkCmd(parsed[0]);
		// action
		switch (action)
		{
		case Action::REGISTER:
			if (!Register(sockfd, parsed[1], parsed[2],ssl))
				cerr << ": register fail" << endl;
			break;
		case Action::LOGIN:
			if (!Login(sockfd, parsed[1], parsed[2], vec, clientName, loginOrNot, tid_child,ssl))
				cerr << ": login fail(not register yet)" << endl;
			break;
		case Action::LIST:
			if (!List(sockfd, vec,ssl))
				cerr << ": list fail" << endl;
			break;
		case Action::TRANSACTION:
			if (!Transaction(clientName, parsed[1], parsed[2], vec,ssl))
				cerr << ": transaction fail" << endl;
			break;
		case Action::EXIT:
			if (!Exit(sockfd,ssl))
				cerr << ": exit fail" << endl;
			else
				exits = true;
			break;
		default:
			cerr << ": unknown command !!" << endl;
			usage();
		}
		// exits
		if (exits)
			break;
	}
	fclose(p_key);
	// fclose(fp1);
	// fclose(fp2);
	return 0;
}
// ************************************************** //
Action checkCmd(string str)
{
	Action res;

	if (str == "reg")
		res = Action::REGISTER;
	else if (str == "login")
		res = Action::LOGIN;
	else if (str == "list")
		res = Action::LIST;
	else if (str == "trans")
		res = Action::TRANSACTION;
	else if (str == "exit")
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

void *listeningThread(void *pName)
{
	// phase III *****************
	SSL_CTX *ctx_l = InitServerCTX();
	LoadCertificates(ctx_l,"otherclient.crt","otherclient.key");
	X509 *client_cert_l = NULL;
    RSA *sender_RSA;
	SSL_CTX_set_verify(ctx_l, SSL_VERIFY_PEER, NULL);// 要求 sender's certificate
    SSL_CTX_load_verify_locations(ctx_l, "client.crt", NULL);
	// ******************************

	string portName = (char *)pName;
	int *client_sockfd;
	client_sockfd = new int(0); // initialize
	struct sockaddr_in address;
	int addrlen = sizeof(address);
	int new_socket = 0;

	// Creating socket file descriptor
	if ((*client_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		cerr << ": socket failed" << endl;
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(stoi(portName));

	if (::bind(*client_sockfd, (struct sockaddr *)&address, sizeof(address)) < 0)
	{
		cerr << ": bind failed" << endl;
		exit(EXIT_FAILURE);
	}
	if (listen(*client_sockfd, BACKLOG) < 0)
	{
		cerr << ": listen" << endl;
		exit(EXIT_FAILURE);
	}
	// ******************
	char *grateful[2] = {0};
	grateful[0] = "Thank you !";
	grateful[1] = "m(_ _)m";
	while (true)
	{
		//cout <<"where r you"<<endl;
		if ((new_socket = accept(*client_sockfd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
		{
			cerr << "accept" << endl;
			exit(EXIT_FAILURE);
		}
		/* 將連線使用者的 socket 加入到 SSL */
			
    	SSL *ssl_l = SSL_new(ctx_l);
    	SSL_set_fd(ssl_l, new_socket);
    	/* 建立 SSL 連線 */
    	if (SSL_accept(ssl_l) == -1)
    	{
        	ERR_print_errors_fp(stderr);
        	close(new_socket);
        	//continue;
    	}
		client_cert_l = SSL_get_peer_certificate(ssl_l);
		EVP_PKEY *sender_public = X509_get_pubkey(client_cert_l);
		sender_RSA = EVP_PKEY_get1_RSA(sender_public);

		// cout <<"where r you2"<<endl;
		char cbuffer[CYPHER_MAX] = {0};
		char plain[CYPHER_MAX] ={0};
		SSL_read(ssl_l,cbuffer,CYPHER_MAX);
		//recv(new_socket, cbuffer, BUFF_SIZE, 0);
		//string buffer = cbuffer;
		//cout << "-> msg: " << buffer << endl;
		RSA_public_decrypt(CYPHER_MAX,(unsigned char *)cbuffer,(unsigned char *)plain,sender_RSA,RSA_PKCS1_PADDING);
		string plaintext = plain;
		cout << "-msg: " << plaintext << endl;
		cout << "-raw msg: " << std::string(cbuffer) << endl;
		
		//thank section
		int i = rand() % 2;
		SSL_write(ssl_l,grateful[i],strlen(grateful[i]));
		//send(new_socket, grateful[i], strlen(grateful[i]), 0);
		//unsigned char cipher1[CYPHER_MAX_PADDING];
		//unsigned char cipher2[CYPHER_MAX_PADDING];
		char half1_cypher[CYPHER_MAX/2], half2_cypher[CYPHER_MAX/2];
        char first_cypher[CYPHER_MAX], second_cypher[CYPHER_MAX], full_message[CYPHER_MAX*3+1];
		for(int i = 0; i<CYPHER_MAX; i++)
        {
            //printf("i = %d, s = %c\n", i, cypher_message[i]);
            if(i<CYPHER_MAX/2)
                half1_cypher[i] = (cbuffer[i]);
            else
            {
                half2_cypher[i-CYPHER_MAX/2] = cbuffer[i];
                //printf("half2: %c\n", half2_cypher[i-MAX256/2]);
            }
        }
		int flen = (128+1) * sizeof(char);
        RSA_private_encrypt(flen, (unsigned char *)half1_cypher, (unsigned char *)first_cypher, rsa_private, RSA_PKCS1_PADDING);
        RSA_private_encrypt(flen, (unsigned char *)half2_cypher, (unsigned char *)second_cypher, rsa_private, RSA_PKCS1_PADDING);
		cout << "-cypher1 : " << std::string(first_cypher) << endl;
		cout << "-cypher2 : " << std::string(second_cypher) << endl;
        //SSL_write(server_ssl, plain, CYPHER_MAX);
        
		// send ack to server (phase II)
		char cbuffer2[CONFIRM_MAX+2] = {0};
		string server_req = std::string("CONFIRM#") + plaintext;
		SSL_write(server_ssl,server_req.c_str(),CYPHER_MAX);
		SSL_write(server_ssl, first_cypher, CYPHER_MAX);
        SSL_write(server_ssl, second_cypher, CYPHER_MAX);
		SSL_read(server_ssl,cbuffer2,CONFIRM_MAX+2);
		//send(*server_sockfd, server_req.c_str(), strlen(server_req.c_str()), 0);
		//recv(*server_sockfd, cbuffer2, BUFF_SIZE, 0);
		cout << "-> server: " << std::string(cbuffer2);
		//
		//
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

bool outputList(string listInfo)
{
	vector<string> vtmp = parsing(listInfo, " #\r\n");
	string spacing = "    ";
	int name_offset = 10;
	int ip_offset = 20;
	for (int i = 0; i < (vtmp.size() - 2) / 3; i++)
	{
		if (vtmp[3 * i + 2].size() > name_offset)
			name_offset = vtmp[3 * i + 2].size();
		if (vtmp[3 * i + 2 + 1].size() > ip_offset)
			ip_offset = vtmp[3 * i + 2 + 1].size();
	}

	cout << spacing << "Account balance: " << vtmp[0] << endl;
	cout << spacing << "Online users   : " << vtmp[1] << endl;
	cout << spacing << "Online list    : " << endl;
	// draw table
	cout << spacing << std::string(name_offset + ip_offset + 4 + 6, '-') << endl;
	cout << spacing + "|" << setw(name_offset) << "Name"
		 << "|" << setw(ip_offset) << "IP address"
		 << "|" << setw(6) << "Port"
		 << "|" << endl;
	cout << spacing << std::string(name_offset + ip_offset + 4 + 6, '-') << endl;
	for (int i = 0; i < (vtmp.size() - 2) / 3; i++)
		cout << spacing + "|" << setw(name_offset) << vtmp[3 * i + 2] << "|" << setw(ip_offset) << vtmp[3 * i + 2 + 1] << "|" << setw(6) << vtmp[3 * i + 2 + 2] << "|" << endl;
	cout << spacing << std::string(name_offset + ip_offset + 4 + 6, '-') << endl;

	return true;
}
// ******************************************************************************* //
bool Register(int sockfd, string userAccountName, string depositAmount,SSL* ssl)
{
	if (!is_number(depositAmount))
	{
		cerr << ": depositAmount is not a number !" << endl;
		return false;
	}
	char cbuffer[BUFF_SIZE] = {0};
	string msg = std::string("REGISTER") + "#" + userAccountName + "#" + depositAmount;
	SSL_write(ssl,msg.c_str(),strlen(msg.c_str()));
	SSL_read(ssl,cbuffer,BUFF_SIZE);
	//send(sockfd, msg.c_str(), strlen(msg.c_str()), 0); // send request
	//recv(sockfd, cbuffer, BUFF_SIZE, 0);			   // get response
	string buffer = cbuffer;
	cout << "-> server: " << buffer;
	// pasrse response
	char *ptr = strtok(cbuffer, " \n");
	string statusCode = ptr;

	if (statusCode == "100")
		return true;
	else
		return false;
}
bool Login(int sockfd, string userAccountName, string portName, vector<MyAddr> &v, string &cName, bool &loginOrNot, pthread_t &tid,SSL* ssl)
{
	if (!is_number(portName))
	{
		cerr << ": portName is not a number!" << endl;
		return false;
	}
	if (stoi(portName) < 1024 || stoi(portName) > 65536)
	{
		cerr << ": portName is not a number betweeb 1024~65535!" << endl;
		return false;
	}
	char cbuffer[BUFF_SIZE] = {0};

	string msg = userAccountName + "#" + portName;
	SSL_write(ssl,msg.c_str(),strlen(msg.c_str()));
	SSL_read(ssl,cbuffer,BUFF_SIZE);
	//send(sockfd, msg.c_str(), strlen(msg.c_str()), 0); // send request
	//recv(sockfd, cbuffer, BUFF_SIZE, 0);			   // get response
	string buffer = cbuffer;
	if (buffer.find(LOGIN_FAIL) != std::string::npos)
		return false; // catch login error
	if (loginOrNot)
	{
		cout << "-> server: " << buffer << endl;
		return true; // check already login
	}

	// update vector
	vector<string> parsed_list = parsing(buffer, " #\r\n");
	v.clear();
	for (int i = 0; i < (parsed_list.size() - 2) / 3; i++)
	{
		MyAddr tmp = {
			.user_Name = parsed_list[2 + 3 * i],
			.user_IP = parsed_list[2 + 3 * i + 1],
			.user_PORT = parsed_list[2 + 3 * i + 2]};
		v.push_back(tmp);
	}
	char *pName = new char[portName.size()];
	strcpy(pName, portName.c_str());
	pthread_create(&tid, NULL, listeningThread, pName); // threading

	cout << "-> server:\n";
	outputList(buffer); // output list
	loginOrNot = true;
	cName = userAccountName;
	return true;
}

bool List(int sockfd, vector<MyAddr> &v,SSL* ssl)
{
	string msg = "List";
	char cbuffer[BUFF_SIZE] = {0};
	SSL_write(ssl,msg.c_str(),strlen(msg.c_str()));
	SSL_read(ssl,cbuffer,BUFF_SIZE);
	//send(sockfd, msg.c_str(), strlen(msg.c_str()), 0); // send request
	//recv(sockfd, cbuffer, BUFF_SIZE, 0);			   // get response
	string buffer = cbuffer;
	cout << "-> server:\n";
	outputList(buffer);
	// update vector
	vector<string> parsed_list = parsing(buffer, " #\r\n");
	v.clear();
	for (int i = 0; i < (parsed_list.size() - 2) / 3; i++)
	{
		MyAddr tmp = {
			.user_Name = parsed_list[2 + 3 * i],
			.user_IP = parsed_list[2 + 3 * i + 1],
			.user_PORT = parsed_list[2 + 3 * i + 2]};
		v.push_back(tmp);
	}

	return true;
}

bool Exit(int sockfd,SSL* ssl)
{
	string msg = "Exit";
	char cbuffer[BUFF_SIZE] = {0};
	SSL_write(ssl,msg.c_str(),strlen(msg.c_str()));
	SSL_read(ssl,cbuffer,BUFF_SIZE);
	//send(sockfd, msg.c_str(), strlen(msg.c_str()), 0); // send request
	//recv(sockfd, cbuffer, BUFF_SIZE, 0);			   // get response
	string buffer = cbuffer;
	cout << "-> server: " << buffer;

	return true;
}

bool Transaction(string userAccountName, string payAmount, string payeeAccountName, vector<MyAddr> &v,SSL* ssl)
{
	if (!is_number(payAmount))
	{
		cerr << ": payAmount is not a number !" << endl;
		return false;
	}
	string payee_IP;
	string payee_PORT;
	bool found = false;
	vector<MyAddr>::iterator it = v.begin();
	for (it; it != v.end(); it++)
	{
		if (it->user_Name == payeeAccountName)
		{
			found = true;
			payee_IP = it->user_IP;
			payee_PORT = it->user_PORT;
		}
	}
	if (found == false)
	{
		cerr << "user not found" << endl;
		return false;
	}
	// connectdo phase III
	SSL_CTX *sender_ctx = InitClientCTX();
	SSL *sender_ssl;
	LoadCertificates(sender_ctx,"client.crt","client.key");
	// connectdo!
	char cbuffer[BUFF_SIZE] = {0};
	int payee_sockfd = 0;
	if ((payee_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}
	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(stoi(payee_PORT));
	if (inet_pton(AF_INET, payee_IP.c_str(), &server_addr.sin_addr) <= 0)
	{
		cout << "\nInvalid address/ Address not supported \n";
		return -1;
	}
	if (connect(payee_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		cout << "\nConnection Failed \n";
		return -1;
	}
	else{
		// TODO
		sender_ssl = SSL_new(sender_ctx);
    	SSL_set_fd(sender_ssl, payee_sockfd);
   		/* 建立 SSL 連線 */
    	if (SSL_connect(sender_ssl) == -1)
    	{
        	ERR_print_errors_fp(stderr);
        	//continue;
    	}
    	else
    	{
        	printf("Connected with %s encryption\n", SSL_get_cipher(sender_ssl));
        	ShowCerts(sender_ssl);
    	}	
	}
	string msg = userAccountName + "#" + payAmount + "#" + payeeAccountName;
	// TODO phase III
	

	unsigned char cypher[CYPHER_MAX_PADDING];
	unsigned char *uc_msg = new unsigned char [ msg.size()+1];
	strcpy((char*)uc_msg,msg.c_str()); 
	int flen = (strlen((char*)uc_msg)+1) * sizeof(unsigned char);
	int do_encrypt = RSA_private_encrypt(flen,uc_msg,cypher,rsa_private,RSA_PKCS1_PADDING);
	SSL_write(sender_ssl,cypher,CYPHER_MAX);
	SSL_read(sender_ssl,cbuffer,BUFF_SIZE);
	//send(payee_sockfd, msg.c_str(), strlen(msg.c_str()), 0); // send request
	//recv(payee_sockfd, cbuffer, BUFF_SIZE, 0);				 // get response
	cout << "-> " << payeeAccountName << ": " << std::string(cbuffer) << endl;
	// do something phase II
	char cbuffer2[CONFIRM_MAX+2] = {0};
	SSL_read(ssl,cbuffer2,CONFIRM_MAX+2);
	//recv(*server_sockfd, cbuffer2, BUFF_SIZE, 0);
	cout << "-> server: " << std::string(cbuffer2);
	//
	//
	return true;
}
