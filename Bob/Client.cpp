#include<iostream>
#include<winsock.h>
#include <ctype.h>
#include "RSA.h"
#include "BigInteger.h"
#include "EncryptDecrypt.h"
#include "AES.h"
#pragma comment(lib,"ws2_32.lib")


using namespace std;
void initialization();

void initialization2(std::string, char*);

int main() {
	//定义长度变量
	int send_len = 0;
	int recv_len = 0;
	//定义发送缓冲区和接受缓冲区
	char send_buf[200];
	char recv_buf[200];
	//定义服务端套接字，接受请求套接字
	SOCKET s_server;
	//服务端地址客户端地址
	SOCKADDR_IN server_addr;
	initialization();
	//填充服务端信息
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(9999);
	//创建套接字
	s_server = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(s_server, (SOCKADDR *)&server_addr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		cout << "服务器连接失败！" << endl;
		WSACleanup();
	}
	else {
		cout << "服务器连接成功！" << endl;
	}
	//生成公钥和私钥
	EncryptDecrypt encrypt_decrypt;
	encrypt_decrypt.reset();
	encrypt_decrypt.getPublicKey();
	printf("\n\n");
	//发送,接收数据
	while (1) {
		cout << "本次信息是:\n";
		//cin >> send_buf;

		//std::cout << encrypt_decrypt.getRSA().n.data[0] << std::endl;;
		strcpy(send_buf , encrypt_decrypt.getPublicKey().c_str());
		
		//发送
		send_len = send(s_server, send_buf, 100, 0);
		if (send_len < 0) {
			cout << "发送失败！" << endl;
			break;
		}
		recv_len = recv(s_server, recv_buf, 100, 0);
		if (recv_len < 0) {
			cout << "接受失败！" << endl;
			break;
		}
		else {
			cout << "服务端信息:" << recv_buf << endl;
			//这里还得改  已改完
			//接受到的消息是公钥加密的对称密钥和对称密钥加密的密文
			string s(recv_buf);
			int pos = s.find('+');
			string s1 = s.substr(0, pos), s2 = s.substr(pos + 1);
			char symkey[1000];
			strcpy(symkey,encrypt_decrypt.decrypt(s1));
			initialization2(s2,symkey);
		}

		getchar();
		printf("\n");
	}
	//关闭套接字
	closesocket(s_server);
	//释放DLL资源
	WSACleanup();
	system("pause");
	return 0;

}
void initialization() {
	//初始化套接字库
	WORD w_req = MAKEWORD(2, 2);//版本号
	WSADATA wsadata;
	int err;
	err = WSAStartup(w_req, &wsadata);
	if (err != 0) {
		cout << "初始化套接字库失败！" << endl;
	}
	//else {
	//	cout << "初始化套接字库成功！" << endl;
	//}
	//检测版本号
	if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wHighVersion) != 2) {
		cout << "套接字库版本号不符！" << endl;
		WSACleanup();
	}
	//else {
	//	cout << "套接字库版本正确！" << endl;
	//}
	//填充服务端地址信息

}

void initialization2(std::string s,char* symkey)
{
	//unsigned char key[] = {
	//0x01, 0x02, 0x03, 0x04,
	//0x05, 0x06, 0x07, 0x08,
	//0x00, 0x00, 0x00, 0x00,
	//0x00, 0x00, 0x00, 0x00
	//};//128位，16字节
	unsigned char key[16];
	//建立AES对称密钥  这个要自己解析
	int i;
	for (i = 0; symkey[i] != '\0'; i++)
	{
		if(isalpha(symkey[i]))  tolower(symkey[i]);
		symkey[i] > 57 ? key[i] = 0x00 + symkey[i] - 'a' :key[i] = 0x00 + symkey[i] - '0';
	}
	while (i < 16) key[i++] = 0x00;
	AES aes(key);
	char str[65];
	strcpy(str, s.c_str());
	unsigned char unchar[65];
	aes.convertStrToUnChar(str, unchar);
	//for (int i = 0; i < 32; i++)
	//{
	//	printf("%x ", unchar[i]);
	//}
	printf("\n");
	aes.InvCipher((void *)unchar, 21);
	//aes.InvCipher((void *)str, 21);
	//for (int j = 0; j < 32; j++)printf("%X ", (unsigned char)str[j]);
	printf("最后的明文是：");
	for (int i = 0; unchar[i] != '\0'; i++) printf("%c", unchar[i]);
	printf("\n");
}