#include<winsock.h>
#include<iostream>
#include "AES.h"
#include "BigInteger.h"
#include "EncryptDecrypt.h"
#include "RSA.h"
#pragma comment(lib,"ws2_32.lib")

using namespace std;

void initialization();

char* initialization2();

char key1[128 / 4];

int main(){
	//定义长度变量
	int send_len = 0;
	int recv_len = 0;
	int len = 0;
	//定义发送缓冲区和接受缓冲区
	char send_buf[200];
	char recv_buf[200];
	//定义服务端套接字，接受请求套接字
	SOCKET s_server;
	SOCKET s_accept;
	//服务端地址客户端地址
	SOCKADDR_IN server_addr;
	SOCKADDR_IN accept_addr;
	initialization();
	//填充服务端信息
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(9999);
	//建立缓冲区
	char buf2[64];

	//创建套接字
	s_server = socket(AF_INET, SOCK_STREAM, 0);
	if (bind(s_server, (SOCKADDR *)&server_addr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		cout << "套接字绑定失败！" << endl;
		WSACleanup();
	}
	//else {
	//	cout << "套接字绑定成功！" << endl;
	//}
	//设置套接字为监听状态
	if (listen(s_server, SOMAXCONN) < 0) {
		cout << "设置监听状态失败！" << endl;
		WSACleanup();
	}
	else {
		cout << "设置监听状态成功！" << endl;
	}
	cout << "服务端正在监听连接，请稍候...." << endl;
	//接受连接请求
	len = sizeof(SOCKADDR);
	s_accept = accept(s_server, (SOCKADDR *)&accept_addr, &len);
	if (s_accept == SOCKET_ERROR) {
		cout << "连接失败！" << endl;
		WSACleanup();
		return 0;
	}
	cout << "连接建立，准备接受数据" << endl;


	//接收数据
	while (1) {
		recv_len = recv(s_accept, recv_buf, 100, 0);
		cout << "本次接受的信息是:" << endl;;
		if (recv_len < 0) {
			cout << "接受失败！" << endl;
			break;
		}
		else {
			cout << "客户端信息:" << recv_buf << endl;
		}
		//这里输入公钥加密的对称密钥及对称密钥加密的明文
		EncryptDecrypt encrypt_decrypt;
		encrypt_decrypt.setNandE(recv_buf);
		strcpy(buf2, initialization2());
		strcpy(send_buf, encrypt_decrypt.encrypt(key1));
		encrypt_decrypt.getEnvelop(send_buf, buf2);
		//发送到客户端
		send_len = send(s_accept, send_buf, 100, 0);
		if (send_len < 0) {
			cout << "发送失败！" << endl;
			break;
		}
	}
	//关闭套接字
	closesocket(s_server);
	closesocket(s_accept);
	//释放DLL资源
	WSACleanup();
	return 0;
	}

	void initialization()
	{
		WORD w_req = MAKEWORD(2, 2);
		WSADATA wsadata;
		int err = WSAStartup(w_req, &wsadata);
		if (err) {
			cout << "初始化套接字库失败" << endl;
		}
		//else {
		//	cout << "初始化套接字库成功！" << endl;
		//}
		if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wHighVersion) != 2) {
			cout << "套接字版本不符" << endl;
			WSACleanup();
		}
		//else {
		//	cout << "套接字版本正确" << endl;
		//}
	}

	//创建对称密钥
	char* initialization2()
	{
		//初始化12345678
		for (int i = 0; i < 32; i++) { i >= 8 ? key1[i] = 0 : key1[i] = i + 1 + 48; }
		key1[31] = 0;

		//建立AES对称密钥
		unsigned char key[] = {
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		};//128位，16字节
		char str[32] = "NPU";
		unsigned char st[32];
		char buf2[100];
		AES aes(key);
		int j;
		aes.Cipher((void *)str);
		for (j = 0; j < 32; j++) st[j] = str[j];
		aes.convertUnCharToStr(buf2, st, 32);
		buf2[64] = '\0';
		return buf2;
	}