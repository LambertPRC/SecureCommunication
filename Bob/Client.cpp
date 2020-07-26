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
	//���峤�ȱ���
	int send_len = 0;
	int recv_len = 0;
	//���巢�ͻ������ͽ��ܻ�����
	char send_buf[200];
	char recv_buf[200];
	//���������׽��֣����������׽���
	SOCKET s_server;
	//����˵�ַ�ͻ��˵�ַ
	SOCKADDR_IN server_addr;
	initialization();
	//���������Ϣ
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(9999);
	//�����׽���
	s_server = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(s_server, (SOCKADDR *)&server_addr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		cout << "����������ʧ�ܣ�" << endl;
		WSACleanup();
	}
	else {
		cout << "���������ӳɹ���" << endl;
	}
	//���ɹ�Կ��˽Կ
	EncryptDecrypt encrypt_decrypt;
	encrypt_decrypt.reset();
	encrypt_decrypt.getPublicKey();
	printf("\n\n");
	//����,��������
	while (1) {
		cout << "������Ϣ��:\n";
		//cin >> send_buf;

		//std::cout << encrypt_decrypt.getRSA().n.data[0] << std::endl;;
		strcpy(send_buf , encrypt_decrypt.getPublicKey().c_str());
		
		//����
		send_len = send(s_server, send_buf, 100, 0);
		if (send_len < 0) {
			cout << "����ʧ�ܣ�" << endl;
			break;
		}
		recv_len = recv(s_server, recv_buf, 100, 0);
		if (recv_len < 0) {
			cout << "����ʧ�ܣ�" << endl;
			break;
		}
		else {
			cout << "�������Ϣ:" << recv_buf << endl;
			//���ﻹ�ø�  �Ѹ���
			//���ܵ�����Ϣ�ǹ�Կ���ܵĶԳ���Կ�ͶԳ���Կ���ܵ�����
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
	//�ر��׽���
	closesocket(s_server);
	//�ͷ�DLL��Դ
	WSACleanup();
	system("pause");
	return 0;

}
void initialization() {
	//��ʼ���׽��ֿ�
	WORD w_req = MAKEWORD(2, 2);//�汾��
	WSADATA wsadata;
	int err;
	err = WSAStartup(w_req, &wsadata);
	if (err != 0) {
		cout << "��ʼ���׽��ֿ�ʧ�ܣ�" << endl;
	}
	//else {
	//	cout << "��ʼ���׽��ֿ�ɹ���" << endl;
	//}
	//���汾��
	if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wHighVersion) != 2) {
		cout << "�׽��ֿ�汾�Ų�����" << endl;
		WSACleanup();
	}
	//else {
	//	cout << "�׽��ֿ�汾��ȷ��" << endl;
	//}
	//������˵�ַ��Ϣ

}

void initialization2(std::string s,char* symkey)
{
	//unsigned char key[] = {
	//0x01, 0x02, 0x03, 0x04,
	//0x05, 0x06, 0x07, 0x08,
	//0x00, 0x00, 0x00, 0x00,
	//0x00, 0x00, 0x00, 0x00
	//};//128λ��16�ֽ�
	unsigned char key[16];
	//����AES�Գ���Կ  ���Ҫ�Լ�����
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
	printf("���������ǣ�");
	for (int i = 0; unchar[i] != '\0'; i++) printf("%c", unchar[i]);
	printf("\n");
}