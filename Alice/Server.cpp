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
	//���峤�ȱ���
	int send_len = 0;
	int recv_len = 0;
	int len = 0;
	//���巢�ͻ������ͽ��ܻ�����
	char send_buf[200];
	char recv_buf[200];
	//���������׽��֣����������׽���
	SOCKET s_server;
	SOCKET s_accept;
	//����˵�ַ�ͻ��˵�ַ
	SOCKADDR_IN server_addr;
	SOCKADDR_IN accept_addr;
	initialization();
	//���������Ϣ
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(9999);
	//����������
	char buf2[64];

	//�����׽���
	s_server = socket(AF_INET, SOCK_STREAM, 0);
	if (bind(s_server, (SOCKADDR *)&server_addr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		cout << "�׽��ְ�ʧ�ܣ�" << endl;
		WSACleanup();
	}
	//else {
	//	cout << "�׽��ְ󶨳ɹ���" << endl;
	//}
	//�����׽���Ϊ����״̬
	if (listen(s_server, SOMAXCONN) < 0) {
		cout << "���ü���״̬ʧ�ܣ�" << endl;
		WSACleanup();
	}
	else {
		cout << "���ü���״̬�ɹ���" << endl;
	}
	cout << "��������ڼ������ӣ����Ժ�...." << endl;
	//������������
	len = sizeof(SOCKADDR);
	s_accept = accept(s_server, (SOCKADDR *)&accept_addr, &len);
	if (s_accept == SOCKET_ERROR) {
		cout << "����ʧ�ܣ�" << endl;
		WSACleanup();
		return 0;
	}
	cout << "���ӽ�����׼����������" << endl;


	//��������
	while (1) {
		recv_len = recv(s_accept, recv_buf, 100, 0);
		cout << "���ν��ܵ���Ϣ��:" << endl;;
		if (recv_len < 0) {
			cout << "����ʧ�ܣ�" << endl;
			break;
		}
		else {
			cout << "�ͻ�����Ϣ:" << recv_buf << endl;
		}
		//�������빫Կ���ܵĶԳ���Կ���Գ���Կ���ܵ�����
		EncryptDecrypt encrypt_decrypt;
		encrypt_decrypt.setNandE(recv_buf);
		strcpy(buf2, initialization2());
		strcpy(send_buf, encrypt_decrypt.encrypt(key1));
		encrypt_decrypt.getEnvelop(send_buf, buf2);
		//���͵��ͻ���
		send_len = send(s_accept, send_buf, 100, 0);
		if (send_len < 0) {
			cout << "����ʧ�ܣ�" << endl;
			break;
		}
	}
	//�ر��׽���
	closesocket(s_server);
	closesocket(s_accept);
	//�ͷ�DLL��Դ
	WSACleanup();
	return 0;
	}

	void initialization()
	{
		WORD w_req = MAKEWORD(2, 2);
		WSADATA wsadata;
		int err = WSAStartup(w_req, &wsadata);
		if (err) {
			cout << "��ʼ���׽��ֿ�ʧ��" << endl;
		}
		//else {
		//	cout << "��ʼ���׽��ֿ�ɹ���" << endl;
		//}
		if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wHighVersion) != 2) {
			cout << "�׽��ְ汾����" << endl;
			WSACleanup();
		}
		//else {
		//	cout << "�׽��ְ汾��ȷ" << endl;
		//}
	}

	//�����Գ���Կ
	char* initialization2()
	{
		//��ʼ��12345678
		for (int i = 0; i < 32; i++) { i >= 8 ? key1[i] = 0 : key1[i] = i + 1 + 48; }
		key1[31] = 0;

		//����AES�Գ���Կ
		unsigned char key[] = {
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		};//128λ��16�ֽ�
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