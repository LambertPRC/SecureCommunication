#pragma once
#ifndef __ENCRYPTDECRYPT_H__
#define __ENCRYPTDECRYPT_H__

#include <string>
#include "RSA.h"

class EncryptDecrypt {
public:
	EncryptDecrypt() {}
	~EncryptDecrypt() {}

	char* encrypt(char*);    // ����
	bool decrypt();    // ����
	void print();    // ��ӡRSA�����Ϣ
	void reset();    // ����RSA�����Ϣ
	std::string getPublicKey();//���ɴ�����ַ���
	void setNandE(const std::string&);//����n��e
	void getEnvelop(char*, char*);

 protected:
	void load(int);    // ���ݸ���λ������RSA����
	bool islegal(const std::string &);// �ж������ַ����Ƿ�Ϸ�
private:
	RSA rsa;
};

#endif // __ENCRYPTDECRYPT_H__