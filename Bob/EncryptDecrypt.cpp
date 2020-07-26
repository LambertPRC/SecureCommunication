#include <iostream>
#include <ctime>
#include "EncryptDecrypt.h"

/**
 * ��������:��������
 */
char* EncryptDecrypt::encrypt(char* input) {
	std::string str(input);
	std::cout << ">";
	if (!std::cin || !islegal(str))
		return false;
	BigInteger m(str);
	clock_t start = clock();
	BigInteger c = rsa.encryptByPublic(m);
	clock_t finish = clock();

	std::cout << std::fixed;
	std::cout.precision(3);
	std::cout << "��ʱ: " << (double)(finish - start) / CLOCKS_PER_SEC << "s." << std::endl;
	std::cout << "����: " << m << std::endl;
	std::cout << "����: " << c << std::endl;
	char send[128];
	strcpy(send, c.toString().c_str());
	return send;
}

/**
 * ��������:��������
 */
char* EncryptDecrypt::decrypt(std::string str) {
	std::cout << ">";
	//std::cin >> str;// ��������
	
	if (!std::cin || !islegal(str))
		return false;
	BigInteger c(str);
	clock_t start = clock();
	BigInteger m = rsa.decryptByPrivate(c);
	clock_t finish = clock();

	std::cout << std::fixed;
	std::cout.precision(3);
	std::cout << "��ʱ: " << (double)(finish - start) / CLOCKS_PER_SEC << "s." << std::endl;
	std::cout << "��Կ���ܵĶԳ���Կ: " << c << std::endl;
	std::cout << "���ܺ�ĶԳ���Կ: " << m << std::endl;
	
	char buf[1000];
	strcpy(buf, m.toString().c_str());

	return buf;
}

/**
 * ��������:���RSA�����Ϣ
 */
void EncryptDecrypt::print() {
	std::cout << rsa << std::endl;
}

/**
 * ��������:����RSA�����Ϣ
 */
void EncryptDecrypt::reset() {
	int len = 128;
	load(len >> 1);
}

std::string EncryptDecrypt::getPublicKey()
{
	return  rsa.getPublicKey();
}

void EncryptDecrypt::setNandE(const std::string & s)
{
	int pos = s.find('+');
	std::cout << s.substr(0, pos) << std::endl;;
	BigInteger n = s.substr(0, pos), e = s.substr(pos + 1);
	rsa.n = n; rsa.e = e;
	
}

void EncryptDecrypt::getEnvelop(char *send_buf, char *buf2)
{
	char buf1[2] = { '+' };
	strcat(send_buf, buf1);
	strcat(send_buf, buf2);
}


/**
 * ��������:���ݸ���λ��len����rsa
 */
void EncryptDecrypt::load(int len) {
	std::cout << "��ʼ����Կ��..." << std::endl;
	clock_t start = clock();
	rsa.init(len);    // ��ʼ��
	clock_t finish = clock();
	std::cout << "��ʼ�����." << std::endl;
	std::cout << std::fixed;
	std::cout.precision(3);
	std::cout << "��ʱ: " << (double)(finish - start) / CLOCKS_PER_SEC << "s." << std::endl;
}

/**
 * ��������:�ж������ַ���str�Ƿ�Ϸ�
 * ��������:str����������ַ���
 */
bool EncryptDecrypt::islegal(const std::string & str) {
	for (std::string::const_iterator it = str.begin(); it != str.end(); ++it) {
		if (!isalnum(*it))    // ������ĸ��������
			return false;
		if (isalpha(*it)) {
			char ch = tolower(*it);
			if (ch > 'f')    // ����ʮ�������ַ�'f'
				return false;
		}
	}
	return true;
}