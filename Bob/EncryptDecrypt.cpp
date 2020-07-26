#include <iostream>
#include <ctime>
#include "EncryptDecrypt.h"

/**
 * 函数功能:加密运算
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
	std::cout << "用时: " << (double)(finish - start) / CLOCKS_PER_SEC << "s." << std::endl;
	std::cout << "明文: " << m << std::endl;
	std::cout << "密文: " << c << std::endl;
	char send[128];
	strcpy(send, c.toString().c_str());
	return send;
}

/**
 * 函数功能:解密运算
 */
char* EncryptDecrypt::decrypt(std::string str) {
	std::cout << ">";
	//std::cin >> str;// 输入密文
	
	if (!std::cin || !islegal(str))
		return false;
	BigInteger c(str);
	clock_t start = clock();
	BigInteger m = rsa.decryptByPrivate(c);
	clock_t finish = clock();

	std::cout << std::fixed;
	std::cout.precision(3);
	std::cout << "用时: " << (double)(finish - start) / CLOCKS_PER_SEC << "s." << std::endl;
	std::cout << "公钥加密的对称密钥: " << c << std::endl;
	std::cout << "解密后的对称密钥: " << m << std::endl;
	
	char buf[1000];
	strcpy(buf, m.toString().c_str());

	return buf;
}

/**
 * 函数功能:输出RSA相关信息
 */
void EncryptDecrypt::print() {
	std::cout << rsa << std::endl;
}

/**
 * 函数功能:重置RSA相关信息
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
 * 函数功能:根据给定位数len加载rsa
 */
void EncryptDecrypt::load(int len) {
	std::cout << "初始化密钥中..." << std::endl;
	clock_t start = clock();
	rsa.init(len);    // 初始化
	clock_t finish = clock();
	std::cout << "初始化完成." << std::endl;
	std::cout << std::fixed;
	std::cout.precision(3);
	std::cout << "用时: " << (double)(finish - start) / CLOCKS_PER_SEC << "s." << std::endl;
}

/**
 * 函数功能:判断输入字符串str是否合法
 * 参数含义:str代表输入的字符串
 */
bool EncryptDecrypt::islegal(const std::string & str) {
	for (std::string::const_iterator it = str.begin(); it != str.end(); ++it) {
		if (!isalnum(*it))    // 不是字母或者数字
			return false;
		if (isalpha(*it)) {
			char ch = tolower(*it);
			if (ch > 'f')    // 超过十六进制字符'f'
				return false;
		}
	}
	return true;
}