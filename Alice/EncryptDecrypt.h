#pragma once
#ifndef __ENCRYPTDECRYPT_H__
#define __ENCRYPTDECRYPT_H__

#include <string>
#include "RSA.h"

class EncryptDecrypt {
public:
	EncryptDecrypt() {}
	~EncryptDecrypt() {}

	char* encrypt(char*);    // 加密
	bool decrypt();    // 解密
	void print();    // 打印RSA相关信息
	void reset();    // 重置RSA相关信息
	std::string getPublicKey();//生成传输的字符串
	void setNandE(const std::string&);//分离n和e
	void getEnvelop(char*, char*);

 protected:
	void load(int);    // 根据给定位数加载RSA对象
	bool islegal(const std::string &);// 判断输入字符串是否合法
private:
	RSA rsa;
};

#endif // __ENCRYPTDECRYPT_H__