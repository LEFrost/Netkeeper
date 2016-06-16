#include "stdafx.h"
#include <winsock2.h> 
#include <cstring>
#include <iostream>
#include <fstream>
#include "MD5.h"
#include "ras.h"
#include "rdial.h"

#pragma comment(lib, "ws2_32") 
#pragma comment(lib, "RASAPI32.LIB")
#pragma comment(lib,"rasapi32.lib") 

long m_lasttimec = 0;

CString Realusername(CString m_username)
{
	time_t m_time = 0;						//得到系统时间，从1970.01.01.00:00:00 开始的秒数
	long m_time1c = 0;						//时间初处理m_time1c为结果,经过时间计算出的第一次加密
	long temp = 0;
	int i = 0, j = 0, k = 0;
	unsigned int lenth = 0;

	unsigned char ss[4] = { 0 };		//源数据1,对m_time1convert进行计算得到格式符源数据
	unsigned char pad1[4] = { 0 };

	//格式符初加密
	unsigned char pp[4] = { 0 };
	unsigned char pf[6] = { 0 };
	char temp1[100];

	CString strS1;						//md5加密参数的一部分,ss2的整体形式
	CString strInput;
	CString m_formatsring;				//由m_timece算出的字符串,一般为可视字符
	CString m_md5;						//对初加密(m_timec字符串表示+m_username+radius)的MD5加密
	CString m_md5use;					//md5 Lower模式的前两位


	//取得系统时间m_time
	time(&m_time);
	//时间初处理m_time1c为结果,经过时间计算出的第一次加密
	//子函数////////////////////////////

	m_time1c = (m_time * 0x66666667) >> 0x21;

	//5秒内动态用户名一致处理
	if (m_time1c <= m_lasttimec)
	{
		m_time1c = m_lasttimec + 1;
	}
	m_lasttimec = m_time1c;

	temp = htonl(m_time1c);
	memcpy(pad1, &temp, 4);

	for (int i = 0; i < 4; i++)
	{
		strS1 += pad1[i];
	}

	memcpy(ss, &m_time1c, 4);

	//子函数////////////////////////////

	for (i = 0; i < 32; i++)
	{
		j = i / 8;
		k = 3 - (i % 4);
		pp[k] *= 2;
		if (ss[j] % 2 == 1)
		{
			pp[k]++;
		}
		ss[j] /= 2;
	}


	pf[0] = pp[3] / 0x4;
	pf[1] = (pp[2] / 0x10) | ((pp[3] & 0x3) * 0x10);
	pf[2] = (pp[1] / 0x40) | (pp[2] & 0x0F) * 0x04;
	pf[3] = pp[1] & 0x3F;
	pf[4] = pp[0] / 0x04;
	pf[5] = (pp[0] & 0x03) * 0x10;

	/////////////////////////////////////

	for (i = 0; i < 6; i++)
	{
		pf[i] += 0x20;
		if ((pf[i]) >= 0x40)
		{
			pf[i]++;
		}
	}

	for (i = 0; i < 6; i++)
	{
		m_formatsring += pf[i];
	}

	strInput = strS1 + m_username.Left(m_username.FindOneOf("@")) + "cqxinliradius002";
	lenth = 20 + m_username.FindOneOf("@");
	memcpy(temp1, strInput.GetBuffer(100), 100);
	m_md5 = MD5String(temp1, lenth);
	m_md5use = m_md5.Left(2);
	CString m_realusername = "\r\n" + m_formatsring + m_md5use + m_username;

	return m_realusername;
}


int main(int argc, char *argv[])
{
	string user;
	string pass;
	ifstream fin("User.txt");
	if (!fin.eof())
	{
		fin >> user;
	}
	/*printf("UserName:");
	char user[100] = { 0 };
	scanf("%s", user);
	printf("PassWord:");
	char pass[100] = { 0 };
	scanf("%s", pass);*/


	//CString user = "15310617430@cqupt";
	//CString pass = "309410";

	RASDIALPARAMSA rdParams;
	rdParams.dwSize = sizeof(RASDIALPARAMSA);
	strcpy(rdParams.szEntryName, "ChinaNetSNWide"); //连接名称是你的拨号名称
	rdParams.szPhoneNumber[0] = '\0';
	rdParams.szCallbackNumber[0] = '\0';
	strcpy(rdParams.szUserName, Realusername(user));
	strcpy(rdParams.szPassword, pass);
	rdParams.szDomain[0] = '\0';
	HRASCONN hRscon = NULL;
	DWORD retn = RasDialA(NULL, NULL, &rdParams, 0L, NULL, &hRscon);

	if (retn == 0)
	{
		printf("已经连接上...\n");
		//断开函数
		/*
		DWORD off= RasHangUp(&hRscon);
		if (off==0)
		{
		printf("连接已断开...\n");
		}else
		printf("断开连接出错...\n");
		*/
		//具体的细节慢慢扩充吧...仅仅演示一下...
		return 0;
	}
	printf("连接出错...\n");
	return 0;
}
