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
	time_t m_time = 0;						//�õ�ϵͳʱ�䣬��1970.01.01.00:00:00 ��ʼ������
	long m_time1c = 0;						//ʱ�������m_time1cΪ���,����ʱ�������ĵ�һ�μ���
	long temp = 0;
	int i = 0, j = 0, k = 0;
	unsigned int lenth = 0;

	unsigned char ss[4] = { 0 };		//Դ����1,��m_time1convert���м���õ���ʽ��Դ����
	unsigned char pad1[4] = { 0 };

	//��ʽ��������
	unsigned char pp[4] = { 0 };
	unsigned char pf[6] = { 0 };
	char temp1[100];

	CString strS1;						//md5���ܲ�����һ����,ss2��������ʽ
	CString strInput;
	CString m_formatsring;				//��m_timece������ַ���,һ��Ϊ�����ַ�
	CString m_md5;						//�Գ�����(m_timec�ַ�����ʾ+m_username+radius)��MD5����
	CString m_md5use;					//md5 Lowerģʽ��ǰ��λ


	//ȡ��ϵͳʱ��m_time
	time(&m_time);
	//ʱ�������m_time1cΪ���,����ʱ�������ĵ�һ�μ���
	//�Ӻ���////////////////////////////

	m_time1c = (m_time * 0x66666667) >> 0x21;

	//5���ڶ�̬�û���һ�´���
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

	//�Ӻ���////////////////////////////

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
	strcpy(rdParams.szEntryName, "ChinaNetSNWide"); //������������Ĳ�������
	rdParams.szPhoneNumber[0] = '\0';
	rdParams.szCallbackNumber[0] = '\0';
	strcpy(rdParams.szUserName, Realusername(user));
	strcpy(rdParams.szPassword, pass);
	rdParams.szDomain[0] = '\0';
	HRASCONN hRscon = NULL;
	DWORD retn = RasDialA(NULL, NULL, &rdParams, 0L, NULL, &hRscon);

	if (retn == 0)
	{
		printf("�Ѿ�������...\n");
		//�Ͽ�����
		/*
		DWORD off= RasHangUp(&hRscon);
		if (off==0)
		{
		printf("�����ѶϿ�...\n");
		}else
		printf("�Ͽ����ӳ���...\n");
		*/
		//�����ϸ�����������...������ʾһ��...
		return 0;
	}
	printf("���ӳ���...\n");
	return 0;
}
