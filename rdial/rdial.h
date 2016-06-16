
#include <string>
#include <iostream>

using namespace std;
typedef int INT;
 
typedef __int64   LONG64;

class Rdial
{
public:
	Rdial (CString username, INT ver = 18, long lasttimec = 0); 
	CString Realusername();
	bool CreateRASLink();
	int dial();
private:
	INT m_ver;				//�ǿյİ汾��V12��V18����
	long m_lasttimec;		//�ϴγɹ���ʱ�䴦��
	CString m_username;		//ԭʼ�û���
	CString m_realusername;	//�������û���
	CString RADIUS;
	CString LR;
};

