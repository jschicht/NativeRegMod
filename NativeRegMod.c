#include <windows.h>
#include <Winternl.h>

#define STATUS_OBJECT_NAME_NOT_FOUND     ((NTSTATUS)0xC0000034L)

/*
WinNT.h:13914
REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_LITTLE_ENDIAN = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_RESOURCE_LIST = 8
REG_FULL_RESOURCE_DESCRIPTOR = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_QWORD = 11
REG_QWORD_LITTLE_ENDIAN = 11
*/

typedef enum _KEY_INFORMATION_CLASS { 
  KeyBasicInformation           = 0,
  KeyNodeInformation            = 1,
  KeyFullInformation            = 2,
  KeyNameInformation            = 3,
  KeyCachedInformation          = 4,
  KeyFlagsInformation           = 5,
  KeyVirtualizationInformation  = 6,
  KeyHandleTagsInformation      = 7,
  MaxKeyInfoClass               = 8
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS { 
  KeyValueBasicInformation           = 0,
  KeyValueFullInformation            = 1,
  KeyValuePartialInformation         = 2,
  KeyValueFullInformationAlign64     = 3,
  KeyValuePartialInformationAlign64  = 4,
  MaxKeyValueInfoClass               = 5
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_NAME_INFORMATION {
  ULONG NameLength;
  WCHAR Name[512];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG DataLength;
  CHAR Data[4096];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

void NTAPI RtlInitUnicodeString(PUNICODE_STRING,PCWSTR);
NTSTATUS NTAPI NtOpenFile(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,ULONG,ULONG);
NTSTATUS NTAPI NtCreateFile(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
NTSTATUS NTAPI NtClose(HANDLE);
NTSTATUS NTAPI NtReadFile(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
NTSTATUS NTAPI NtOpenKey(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtQueryKey(HANDLE,KEY_INFORMATION_CLASS,PVOID,ULONG,PULONG);
NTSTATUS NTAPI NtQueryValueKey(HANDLE,PUNICODE_STRING ,KEY_VALUE_INFORMATION_CLASS ,PVOID,ULONG,PULONG);
NTSTATUS NTAPI NtSetValueKey(HANDLE,PUNICODE_STRING ,ULONG ,ULONG,PVOID,ULONG);
NTSTATUS NTAPI NtCreateKey(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,ULONG,PUNICODE_STRING,ULONG,PULONG);
NTSTATUS NTAPI RtlIntegerToUnicodeString(ULONG,ULONG,PUNICODE_STRING);
NTSTATUS NTAPI RtlInt64ToUnicodeString(ULONGLONG,ULONG,PUNICODE_STRING);
NTSTATUS NTAPI RtlAppendUnicodeStringToString(PUNICODE_STRING,PCUNICODE_STRING);
NTSTATUS NTAPI RtlAppendUnicodeToString(PUNICODE_STRING,PCWSTR);
NTSTATUS NTAPI NtDisplayString(PUNICODE_STRING);
NTSTATUS NTAPI NtDelayExecution(BOOLEAN,PLARGE_INTEGER);
NTSTATUS NTAPI NtTerminateProcess(HANDLE,NTSTATUS);
NTSTATUS NTAPI NtDeleteKey(HANDLE);
NTSTATUS NTAPI NtDeleteValueKey(HANDLE,PUNICODE_STRING);


void NtProcessStartup()
{
	UNICODE_STRING us0,us1,filename,usnl,szUniStr;
	ANSI_STRING szAnsiStr;
	OBJECT_ATTRIBUTES obja;
	NTSTATUS status;
	LARGE_INTEGER delay,delay2;
	HANDLE file;
	LARGE_INTEGER ByteOffset;
	int i=0,j=0,counter=0;
	IO_STATUS_BLOCK iostatusblock;
	char buffer[256] = {0};
	char chTemp0[8192], chTemp1[280], chTemp2[280], chTemp3[280], chTemp4[280], chTemp5[280], *pDest1, *pDest2;
	int iPos1 = 0, iPos2 = 0, iLen = 0, iLen2 = 0;
	unsigned long m_ulTemp = 0;
	char *TargetKeyName, *TargetValueName, *TargetType, *TargetValue;
	BOOL MoreToProcess = 0, ConfigOk = 0;
	char Volumes[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	delay.QuadPart=-100000000;
	delay2.QuadPart=-10000000;
	RtlInitUnicodeString(&usnl,L"\n");

	ByteOffset.QuadPart = 0;
	for (j = 0; j < strlen(Volumes); j++ ) {
		memset(buffer, 0, sizeof(buffer));
		RtlSecureZeroMemory(&szAnsiStr, sizeof(szAnsiStr));
		RtlSecureZeroMemory(&filename, sizeof(filename));
		strcat(buffer,"\\??\\");
		strncat(buffer,&Volumes[j],1);
		strcat(buffer,":\\NativeRegMod.config");
		RtlInitAnsiString(&szAnsiStr, buffer);
		RtlAnsiStringToUnicodeString(&filename, &szAnsiStr, TRUE);
		InitializeObjectAttributes(&obja, &filename, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = NtOpenFile(&file, FILE_READ_DATA, &obja, &iostatusblock, NULL, NULL);
		if(!NT_SUCCESS(status)) {
			continue;
		}
		else {
			ConfigOk = 1;
			break;}
	}
	if (ConfigOk == 0) {
		RtlInitUnicodeString(&us0,L"Error: Could not find config file\n");
		NtDisplayString(&us0);
		NtDelayExecution(FALSE,&delay);
		RtlSecureZeroMemory(&us0, sizeof(us0));
		RtlSecureZeroMemory(&filename, sizeof(filename));
		NtTerminateProcess((HANDLE)-1,0);
	}
	NtDisplayString(&filename);
	RtlSecureZeroMemory(&filename, sizeof(filename));
	RtlInitUnicodeString(&us0,L"\n");
	NtDisplayString(&us0);
	RtlSecureZeroMemory(&us0, sizeof(us0));

	memset(chTemp0, 0, sizeof(chTemp0));
	status = NtReadFile(file,NULL,NULL,NULL,&iostatusblock,chTemp0,8192,&ByteOffset,NULL);
    if(!NT_SUCCESS(status)) {
		RtlInitUnicodeString(&us0,L"Error in NtReadFile: 0x");
		_ui64toa(status, buffer, 16);
		RtlInitAnsiString(&szAnsiStr, buffer);
		RtlAnsiStringToUnicodeString(&szUniStr, &szAnsiStr, TRUE);
		NtDisplayString(&szUniStr);
		NtDisplayString(&usnl);
		RtlZeroMemory(&us0, sizeof(us0));
		RtlZeroMemory(&buffer, sizeof(buffer));
		RtlZeroMemory(&szUniStr, sizeof(szUniStr));
		RtlZeroMemory(&szAnsiStr, sizeof(szAnsiStr));
		NtDelayExecution(FALSE,&delay);
		NtTerminateProcess((HANDLE)-1,0);
    }


	do
	{
		pDest1 = strchr(chTemp0+iPos1, '\n');
		if (!pDest1 > 0) {break;}
		iLen = pDest1 - iPos1 - chTemp0 + 1;
		if (iLen < 5) {break;}
		iPos1 = pDest1 - chTemp0 + 1;
		memset(chTemp1, 0, sizeof(chTemp1));
		memcpy(chTemp1, chTemp0 + iPos1 - iLen, iLen);
		counter = 0;
		pDest2 = chTemp1;
		iPos2 = 0;
		do
		{
			pDest2 = strchr(chTemp1+iPos2, ',');
			if (!pDest2 > 0) {break;}
			iLen2 = pDest2 - iPos2 - chTemp1 + 1;
			iPos2 = pDest2 - chTemp1 + 1;
			if (counter == 0) {
				memset(chTemp2, 0, sizeof(chTemp2));
				memcpy(chTemp2, chTemp1 + iPos2 - iLen2, iLen2-1);
				TargetKeyName = chTemp2;};
			if (counter == 1) {
				memset(chTemp3, 0, sizeof(chTemp3));
				memcpy(chTemp3, chTemp1 + iPos2 - iLen2, iLen2-1);
				TargetValueName = chTemp3;};
			if (counter == 2) {
				memset(chTemp4, 0, sizeof(chTemp4));
				memcpy(chTemp4, chTemp1 + iPos2 - iLen2, iLen2-1);
				TargetType = chTemp4;};
			if (counter == 3) {
				memset(chTemp5, 0, sizeof(chTemp5));
				memcpy(chTemp5, chTemp1 + iPos2 - iLen2, iLen2-1);
				TargetValue = chTemp5;};
			counter += 1;
			if (counter == 4) {break;}
		}
		while (pDest2 != NULL);
		ModifyRegistry(TargetKeyName, TargetValueName, TargetType, TargetValue);
		memset(TargetKeyName, 0, sizeof(TargetKeyName));
		memset(TargetValueName, 0, sizeof(TargetValueName));
		memset(TargetType, 0, sizeof(TargetType));
		memset(TargetValue, 0, sizeof(TargetValue));
		NtDelayExecution(FALSE,&delay2);
	}
	while (pDest1 != NULL || iPos1 < strlen(chTemp0));

	NtClose(file);
	NtDelayExecution(FALSE,&delay);
	RtlSecureZeroMemory(&us0, sizeof(us0));
	RtlSecureZeroMemory(&us1, sizeof(us1));
	NtTerminateProcess((HANDLE)-1,0);
}

int ModifyRegistry(char *KeyName, char *ValueName, char *Type, char *Value)
{
	UNICODE_STRING us0,us1,us2,usnl,szUniStr = {0};
	ANSI_STRING as,as1,szAnsiStr = {0};
	OBJECT_ATTRIBUTES oaKeyName;
//	LARGE_INTEGER delay3;
	NTSTATUS status;
	HANDLE key;
	KEY_NAME_INFORMATION KeyNameStruct;
	ULONG outsize,disp;
	char buffer[256] = {0};
	int RegValType,ValSize,i=0,n=0, x=0, skipcounter=0;
	DWORD NewRegDwordValue;
	WCHAR NewRegSzValue[512];
	enum {NBBYTES = 512};
	char res[NBBYTES+1];

//	delay3.QuadPart=-30000000;
	RtlInitUnicodeString(&usnl,L"\n");

	RtlInitUnicodeString(&us1,L"Modifying: ");
	RtlInitAnsiString(&as,KeyName);
	RtlAnsiStringToUnicodeString(&us0, &as, TRUE);
	NtDisplayString(&us1);
	NtDisplayString(&us0);
	NtDisplayString(&usnl);
	RtlZeroMemory(&us1,sizeof(us1));
	RtlZeroMemory(&as,sizeof(as));

	RtlInitAnsiString(&as,ValueName);
	RtlAnsiStringToUnicodeString(&us1, &as, TRUE);
	NtDisplayString(&us1);
	NtDisplayString(&usnl);
	RtlInitAnsiString(&as,Type);
	RtlAnsiStringToUnicodeString(&us1, &as, TRUE);
	NtDisplayString(&us1);
	NtDisplayString(&usnl);
	RtlInitAnsiString(&as,Value);
	RtlAnsiStringToUnicodeString(&us1, &as, TRUE);
	NtDisplayString(&us1);
	NtDisplayString(&usnl);
	
//	NtDelayExecution(FALSE,&delay3);

	InitializeObjectAttributes(&oaKeyName, &us0, OBJ_CASE_INSENSITIVE, NULL, NULL);
	key = NULL;
	status = NtOpenKey(&key, KEY_ALL_ACCESS , &oaKeyName);
	if(status == STATUS_OBJECT_NAME_NOT_FOUND)
	{
		status = NtCreateKey(&key,KEY_ALL_ACCESS,&oaKeyName,0,NULL,REG_OPTION_NON_VOLATILE,&disp);
		if(!NT_SUCCESS(status))
		{
			RtlInitUnicodeString(&us0,L"Error in NtCreateKey: 0x");
			NtDisplayString(&us0);
			_ui64toa(status, buffer, 16);
			RtlInitAnsiString(&szAnsiStr, buffer);
			RtlAnsiStringToUnicodeString(&szUniStr, &szAnsiStr, TRUE);
			NtDisplayString(&szUniStr);
			NtDisplayString(&usnl);
			RtlZeroMemory(&us0, sizeof(us0));
			RtlZeroMemory(&buffer, sizeof(buffer));
			RtlZeroMemory(&szUniStr, sizeof(szUniStr));
			RtlZeroMemory(&szAnsiStr, sizeof(szAnsiStr));
			return 0;
		}
	}
    else if(!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_NOT_FOUND) 
	{
		RtlInitUnicodeString(&us0,L"Error in NtOpenKey: 0x");
		NtDisplayString(&us0);
		_ui64toa(status, buffer, 16);
		RtlInitAnsiString(&szAnsiStr, buffer);
		RtlAnsiStringToUnicodeString(&szUniStr, &szAnsiStr, TRUE);
		NtDisplayString(&szUniStr);
		NtDisplayString(&usnl);
		RtlZeroMemory(&us0, sizeof(us0));
		RtlZeroMemory(&buffer, sizeof(buffer));
		RtlZeroMemory(&szUniStr, sizeof(szUniStr));
		RtlZeroMemory(&szAnsiStr, sizeof(szAnsiStr));
		return 0;
    }
	RtlZeroMemory(&us0,sizeof(us0));
//	NtDelayExecution(FALSE,&delay3);

	if (strstr(Type,"DELETE"))
	{
		if (strlen(ValueName) == 0)
		{
			RtlInitUnicodeString(&us0,L"Error in NtDeleteKey: 0x");
			status = NtDeleteKey(key);
		}
		else
		{
			RtlInitUnicodeString(&us0,L"Error in NtDeleteValueKey: 0x");
			RtlInitAnsiString(&as1,ValueName);
			RtlAnsiStringToUnicodeString(&us2, &as1, TRUE);
			status = NtDeleteValueKey(key,&us2);
			RtlZeroMemory(&as1, sizeof(as1));
			RtlZeroMemory(&us2, sizeof(us2));
		}
		if(!NT_SUCCESS(status))
		{
			NtDisplayString(&us0);
			_ui64toa(status, buffer, 16);
			RtlInitAnsiString(&szAnsiStr, buffer);
			RtlAnsiStringToUnicodeString(&szUniStr, &szAnsiStr, TRUE);
			NtDisplayString(&szUniStr);
			NtDisplayString(&usnl);
			RtlZeroMemory(&us0, sizeof(us0));
			RtlZeroMemory(&buffer, sizeof(buffer));
			RtlZeroMemory(&szUniStr, sizeof(szUniStr));
			RtlZeroMemory(&szAnsiStr, sizeof(szAnsiStr));
			return 0;
		}
		return 0;
	}
	if(NT_SUCCESS(NtQueryKey(key,KeyNameInformation,&KeyNameStruct,sizeof(KeyNameStruct),&outsize)))
	{
		RtlInitAnsiString(&as1,ValueName);
		RtlAnsiStringToUnicodeString(&us2, &as1, TRUE);
		
		if (strstr(Type,"REG_SZ")) {
			RegValType = REG_SZ;
			mbstowcs(NewRegSzValue,Value,strlen(Value));
			status = NtSetValueKey(key, &us2, 0, RegValType, &NewRegSzValue, wcslen(NewRegSzValue) * sizeof(WCHAR) + sizeof(WCHAR));
			RtlZeroMemory(&NewRegSzValue,sizeof(NewRegSzValue));
		}
		else if (strstr(Type,"REG_DWORD")) {
			RegValType = REG_DWORD;
			NewRegDwordValue = atoi(Value);
			status = NtSetValueKey(key, &us2, 0, RegValType, &NewRegDwordValue, sizeof(DWORD));
			RtlZeroMemory(&NewRegDwordValue,sizeof(NewRegDwordValue));
		}
		else if (strstr(Type,"REG_BINARY")) {
			RegValType = REG_BINARY;
			ValSize = strlen(Value);
			for (i = 0; i < NBBYTES; i++){
				switch (*Value){
					case '0': case '1': case '2': case '3': case '4':
					case '5': case '6': case '7': case '8': case '9':
						res[i] = *Value - '0';
					break;
					case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
						res[i] = *Value - 'A' + 10;
					break;
				default:
					;
				}
				Value++;
				switch (*Value){
					case '0': case '1': case '2': case '3': case '4':
					case '5': case '6': case '7': case '8': case '9':
						res[i] = res[i]*16 + *Value - '0';
					break;
					case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
						res[i] = res[i]*16 + *Value - 'A' + 10;
					break;
				default:
					;
				}
				Value++;
				if (*Value == 0) { continue; }
				if (*Value == ' ') { Value++; continue; }
			}
			status = NtSetValueKey(key, &us2, 0, RegValType, res, ValSize/2);
		}
		else {
			RtlInitUnicodeString(&us2,L"Unsupported reg type\n");
			NtDisplayString(&us2);
			RtlZeroMemory(&us2,sizeof(us2));
			NtClose(key);
			return 0;
		}
		RtlZeroMemory(&us2,sizeof(us2));
//		NtDelayExecution(FALSE,&delay3);
		if(!NT_SUCCESS(status))
		{
			RtlInitUnicodeString(&us0,L"Error in NtSetValueKey: 0x");
			NtDisplayString(&us0);
			_ui64toa(status, buffer, 16);
			RtlInitAnsiString(&szAnsiStr, buffer);
			RtlAnsiStringToUnicodeString(&szUniStr, &szAnsiStr, TRUE);
			NtDisplayString(&szUniStr);
			NtDisplayString(&usnl);
			RtlZeroMemory(&us0, sizeof(us0));
			RtlZeroMemory(&buffer, sizeof(buffer));
			RtlZeroMemory(&szUniStr, sizeof(szUniStr));
			RtlZeroMemory(&szAnsiStr, sizeof(szAnsiStr));
			NtClose(key);
			return 0;
		}
		RtlZeroMemory(&us2, sizeof(us2));
	}
	else
	{
		RtlInitUnicodeString(&us0,L"Error in NtQueryKey: 0x");
		NtDisplayString(&us0);
		_ui64toa(status, buffer, 16);
		RtlInitAnsiString(&szAnsiStr, buffer);
		RtlAnsiStringToUnicodeString(&szUniStr, &szAnsiStr, TRUE);
		NtDisplayString(&szUniStr);
		NtDisplayString(&usnl);
		RtlZeroMemory(&us0, sizeof(us0));
		RtlZeroMemory(&buffer, sizeof(buffer));
		RtlZeroMemory(&szUniStr, sizeof(szUniStr));
		RtlZeroMemory(&szAnsiStr, sizeof(szAnsiStr));
		NtClose(key);
		return 0;
	}
	NtClose(key);
}