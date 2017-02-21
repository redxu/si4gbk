#include "winapihook.h"
#include "hook/hookapi.h"
#include "utils.h"
#include "utf8.h"
#include "sifilemgr.h"
#include "sihandlemgr.h"
#include "md5.h"


typedef HANDLE (WINAPI *CreateFileAFn)(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
);

typedef HANDLE (WINAPI *CreateFileWFn)(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
);

typedef HANDLE (WINAPI *FindFirstFileWFn)(
	LPCWSTR lpFileName,
	LPWIN32_FIND_DATA lpFindFileData
);

typedef BOOL (WINAPI *CloseHandleFn)(
	HANDLE hObject
);

typedef BOOL (WINAPI *SetEndOfFileFn)(
	HANDLE hFile
);


CreateFileAFn OrgCreateFileA = NULL;
CreateFileWFn OrgCreateFileW = NULL;
FindFirstFileWFn OrgFindFirstFileW = NULL;
CloseHandleFn OrgCloseHandle = NULL;
SetEndOfFileFn OrgSetEndOfFile = NULL;


static BOOL MByteToWChar(LPCSTR lpcszStr, LPWSTR lpwszStr, DWORD dwSize)
{
	DWORD dwMinSize;
	dwMinSize = MultiByteToWideChar (CP_ACP, 0, lpcszStr, -1, NULL, 0);
	if(dwSize < dwMinSize)
	{
		return FALSE;
	}
	MultiByteToWideChar (CP_ACP, 0, lpcszStr, -1, lpwszStr, dwMinSize);
	return TRUE;
}

static BOOL WCharToMByte(LPCWSTR lpcwszStr,LPSTR lpszStr,DWORD dwSize)
{
	DWORD dwMinSize;
	dwMinSize = WideCharToMultiByte(CP_OEMCP,0,lpcwszStr,-1,NULL,0,NULL,FALSE);
	if(dwSize < dwMinSize)
	{
		return FALSE;
	}
	WideCharToMultiByte(CP_OEMCP,0,lpcwszStr,-1,lpszStr,dwSize,NULL,FALSE);
	return TRUE;
}

HANDLE WINAPI HookCreateFileA(
	LPCTSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	HANDLE handle;
	int u8flag = 0;
	char hookfilename[256];
	unsigned char fmd5[16];
	struct SiFileInfo* si_file_info = NULL;
	unsigned long hash = HashString(lpFileName);
OutputDebugStringEx("CreateFileA %s", lpFileName);	
	memset(hookfilename,0,sizeof(hookfilename));
	strcpy(hookfilename,lpFileName);	
	si_file_info = FindSiFileFromLink(hash);	
	if(si_file_info == NULL)
	{
		HANDLE hFile = OrgCreateFileA(lpFileName,
								GENERIC_READ,
    							FILE_SHARE_READ,
    							NULL,
    							OPEN_EXISTING,
    							FILE_ATTRIBUTE_NORMAL,
    							NULL);
    	if(hFile == INVALID_HANDLE_VALUE)
    	{
    		OutputDebugStringEx("Function: %s OrgCreateFile1 %s Failed[%d]",__FUNCTION__,lpFileName,GetLastError());
    		goto RECOVER;
    	}    	
    	DWORD fread;
    	DWORD fsize = GetFileSize(hFile,NULL);
    	char* buffer = (char*)malloc(fsize+1);
    	memset(buffer,0,fsize+1);
    	ReadFile(hFile,buffer,fsize,&fread,NULL);
    	OrgCloseHandle(hFile);	
    	u8flag = IsUtf8(buffer,fsize); 	
	    	
    	//convert
    	if(u8flag != 0)
    	{    		
    		//OutputDebugStringEx("[%d]%s",u8flag,lpFileName);
    		DWORD gbksize = 0;
    		DWORD gbkwriten;
    		char* gbk = (char *)malloc(fsize+1);
			if(u8flag == 1)   		
    			utf8_to_gbk(buffer,gbk,&gbksize);
    		else if(u8flag == 2)
    			utf8_to_gbk(buffer+3,gbk,&gbksize);  		
    		//sprintf(hookfilename,"%s.gbk",lpFileName);
    		GetTmpFilename(hash,hookfilename);
    		HANDLE hGbk = OrgCreateFileA(hookfilename,
								GENERIC_WRITE,
    							0,
    							NULL,
    							CREATE_ALWAYS,
    							FILE_ATTRIBUTE_NORMAL,
    							NULL);    							
    		if(hGbk != INVALID_HANDLE_VALUE)
    		{
    			WriteFile(hGbk,gbk,gbksize-1,&gbkwriten,NULL);
    			OrgCloseHandle(hGbk);
    		}
    		else 
    		{
    			OutputDebugStringEx("CreateFile %s Failed![Error=%ld]",hookfilename,GetLastError());
    		}   		
    		free(gbk);	    		
    	}
    	//calc md5sum only u8
    	if(u8flag != 0)
    	{
    		memset(fmd5,0,sizeof(fmd5));
    		Md5Sum((unsigned char *)buffer,fsize,fmd5);
    	}
    	  	
    	free(buffer);
		SiFile_Add(hash,u8flag,fmd5,(char *)lpFileName,hookfilename);	
	}
	else 
	{		
		u8flag = si_file_info->u8flag;
		//judge outside change
		if(u8flag != 0)
		{
			if(dwDesiredAccess == GENERIC_READ)
			{
				//read file
				HANDLE hFile = OrgCreateFileA(lpFileName,
								GENERIC_READ,
    							FILE_SHARE_READ,
    							NULL,
    							OPEN_EXISTING,
    							FILE_ATTRIBUTE_NORMAL,
    							NULL);
		    	if(hFile == INVALID_HANDLE_VALUE)
		    	{
		    		OutputDebugStringEx("Function :%s OrgCreateFile2 %s Failed[%d]",__FUNCTION__,lpFileName,GetLastError());
		    		goto RECOVER;
		    	}    	
		    	DWORD fread;
		    	DWORD fsize = GetFileSize(hFile,NULL);
		    	char* buffer = (char*)malloc(fsize+1);
		    	memset(buffer,0,fsize+1);
		    	ReadFile(hFile,buffer,fsize,&fread,NULL);
		    	OrgCloseHandle(hFile);

		    	//calc md5sum
		    	memset(fmd5,0,sizeof(fmd5));
				Md5Sum((unsigned char *)buffer,fsize,fmd5);
				if(memcmp(fmd5,si_file_info->orgmd5,16) != 0)
				{
					OutputDebugStringEx("u8[%s] Changed outside!",lpFileName);
					//convert
					DWORD gbksize = 0;
		    		DWORD gbkwriten;
		    		char* gbk = (char *)malloc(fsize+1);
					if(u8flag == 1)   		
		    			utf8_to_gbk(buffer,gbk,&gbksize);
		    		else if(u8flag == 2)
		    			utf8_to_gbk(buffer+3,gbk,&gbksize);  		
		    		//sprintf(hookfilename,"%s.gbk",lpFileName);
		    		GetTmpFilename(hash,hookfilename);
		    		HANDLE hGbk = OrgCreateFileA(hookfilename,
										GENERIC_WRITE,
		    							0,
		    							NULL,
		    							CREATE_ALWAYS,
		    							FILE_ATTRIBUTE_NORMAL,
		    							NULL);    							
		    		if(hGbk != INVALID_HANDLE_VALUE)
		    		{
		    			WriteFile(hGbk,gbk,gbksize-1,&gbkwriten,NULL);
		    			OrgCloseHandle(hGbk);
		    		}
		    		else 
		    		{
		    			OutputDebugStringEx("CreateFile %s Failed![Error=%ld]",hookfilename,GetLastError());
		    		}   		
		    		free(gbk);

		    		//update hash
		    		memcpy(si_file_info->orgmd5,fmd5,16);
				}

				free(buffer);
			}
		}
		strcpy(hookfilename,si_file_info->gbkfile);
	}
	
RECOVER:
	handle = OrgCreateFileA(hookfilename,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
									dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
	if(u8flag != 0)
	{
		SiHandle_Add(handle,u8flag,(char *)lpFileName,hookfilename);		
	}
	
	return handle;
}


HANDLE WINAPI HookCreateFileW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	HANDLE handle;
	int gbkflag = 0;
	char hookfilename[1024];
	char orgfilename[1024];
	wchar_t lpwszStr[1024];
	unsigned char fmd5[16];
	WIN32_FILE_ATTRIBUTE_DATA wfad;
	struct SiFileInfo* si_file_info = NULL;

	memset(&wfad, 0, sizeof(wfad));
	memset(hookfilename,0,sizeof(hookfilename));
	memset(orgfilename, 0, sizeof(orgfilename));
	WCharToMByte(lpFileName, hookfilename, 1024);
	WCharToMByte(lpFileName, orgfilename, 1024);	
	unsigned long hash = HashString(orgfilename);
	si_file_info = FindSiFileFromLink(hash);
OutputDebugStringEx("CreateFileW %s", orgfilename); 
	if(si_file_info == NULL)
	{
		HANDLE hFile = OrgCreateFileW(lpFileName,
								GENERIC_READ,
    							FILE_SHARE_READ,
    							NULL,
    							OPEN_EXISTING,
    							FILE_ATTRIBUTE_NORMAL,
    							NULL);
    	if(hFile == INVALID_HANDLE_VALUE)
    	{
    		OutputDebugStringEx("Function: %s OrgCreateFileW1 %s Failed[%d]",__FUNCTION__,orgfilename,GetLastError());
    		goto RECOVER;
    	} 	
    	DWORD fread;
    	DWORD fsize = GetFileSize(hFile,NULL);
    	char* buffer = (char*)malloc(fsize+1);
    	memset(buffer,0,fsize+1);
    	if(fsize > 0)
    	{
    		ReadFile(hFile,buffer,fsize,&fread,NULL);
    	}
    	OrgCloseHandle(hFile);	
    	gbkflag = IsGBK(buffer,fsize);	
	    	
    	//convert
    	if(gbkflag != 0)
    	{    		
    		DWORD utf8size = 0;
    		DWORD utf8writen;
    		char* utf8 = (char *)malloc(2*fsize+1);
    		gbk_to_utf8(buffer, utf8, &utf8size);		
    		GetTmpFilename(hash,hookfilename);
    		MByteToWChar(hookfilename, lpwszStr, 1024);
    		HANDLE hUtf8 = OrgCreateFileW(lpwszStr,
								GENERIC_WRITE,
    							0,
    							NULL,
    							CREATE_ALWAYS,
    							FILE_ATTRIBUTE_NORMAL,
    							NULL);    							
    		if(hUtf8 != INVALID_HANDLE_VALUE)
    		{
    			WriteFile(hUtf8,utf8,utf8size-1,&utf8writen,NULL);
    			//sync time
    			//GetFileAttributesExW(lpFileName, GetFileExInfoStandard, &wfad);
    			//SetFileTime(hUtf8, &wfad.ftCreationTime, &wfad.ftLastAccessTime, &wfad.ftLastWriteTime);
    			OrgCloseHandle(hUtf8);
    		}
    		else 
    		{
    			OutputDebugStringEx("CreateFile %s Failed![Error=%ld]",hookfilename,GetLastError());
    		}   		
    		free(utf8);	    		
    	}
    	//calc md5sum only gbk
    	if(gbkflag != 0)
    	{
    		memset(fmd5,0,sizeof(fmd5));
    		Md5Sum((unsigned char *)buffer,fsize,fmd5);
    	}
    	  	
    	free(buffer);
		SiFile_Add(hash,gbkflag,fmd5,(char *)orgfilename,hookfilename);
		//debug
		si_file_info = FindSiFileFromLink(hash);
		si_file_info->wfad = wfad;
	}
	else 
	{		
		gbkflag = si_file_info->u8flag;
		//judge outside change
#if 0
		if(gbkflag != 0)
		{
			//if(dwDesiredAccess == GENERIC_READ)
			//why this change?
			//if(dwDesiredAccess == GENERIC_WRITE)
			{
				//read file
				HANDLE hFile = OrgCreateFileW(lpFileName,
								GENERIC_READ,
    							FILE_SHARE_READ,
    							NULL,
    							OPEN_EXISTING,
    							FILE_ATTRIBUTE_NORMAL,
    							NULL);
		    	if(hFile == INVALID_HANDLE_VALUE)
		    	{
		    		OutputDebugStringEx("Function :%s OrgCreateFile2 %s Failed[%d]",__FUNCTION__,orgfilename,GetLastError());
		    		goto RECOVER;
		    	}    	
		    	DWORD fread;
		    	DWORD fsize = GetFileSize(hFile,NULL);
		    	char* buffer = (char*)malloc(fsize+1);
		    	memset(buffer,0,fsize+1);
		    	ReadFile(hFile,buffer,fsize,&fread,NULL);
		    	OrgCloseHandle(hFile);

		    	//calc md5sum
		    	memset(fmd5,0,sizeof(fmd5));
				Md5Sum((unsigned char *)buffer,fsize,fmd5);
				if(memcmp(fmd5,si_file_info->orgmd5,16) != 0)
				{
					OutputDebugStringEx("gbk[%s] Changed outside!",orgfilename);
		    		DWORD utf8size = 0;
		    		DWORD utf8writen;
		    		char* utf8 = (char *)malloc(2*fsize+1);
		    		gbk_to_utf8(buffer, utf8, &utf8size);
		    		GetTmpFilename(hash,hookfilename);
		    		MByteToWChar(hookfilename, lpwszStr, 1024);
		    		HANDLE hUtf8 = OrgCreateFileW(lpwszStr,
										GENERIC_WRITE,
		    							0,
		    							NULL,
		    							CREATE_ALWAYS,
		    							FILE_ATTRIBUTE_NORMAL,
		    							NULL);    							
		    		if(hUtf8 != INVALID_HANDLE_VALUE)
		    		{
		    			WriteFile(hUtf8,utf8,utf8size-1,&utf8writen,NULL);
		    			OrgCloseHandle(hUtf8);
		    		}
		    		else 
		    		{
		    			OutputDebugStringEx("CreateFile %s Failed![Error=%ld]",hookfilename,GetLastError());
		    		}   		
		    		free(utf8);

		    		//update hash
		    		memcpy(si_file_info->orgmd5,fmd5,16);
				}

				free(buffer);
			}
		}
#endif
		strcpy(hookfilename,si_file_info->gbkfile);
	}
	
RECOVER:
	MByteToWChar(hookfilename, lpwszStr, 1024);
	handle = OrgCreateFileW(lpwszStr,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
									dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);

	if(gbkflag != 0)
	{
		SiHandle_Add(handle,gbkflag,(char *)orgfilename,hookfilename);		
	}
	
	return handle;
}

HANDLE WINAPI HookFindFirstFileW(
	LPCWSTR lpFileName,
	LPWIN32_FIND_DATA lpFindFileData
)
{
	HANDLE handle;
	int gbkflag = 0;
	unsigned char fmd5[16];
	char hookfilename[1024];
	char orgfilename[1024];
	wchar_t lpwszStr[1024];
	WIN32_FILE_ATTRIBUTE_DATA wfad;
	struct SiFileInfo* si_file_info = NULL;

	handle = OrgFindFirstFileW(lpFileName, lpFindFileData);
	return handle;
	memset(&wfad, 0, sizeof(wfad));
	memset(hookfilename,0,sizeof(hookfilename));
	memset(orgfilename, 0, sizeof(orgfilename));
	WCharToMByte(lpFileName, hookfilename, 1024);
	WCharToMByte(lpFileName, orgfilename, 1024);	
	unsigned long hash = HashString(orgfilename);
	si_file_info = FindSiFileFromLink(hash);
OutputDebugStringEx("FindFirstFileW %s", orgfilename); 
	if(si_file_info == NULL)
	{
		HANDLE hFile = OrgCreateFileW(lpFileName,
								GENERIC_READ,
    							FILE_SHARE_READ,
    							NULL,
    							OPEN_EXISTING,
    							FILE_ATTRIBUTE_NORMAL,
    							NULL);
    	if(hFile == INVALID_HANDLE_VALUE)
    	{
    		OutputDebugStringEx("Function: %s OrgCreateFileW1 %s Failed[%d]",__FUNCTION__,orgfilename,GetLastError());
    		goto RECOVER;
    	} 	
    	DWORD fread;
    	DWORD fsize = GetFileSize(hFile,NULL);
    	char* buffer = (char*)malloc(fsize+1);
    	memset(buffer,0,fsize+1);
    	if(fsize > 0)
    	{
    		ReadFile(hFile,buffer,fsize,&fread,NULL);
    	}
    	OrgCloseHandle(hFile);	
    	gbkflag = IsGBK(buffer,fsize);	
	    	
    	//convert
    	if(gbkflag != 0)
    	{    		
    		DWORD utf8size = 0;
    		DWORD utf8writen;
    		char* utf8 = (char *)malloc(2*fsize+1);
    		gbk_to_utf8(buffer, utf8, &utf8size);		
    		GetTmpFilename(hash,hookfilename);
    		MByteToWChar(hookfilename, lpwszStr, 1024);
    		HANDLE hUtf8 = OrgCreateFileW(lpwszStr,
								GENERIC_WRITE,
    							0,
    							NULL,
    							CREATE_ALWAYS,
    							FILE_ATTRIBUTE_NORMAL,
    							NULL);    							
    		if(hUtf8 != INVALID_HANDLE_VALUE)
    		{
    			WriteFile(hUtf8,utf8,utf8size-1,&utf8writen,NULL);
    			//sync time
    			GetFileAttributesExW(lpFileName, GetFileExInfoStandard, &wfad);
    			SetFileTime(hUtf8, &wfad.ftCreationTime, &wfad.ftLastAccessTime, &wfad.ftLastWriteTime);
    			if(lpFindFileData != NULL)
    			{
    				lpFindFileData->nFileSizeLow = utf8size-1;
    				lpFindFileData->nFileSizeHigh = 0;
    			}
    			OrgCloseHandle(hUtf8);
    		}
    		else 
    		{
    			OutputDebugStringEx("[%s]CreateFile %s Failed![Error=%ld]",__FUNCTION__,hookfilename,GetLastError());
    		}   		
    		free(utf8);	    		
    	}
    	//calc md5sum only gbk
    	if(gbkflag != 0)
    	{
    		memset(fmd5,0,sizeof(fmd5));
    		Md5Sum((unsigned char *)buffer,fsize,fmd5);
    	}
    	  	
    	free(buffer);
		SiFile_Add(hash,gbkflag,fmd5,(char *)orgfilename,hookfilename);
		//debug
		si_file_info = FindSiFileFromLink(hash);
		si_file_info->wfad = wfad;
	}
	else 
	{
		gbkflag = si_file_info->u8flag;
		//judge outside change
#if 0
		if(gbkflag != 0)
		{
			//if(dwDesiredAccess == GENERIC_READ)
			//why this change?
			//if(dwDesiredAccess == GENERIC_WRITE)
			{
				//read file
				HANDLE hFile = OrgCreateFileW(lpFileName,
								GENERIC_READ,
    							FILE_SHARE_READ,
    							NULL,
    							OPEN_EXISTING,
    							FILE_ATTRIBUTE_NORMAL,
    							NULL);
		    	if(hFile == INVALID_HANDLE_VALUE)
		    	{
		    		OutputDebugStringEx("Function :%s OrgCreateFile2 %s Failed[%d]",__FUNCTION__,orgfilename,GetLastError());
		    		goto RECOVER;
		    	}    	
		    	DWORD fread;
		    	DWORD fsize = GetFileSize(hFile,NULL);
		    	char* buffer = (char*)malloc(fsize+1);
		    	memset(buffer,0,fsize+1);
		    	ReadFile(hFile,buffer,fsize,&fread,NULL);
		    	OrgCloseHandle(hFile);

		    	//calc md5sum
		    	memset(fmd5,0,sizeof(fmd5));
				Md5Sum((unsigned char *)buffer,fsize,fmd5);
				if(memcmp(fmd5,si_file_info->orgmd5,16) != 0)
				{
					OutputDebugStringEx("gbk[%s] Changed outside!",orgfilename);
		    		DWORD utf8size = 0;
		    		DWORD utf8writen;
		    		char* utf8 = (char *)malloc(2*fsize+1);
		    		gbk_to_utf8(buffer, utf8, &utf8size);
		    		GetTmpFilename(hash,hookfilename);
		    		MByteToWChar(hookfilename, lpwszStr, 1024);
		    		HANDLE hUtf8 = OrgCreateFileW(lpwszStr,
										GENERIC_WRITE,
		    							0,
		    							NULL,
		    							CREATE_ALWAYS,
		    							FILE_ATTRIBUTE_NORMAL,
		    							NULL);    							
		    		if(hUtf8 != INVALID_HANDLE_VALUE)
		    		{
		    			WriteFile(hUtf8,utf8,utf8size-1,&utf8writen,NULL);
		    			OrgCloseHandle(hUtf8);
		    		}
		    		else 
		    		{
		    			OutputDebugStringEx("CreateFile %s Failed![Error=%ld]",hookfilename,GetLastError());
		    		}   		
		    		free(utf8);

		    		//update hash
		    		memcpy(si_file_info->orgmd5,fmd5,16);
				}

				free(buffer);
			}
		}
#endif
		strcpy(hookfilename,si_file_info->gbkfile);
	}
	
RECOVER:
	if(gbkflag != 0)
	{
		SiHandle_Add(handle,gbkflag,(char *)orgfilename,hookfilename);		
	}
	
	return handle;
}



BOOL WINAPI HookCloseHandle(
	HANDLE hObject
)
{
	BOOL rtv;

	SiHandle_Del(hObject);
	rtv = OrgCloseHandle(hObject);
	
	return rtv;
}

BOOL WINAPI HookSetEndOfFile(
	HANDLE hFile
)
{
	BOOL rtv;
	
	rtv = OrgSetEndOfFile(hFile);
	
	struct SiHandleInfo* si_handle_info = NULL;
	si_handle_info = FindSiHandleFromLink(hFile);
	if(si_handle_info != NULL)
	{
		//读文件
		DWORD fread;
		DWORD fsize = SetFilePointer(hFile,0,NULL,FILE_CURRENT);
		char* utf8 = (char *)malloc(fsize+1);
		memset(utf8,0,fsize+1);
		SetFilePointer(hFile,0,NULL,FILE_BEGIN);
		ReadFile(hFile,utf8,fsize,&fread,NULL);
		SetFilePointer(hFile,fsize,NULL,FILE_BEGIN);
    	
    	//转成gbk
    	DWORD gbksize = 0;
    	DWORD gbkwriten;
    	char* gbk = (char *)malloc(fsize+1);
    	memset(gbk,0,fsize+1);
    	if(si_handle_info->u8flag == 1)
    		utf8_to_gbk(utf8, gbk, &gbksize);
    	else 
    	{
    		OutputDebugStringEx("Function :%s Error HandleInfo!",__FUNCTION__);
    	}
    		
    	//写回gbk
    	wchar_t wstr[1025];
    	MByteToWChar(si_handle_info->orgfile, wstr, 1024);
    	HANDLE hGbk = OrgCreateFileW(wstr,
								GENERIC_WRITE,
    							FILE_SHARE_READ | FILE_SHARE_WRITE,
    							NULL,
    							CREATE_ALWAYS,
    							FILE_ATTRIBUTE_NORMAL,
    							NULL);    							
		if(hGbk != INVALID_HANDLE_VALUE)
		{
			WriteFile(hGbk,gbk,gbksize-1,&gbkwriten,NULL);
			OrgCloseHandle(hGbk);
		}
		else 
		{
			OutputDebugStringEx("[%s]CreateFile %s Failed![Error=%ld]",__FUNCTION__,si_handle_info->orgfile,GetLastError());
			OutputDebugStringEx("%s", si_handle_info->gbkfile);
		}

		//update md5
		unsigned long hash = HashString(si_handle_info->orgfile);
		struct SiFileInfo* si_file_info = FindSiFileFromLink(hash);
		unsigned char fmd5[16];
		memset(fmd5,0,sizeof(fmd5));
		Md5Sum((unsigned char *)gbk,gbksize-1,fmd5);
		memcpy(si_file_info->orgmd5,fmd5,16);
		
		free(utf8);
		free(gbk);
	}
	
	return rtv;
}


BOOL HookWinApi(void)
{
	OrgCreateFileA = (CreateFileAFn)HookFunction("kernel32.dll","CreateFileA",(void *)HookCreateFileA);
	if(OrgCreateFileA == NULL)
	{
		OutputDebugString("Hook CreateFileA Failed!");
		return FALSE;
	}

	OrgCreateFileW = (CreateFileWFn)HookFunction("kernel32.dll","CreateFileW",(void *)HookCreateFileW);
	if(OrgCreateFileW == NULL)
	{
		OutputDebugString("Hook CreateFileW Failed!");
		return FALSE;
	}

	OrgFindFirstFileW = (FindFirstFileWFn)HookFunction("kernel32.dll","FindFirstFileW",(void *)HookFindFirstFileW);
	if(OrgFindFirstFileW == NULL)
	{
		OutputDebugString("Hook OrgFindFirstFileW Failed!");
		return FALSE;
	}
	
	OrgCloseHandle = (CloseHandleFn)HookFunction("kernel32.dll","CloseHandle",(void *)HookCloseHandle);
	if(OrgCloseHandle == NULL)
	{
		OutputDebugString("Hook CloseHandle Failed!");
		return FALSE;
	}
	
	OrgSetEndOfFile = (SetEndOfFileFn)HookFunction("kernel32.dll","SetEndOfFile",(void *)HookSetEndOfFile);
	if(OrgSetEndOfFile == NULL)
	{
		OutputDebugString("Hook SetEndOfFile Failed!");
		return FALSE;
	}
	
	return TRUE;
}
