#include "hack.h"
#include "hook/hookapi.h"
#include <Wincrypt.h>

typedef BOOL (WINAPI* CryptVerifySignatureWFn)(
	HCRYPTHASH hHash,
	BYTE       *pbSignature,
	DWORD      dwSigLen,
	HCRYPTKEY  hPubKey,
	LPCWSTR    sDescription,
	DWORD      dwFlags
);

CryptVerifySignatureWFn OrgCryptVerifySignatureW = NULL;

BOOL WINAPI HookCryptVerifySignatureW(
	HCRYPTHASH hHash,
	BYTE       *pbSignature,
	DWORD      dwSigLen,
	HCRYPTKEY  hPubKey,
	LPCWSTR    sDescription,
	DWORD      dwFlags
)
{
	return TRUE;
}


BOOL HackSI4(void)
{
	OrgCryptVerifySignatureW = (CryptVerifySignatureWFn)HookFunction("Advapi32.dll","CryptVerifySignatureW",(void *)HookCryptVerifySignatureW);
	if(OrgCryptVerifySignatureW == NULL)
	{
		OutputDebugString("Hook CryptVerifySignatureW Failed!");
		return FALSE;
	}

	return TRUE;
}
