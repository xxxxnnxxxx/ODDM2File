// ODDM.cpp : Defines the exported functions for the DLL application.
//

#include <Windows.h>
#include <Plugin.h>
#include "resource.h"
#include "_pe.h"

#pragma comment(lib,"Ollydbg.lib")

HINSTANCE g_hInstance;
HWND	g_OllyDBGHWND;
//Input Dialog

/*
type	0: read the memory from dwBeginAddr to dwEndAddr
		1: read the memory as a PE file from dwBeginAddr
*/
char * ObtainDataFromMemory(DWORD dwBeginAddr,DWORD dwEndAddr,int type,DWORD *dwReaded)
{
	DWORD dwLen2Read=0;
	char * outbuf=(char*)0;
	unsigned int ret=0;
	if(type==0)
	{
		if(dwEndAddr<=dwBeginAddr)
			return (char*)0;

		dwLen2Read=dwEndAddr-dwBeginAddr;
		*dwReaded=dwLen2Read;
		outbuf=(char*)malloc(dwLen2Read);
		ret=Readmemory(outbuf,dwBeginAddr,dwLen2Read,MM_RESILENT);
		if(ret==0)
		{
			free(outbuf);
		}
		else
			return outbuf;
	}else if(type==1){
		//read the memory as a PE file
		if(is_pefile((char*)dwBeginAddr))
		{
			return generate_pe((char*)dwBeginAddr,dwReaded);
		}
	}
	return (char*)0;
}


DWORD GetAddress(HWND hWnd,UINT uID)
{
	DWORD dwAddress=0;
	DWORD dwAdd;
	char szAddress[256]={0};
	int ret=0;

	ret=GetDlgItemText(hWnd,uID,szAddress,256);
	if(ret!=0){
		char *padd=strchr(szAddress,'+');
		if(padd==NULL){
			dwAddress=strtol(szAddress,NULL,16);
		}
		else{
			char *add="+";
			dwAddress=strtol(szAddress,&add,16);
			dwAdd=strtol(padd+1,NULL,16);
			dwAddress+=dwAdd;
		}
	}

	return dwAddress;
}

BOOL CALLBACK MainDlgProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
	int status;
	switch(msg)
	{
	case WM_INITDIALOG:
		{
			//SetWindowPos(hWnd,HWND_TOPMOST,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE);
			status= SendDlgItemMessage(hWnd,IDC_CK_PE,BM_GETCHECK,0,0);
			EnableWindow(GetDlgItem(hWnd,IDC_ET_END),!status);
			return TRUE;
		}

		break;
	case WM_COMMAND:
		{
			switch(wParam)
			{
			case IDOK:
				{
					char szFile[1024]={0};
					int ret=0;
					ret=Browsefilename("Save dump to a file",szFile,"*.*",0x80);
					if(ret){
						DWORD dwBeginAddress,dwEndAddress;
						DWORD dwReaded=0;
						DWORD dwWrited=0;
						char *pMemory=NULL;

						dwBeginAddress=GetAddress(hWnd,IDC_ET_BEGIN);

						status= SendDlgItemMessage(hWnd,IDC_CK_PE,BM_GETCHECK,0,0);
						if(!status)
						{
							dwEndAddress=GetAddress(hWnd,IDC_ET_END);
						}

						//
						pMemory=ObtainDataFromMemory(dwBeginAddress,dwEndAddress,status,&dwReaded);
						if(pMemory!=NULL)
						{
							HANDLE hFile=CreateFileA(szFile,GENERIC_WRITE,FILE_SHARE_READ,
								NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
							if(hFile!=NULL){
								if(!WriteFile(hFile,pMemory,dwReaded,&dwWrited,NULL))
								{
									MessageBoxA(hWnd,"Write Failed","ODDM",MB_OK|MB_ICONWARNING);
								}
								CloseHandle(hFile);
							}

							free(pMemory);
							pMemory=NULL;
						}
	
					}
					EndDialog(hWnd,IDYES);
				}
				break;
			case IDCANCEL:
				{
					EndDialog(hWnd,IDNO);
				}

				break;
			case IDC_CK_PE:
				{
					status= SendDlgItemMessage(hWnd,IDC_CK_PE,BM_GETCHECK,0,0);
					EnableWindow(GetDlgItem(hWnd,IDC_ET_END),!status);
				}
				break;
			}
		}
		break;
	default:
		break;
	}

	return FALSE;
}

BOOL CALLBACK AboutDlgProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
	switch(msg)
	{
	case WM_INITDIALOG:
		return TRUE;
	case WM_COMMAND:
		{
			switch(wParam)
			{
			case IDCANCEL:
				EndDialog(hWnd,IDNO);
				break;
			default:
				break;
			}
		}
		break;
	case WM_CLOSE:
		EndDialog(hWnd,IDCLOSE);
		break;
	default:
		break;
	}

	return FALSE;
}

extc int _export cdecl ODBG_Plugindata(char shortname[32]) {
	strcpy_s(shortname,10,"ODDM2File");    // Name of command line plugin
	return PLUGIN_VERSION;
};

extc int _export cdecl ODBG_Plugininit(int ollydbgversion,HWND hw,ulong *features) 
{
	
	if(ollydbgversion<PLUGIN_VERSION)
		return -1;

	g_OllyDBGHWND=hw;
	return 0;
};
extc int _export cdecl ODBG_Pluginmenu(int origin,char data[4096],void *item) 
{ 
	if(origin != PM_MAIN) 
		return 0; 
	strcpy_s(data,28,"0 &DumpMemory2File|1 &About"); 
	return 1; 
}

extc void _export cdecl ODBG_Pluginaction(int origin,int action,void *item) 
{
	switch(origin)
	{
	case PM_MAIN:
		{
			switch (action)
			{
			case 0:
				{
					int ret=0;
					if((ret=Plugingetvalue(VAL_HPROCESS))==0)
					{
						MessageBoxA(g_OllyDBGHWND,"No exefile is debuged","ODDM2File",MB_OK|MB_ICONWARNING);
						return;
					}
					CreateDialogParamA(g_hInstance,MAKEINTRESOURCEA(IDD_Main),g_OllyDBGHWND,MainDlgProc,0);
				}
				break;
			case 1://about
				{
					DialogBoxA(g_hInstance,MAKEINTRESOURCEA(IDD_ABOUT),g_OllyDBGHWND,AboutDlgProc);
				}
				break;
			default:
				break;
			}
		}
		break;
	case PM_DISASM:
		{
			t_dump *pdump=(t_dump*)item;
			if(pdump!=NULL)
			{

			}
		}
		break;
	}
	
}