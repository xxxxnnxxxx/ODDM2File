#include <Windows.h>
#include "_pe.h"
#include <Plugin.h>

int	is_pefile(char *pebase)
{
	int	ret=0;
	IMAGE_DOS_HEADER dosHeader={0};
	IMAGE_NT_HEADERS32 ntHeader={0};
	unsigned int readlen=0;

	readlen=Readmemory((void*)&dosHeader,(unsigned long)pebase,sizeof(IMAGE_DOS_HEADER),MM_RESILENT);
	if(readlen==0)
		return 0;

	readlen=Readmemory((void*)&ntHeader,(unsigned long)pebase+dosHeader.e_lfanew,sizeof(IMAGE_NT_HEADERS32),MM_RESILENT);

	if(readlen==0)
		return 0;

	if(dosHeader.e_magic!=0x5A4D){
		ret=0;
		goto bail;
	}
	if(ntHeader.Signature==0x00004550){
		ret=1;
		goto bail;
	}

bail:
	return ret;
}

char * generate_pe(char *pebase,size_t *len)
{

	char *outbuf=(char*)0;
	int i=0;
	unsigned int readlen=0;
	//PE
	IMAGE_DOS_HEADER dosheader={0};
	IMAGE_NT_HEADERS32 ntheader={0};
	IMAGE_SECTION_HEADER current_section={0};
	int secnum=0;
	int headersize=0;

	readlen=Readmemory((void*)&dosheader,(unsigned long)pebase,sizeof(IMAGE_DOS_HEADER),MM_RESILENT);
	if(readlen==0)
		return (char*)0;

	readlen=Readmemory((void*)&ntheader,(unsigned long)pebase+dosheader.e_lfanew,sizeof(IMAGE_NT_HEADERS32),MM_RESILENT);

	if(readlen==0)
		return (char*)0;

	headersize=ntheader.OptionalHeader.SizeOfHeaders;

	outbuf=(char*)malloc(headersize);
	memset(outbuf,0,headersize);
	//wirte headers into the outputbuf
	readlen=Readmemory((void*)outbuf,(unsigned long)pebase,headersize,MM_RESILENT);
	if(readlen==0)
		return (char*)0;
	*len=headersize;
	


	secnum=ntheader.FileHeader.NumberOfSections;
	for(i=0;i<secnum;i++)
	{//enum secitons
		readlen=Readmemory((void*)&current_section,(unsigned long)pebase+dosheader.e_lfanew+sizeof(IMAGE_NT_HEADERS32)+i*sizeof(IMAGE_SECTION_HEADER),sizeof(IMAGE_SECTION_HEADER),MM_RESILENT);
		if(readlen==0)
			return (char*)0;

		//拷贝相应的节到地址
		outbuf=(char*)_recalloc(outbuf,current_section.PointerToRawData+current_section.Misc.VirtualSize,1);
		readlen=Readmemory(outbuf+current_section.PointerToRawData,(unsigned long)pebase+current_section.PointerToRawData,current_section.Misc.VirtualSize,MM_RESILENT);
		*len=current_section.PointerToRawData+current_section.Misc.VirtualSize;
	}

	return outbuf;

}