#pragma once

#include "Includes.h"

#define CV_SIGNATURE_NB10 '01BN'
#define CV_SIGNATURE_RSDS 'SDSR'

typedef struct _CV_INFO_PDB20 
{
	DWORD	CvSignature;
	DWORD	Offset;
	DWORD	Signature;
	DWORD	Age;
	CHAR	PdbFileName[MAX_PATH];
} CV_INFO_PDB20, *PCV_INFO_PDB20;

typedef struct _CV_INFO_PDB70 {
	DWORD	CvSignature;
	GUID	Signature;
	DWORD	Age;
	CHAR	PdbFileName[MAX_PATH];
} CV_INFO_PDB70, *PCV_INFO_PDB70;