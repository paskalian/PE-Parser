#pragma once

#include "Includes.h"

#define PRSR_CAPTION "Parser"

#define PRSR_MAIN ImGuiWindowFlags_AlwaysHorizontalScrollbar | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus
#define PRSR_MISC ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoResize
#define PRSR_ABOUT ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize
#define PRSR_TOOLTIP (ImGui::IsItemHovered() && ImGui::IsMouseDown(ImGuiMouseButton_Middle))
#define PRSR_DETAIL (ImGui::IsItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Right))

#define PRSR_HEXBYTEAMNT 0x1000

extern HWND* g_pMainWnd;
extern std::vector<BYTE> OpenedFile;
extern CHAR g_FileName[MAX_PATH];

extern PIMAGE_DOS_HEADER g_pDosHeader;
extern PIMAGE_NT_HEADERS g_pNtHeaders;
extern PIMAGE_FILE_HEADER g_pFileHeader;
extern PIMAGE_OPTIONAL_HEADER g_pOptionalHeader;

using PARSER_CALLBACK = void(__fastcall*)();
extern PARSER_CALLBACK g_FDetails;
void __fastcall DTL_DFT();

namespace Parser 
{
	BOOLEAN OpenFile(std::vector<BYTE>& OpenedFile);
	BOOLEAN CheckFile(const std::vector<BYTE>& OpenedFile);
	BOOLEAN Render();

	namespace Helpers
	{
		VOID Parse(DWORD BaseOffset, WORD Id);
		VOID ParseExportDir(DWORD BaseOffset);
		VOID ParseImportDir(DWORD BaseOffset);
		VOID ParseRsrcDir(DWORD BaseOffset);
		VOID ParseExceptionDir(DWORD BaseOffset);
		VOID ParseSecurityDir(DWORD BaseOffset);
		VOID ParseBaseRelocDir(DWORD BaseOffset);
		VOID ParseDebugDir(DWORD BaseOffset);
		// Architecture
		// GlobalPtr
		VOID ParseTlsDir(DWORD BaseOffset);
		VOID ParseLoadCfgDir(DWORD BaseOffset);
		VOID ParseBoundImportDir(DWORD BaseOffset);
		VOID ParseIATDir(DWORD BaseOffset);
		VOID ParseDelayLoadImportDir(DWORD BaseOffset);
		VOID ParseCOMDir(DWORD BaseOffset);

		DWORD RVAToFileOffset(DWORD RVA);
	}
}