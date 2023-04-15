#pragma once

#include "Includes.h"

#define PRSR_CAPTION "Parser"

#define PRSR_MAIN ImGuiWindowFlags_AlwaysHorizontalScrollbar | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus
#define PRSR_MISC ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoResize
#define PRSR_ABOUT ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize
#define PRSR_TOOLTIP (ImGui::IsItemHovered() && ImGui::IsMouseDown(ImGuiMouseButton_Middle))

#define PRSR_HEXBYTEAMNT 0x1000

extern HWND* g_pMainWnd;
extern std::vector<BYTE> OpenedFile;
extern CHAR g_FileName[MAX_PATH];

namespace Parser 
{
	BOOLEAN OpenFile(std::vector<BYTE>& OpenedFile);
	BOOLEAN CheckFile(const std::vector<BYTE>& OpenedFile);
	BOOLEAN Render();

	namespace Helpers
	{
		DWORD RVAToFileOffset(DWORD RVA);
	}
}