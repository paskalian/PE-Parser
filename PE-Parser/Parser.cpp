#include "Parser.h"

HWND* g_pMainWnd = nullptr;
std::vector<BYTE> g_OpenedFile(0);
CHAR g_FileName[MAX_PATH] = {};

PIMAGE_DOS_HEADER g_pDosHeader = nullptr;
PIMAGE_NT_HEADERS g_pNtHeaders = nullptr;
PIMAGE_FILE_HEADER g_pFileHeader = nullptr;
PIMAGE_OPTIONAL_HEADER g_pOptionalHeader = nullptr;

BOOLEAN g_bShowAbout = FALSE;
BOOLEAN Parser::OpenFile(OUT std::vector<BYTE>& OpenedFile)
{
	OPENFILENAMEW ofn;
	ZeroMemory(&ofn, sizeof(ofn));

	wchar_t szFile[MAX_PATH];
	
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = *g_pMainWnd;
	ofn.lpstrFile = szFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = L"All Files\0*.*\0PE Files\0*.EXE;.DLL;.SYS*\0\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (GetOpenFileNameW(&ofn))
	{
		HANDLE FileHandle = CreateFileW(ofn.lpstrFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (FileHandle == INVALID_HANDLE_VALUE)
			return false;

		LARGE_INTEGER FileSize = {};
		if (!GetFileSizeEx(FileHandle, &FileSize))
		{
			CloseHandle(FileHandle);
			return false;
		}

		std::vector<BYTE> FileBytes(FileSize.QuadPart);

		DWORD BytesRead = 0;
		if (!ReadFile(FileHandle, &FileBytes[0], FileSize.QuadPart, &BytesRead, NULL))
		{
			CloseHandle(FileHandle);
			return false;
		}

		if (Parser::CheckFile(FileBytes))
		{
			OpenedFile.clear();
			OpenedFile = FileBytes;

			g_pDosHeader = (PIMAGE_DOS_HEADER)&g_OpenedFile[0];
			g_pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)g_pDosHeader + g_pDosHeader->e_lfanew);
			g_pFileHeader = &g_pNtHeaders->FileHeader;
			g_pOptionalHeader = &g_pNtHeaders->OptionalHeader;

			memset(g_FileName, 0, sizeof(g_FileName));

			size_t NumberOfCharConverted = 0;
			wcstombs_s(&NumberOfCharConverted, g_FileName, ofn.lpstrFile, MAX_PATH - 1);
		}
		else
			MessageBoxA(*g_pMainWnd, "Invalid file", PRSR_CAPTION, MB_OK);

		CloseHandle(FileHandle);
		return true;
	}

	return true;
}

BOOLEAN Parser::CheckFile(const std::vector<BYTE>& OpenedFile)
{
	const PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)&OpenedFile[0];
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	const PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	const PIMAGE_FILE_HEADER pFileHeader = &pNtHeaders->FileHeader;
	if (pFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64 && pFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
		return FALSE;

	const PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeaders->OptionalHeader;
	if (pOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
	{
#ifdef _WIN64
		MessageBoxA(*g_pMainWnd, "Open this file in 32-bit parser.", PRSR_CAPTION, MB_OK);
#else
		MessageBoxA(*g_pMainWnd, "Open this file in 64-bit parser.", PRSR_CAPTION, MB_OK);
#endif
		
		return FALSE;
	}

	return TRUE;
}

BOOLEAN Parser::Render()
{
	BOOLEAN Status = TRUE;

    static ImGuiViewport* viewport = ImGui::GetMainViewport();
	ImGui::SetNextWindowPos(viewport->Pos, true, ImVec2(0, 0));

    ImGui::Begin("Main Area", NULL, PRSR_MAIN);

	ImVec2 MainAreaSize = ImGui::GetWindowSize();
	ImGui::SetWindowSize(ImVec2(MainAreaSize.x, viewport->Size.y));

    if (ImGui::BeginMenuBar())
    {
        if (ImGui::BeginMenu("Main"))
        {
            if (ImGui::MenuItem("Open File"))
            {
				Status = Parser::OpenFile(g_OpenedFile);
            }
            if (ImGui::MenuItem("About"))
            {
				g_bShowAbout = ~g_bShowAbout;
            }
            if (ImGui::MenuItem("Exit"))
            {

            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

	// Parsing PE header.
	if (g_OpenedFile.size())
	{
		ImGui::TextWrapped("[File Path]\n%s (%s-bit)", g_FileName, g_pOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "64" : "32");

		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();

		ImGui::Text("Directories");

		ImGui::Separator();
		ImGui::Spacing();

		// Parsing the dos header.
		bool Collapsing_ImageDosHeader = ImGui::TreeNode("IMAGE_DOS_HEADER");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", 0);

		if (Collapsing_ImageDosHeader)
		{
			ImGui::BulletText("[%s] e_magic: 0x%X", "WORD", g_pDosHeader->e_magic);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_magic));

			ImGui::BulletText("[%s] e_cblp: 0x%X", "WORD", g_pDosHeader->e_cblp);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_cblp));

			ImGui::BulletText("[%s] e_cp: 0x%X", "WORD", g_pDosHeader->e_cp);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_cp));

			ImGui::BulletText("[%s] e_crlc: 0x%X", "WORD", g_pDosHeader->e_crlc);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_crlc));

			ImGui::BulletText("[%s] e_cparhdr: 0x%X", "WORD", g_pDosHeader->e_cparhdr);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_cparhdr));

			ImGui::BulletText("[%s] e_minalloc: 0x%X", "WORD", g_pDosHeader->e_minalloc);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_minalloc));

			ImGui::BulletText("[%s] e_maxalloc: 0x%X", "WORD", g_pDosHeader->e_maxalloc);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_maxalloc));

			ImGui::BulletText("[%s] e_ss: 0x%X", "WORD", g_pDosHeader->e_ss);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_ss));

			ImGui::BulletText("[%s] e_sp: 0x%X", "WORD", g_pDosHeader->e_sp);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_sp));

			ImGui::BulletText("[%s] e_csum: 0x%X", "WORD", g_pDosHeader->e_csum);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_csum));

			ImGui::BulletText("[%s] e_ip: 0x%X", "WORD", g_pDosHeader->e_ip);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_ip));

			ImGui::BulletText("[%s] e_cs: 0x%X", "WORD", g_pDosHeader->e_cs);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_cs));

			ImGui::BulletText("[%s] e_lfarlc: 0x%X", "WORD", g_pDosHeader->e_lfarlc);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_lfarlc));

			ImGui::BulletText("[%s] e_ovno: 0x%X", "WORD", g_pDosHeader->e_ovno);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_ovno));

			bool Collapsing_ImageDosHeader_eres = ImGui::TreeNode(static_cast<void*>(nullptr), "[%s] e_res[4]", "WORD");
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_res));

			if (Collapsing_ImageDosHeader_eres)
			{
				for (int i = 0; i < ARRAYSIZE(g_pDosHeader->e_res); i++)
				{
					ImGui::BulletText("[%s] e_res[%i]: 0x%X", "WORD", i, g_pDosHeader->e_res[i]);
					if (PRSR_TOOLTIP)
						ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_res[i]));
				}
				ImGui::TreePop();
			}
			
			ImGui::BulletText("[%s] e_oemid: 0x%X", "WORD", g_pDosHeader->e_oemid);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_oemid));

			ImGui::BulletText("[%s] e_oeminfo: 0x%X", "WORD", g_pDosHeader->e_oeminfo);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_oeminfo));

			bool Collapsing_ImageDosHeader_eres2 = ImGui::TreeNode(static_cast<void*>(nullptr), "[%s] e_res2[10]", "WORD");
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_res2));

			if (Collapsing_ImageDosHeader_eres2)
			{
				for (int i = 0; i < ARRAYSIZE(g_pDosHeader->e_res2); i++)
				{
					ImGui::BulletText("[%s] e_res2[%i]: 0x%X", "WORD", i, g_pDosHeader->e_res2[i]);
					if (PRSR_TOOLTIP)
						ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_res2[i]));
				}
				ImGui::TreePop();
			}

			ImGui::BulletText("[%s] e_lfanew: 0x%X", "LONG", g_pDosHeader->e_lfanew);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", offsetof(IMAGE_DOS_HEADER, e_lfanew));

			ImGui::TreePop();
		}

		// BaseOffset representing the File Offset of a structure.
		DWORD BaseOffset = (BYTE*)g_pNtHeaders - (BYTE*)g_pDosHeader;

		// Parsing the nt header.
		bool Collapsing_ImageNtHeaders = ImGui::TreeNode("IMAGE_NT_HEADERS");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_NT_HEADERS, Signature));

		if (Collapsing_ImageNtHeaders)
		{
			ImGui::BulletText("[%s] Signature: 0x%X", "DWORD", g_pNtHeaders->Signature);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_NT_HEADERS, Signature));

			ImGui::BulletText("[%s] FileHeader: 0x%X", "IMAGE_FILE_HEADER", &g_pNtHeaders->FileHeader);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_NT_HEADERS, FileHeader));

			ImGui::BulletText("[%s] OptionalHeader: 0x%X", "IMAGE_OPTIONAL_HEADER", &g_pNtHeaders->OptionalHeader);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_NT_HEADERS, OptionalHeader));

			ImGui::TreePop();
		}

		BaseOffset = (BYTE*)g_pFileHeader - (BYTE*)g_pDosHeader;

		// Parsing the file header.
		bool Collapsing_ImageFileHeader = ImGui::TreeNode("IMAGE_FILE_HEADER");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_FILE_HEADER, Machine));

		if (Collapsing_ImageFileHeader)
		{
			ImGui::BulletText("[%s] Machine: 0x%X", "WORD", g_pFileHeader->Machine);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_FILE_HEADER, Machine));

			ImGui::BulletText("[%s] NumberOfSections: 0x%X", "WORD", g_pFileHeader->NumberOfSections);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_FILE_HEADER, NumberOfSections));

			ImGui::BulletText("[%s] TimeDateStamp: 0x%X", "DWORD", g_pFileHeader->TimeDateStamp);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_FILE_HEADER, TimeDateStamp));

			ImGui::BulletText("[%s] PointerToSymbolTable: 0x%X", "DWORD", g_pFileHeader->PointerToSymbolTable);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_FILE_HEADER, PointerToSymbolTable));

			ImGui::BulletText("[%s] NumberOfSymbols: 0x%X", "DWORD", g_pFileHeader->NumberOfSymbols);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_FILE_HEADER, NumberOfSymbols));

			ImGui::BulletText("[%s] SizeOfOptionalHeader: 0x%X", "WORD", g_pFileHeader->SizeOfOptionalHeader);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader));

			ImGui::BulletText("[%s] Characteristics: 0x%X", "WORD", g_pFileHeader->Characteristics);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_FILE_HEADER, Characteristics));

			ImGui::TreePop();
		}

		BaseOffset = (BYTE*)g_pOptionalHeader - (BYTE*)g_pDosHeader;

		// Parsing the optional header.
		bool Collapsing_ImageOptionalHeader = ImGui::TreeNode("IMAGE_OPTIONAL_HEADER");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, Magic));

		if (Collapsing_ImageOptionalHeader)
		{
			ImGui::BulletText("[%s] Magic: 0x%X", "WORD", g_pOptionalHeader->Magic);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, Magic));

			ImGui::BulletText("[%s] MajorLinkerVersion: 0x%X", "BYTE", g_pOptionalHeader->MajorLinkerVersion);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, MajorLinkerVersion));

			ImGui::BulletText("[%s] MinorLinkerVersion: 0x%X", "BYTE", g_pOptionalHeader->MinorLinkerVersion);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, MinorLinkerVersion));

			ImGui::BulletText("[%s] SizeOfCode: 0x%X", "DWORD", g_pOptionalHeader->SizeOfCode);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfCode));

			ImGui::BulletText("[%s] SizeOfInitializedData: 0x%X", "DWORD", g_pOptionalHeader->SizeOfInitializedData);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfInitializedData));

			ImGui::BulletText("[%s] SizeOfUninitializedData: 0x%X", "DWORD", g_pOptionalHeader->SizeOfUninitializedData);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfUninitializedData));

			ImGui::BulletText("[%s] AddressOfEntryPoint: 0x%X", "DWORD", g_pOptionalHeader->AddressOfEntryPoint);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, AddressOfEntryPoint));

			ImGui::BulletText("[%s] BaseOfCode: 0x%X", "DWORD", g_pOptionalHeader->BaseOfCode);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, BaseOfCode));

#ifdef _WIN64
			ImGui::BulletText("[%s] ImageBase: 0x%X", "ULONGLONG", g_pOptionalHeader->ImageBase);
#else
			ImGui::BulletText("[%s] ImageBase: 0x%X", "ULONG", g_pOptionalHeader->ImageBase);
#endif
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, ImageBase));

			ImGui::BulletText("[%s] SectionAlignment: 0x%X", "DWORD", g_pOptionalHeader->SectionAlignment);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, SectionAlignment));

			ImGui::BulletText("[%s] FileAlignment: 0x%X", "DWORD", g_pOptionalHeader->FileAlignment);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, FileAlignment));

			ImGui::BulletText("[%s] MajorOperatingSystemVersion: 0x%X", "WORD", g_pOptionalHeader->MajorOperatingSystemVersion);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, MajorOperatingSystemVersion));

			ImGui::BulletText("[%s] MinorOperatingSystemVersion: 0x%X", "WORD", g_pOptionalHeader->MinorOperatingSystemVersion);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, MinorOperatingSystemVersion));

			ImGui::BulletText("[%s] MajorImageVersion: 0x%X", "WORD", g_pOptionalHeader->MajorImageVersion);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, MajorImageVersion));

			ImGui::BulletText("[%s] MinorImageVersion: 0x%X", "WORD", g_pOptionalHeader->MinorImageVersion);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, MinorImageVersion));

			ImGui::BulletText("[%s] MajorSubsystemVersion: 0x%X", "WORD", g_pOptionalHeader->MajorSubsystemVersion);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, MajorSubsystemVersion));

			ImGui::BulletText("[%s] MinorSubsystemVersion: 0x%X", "WORD", g_pOptionalHeader->MinorSubsystemVersion);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, MinorSubsystemVersion));

			ImGui::BulletText("[%s] Win32VersionValue: 0x%X", "DWORD", g_pOptionalHeader->Win32VersionValue);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, Win32VersionValue));

			ImGui::BulletText("[%s] SizeOfImage: 0x%X", "DWORD", g_pOptionalHeader->SizeOfImage);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfImage));

			ImGui::BulletText("[%s] SizeOfHeaders: 0x%X", "DWORD", g_pOptionalHeader->SizeOfHeaders);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfHeaders));

			ImGui::BulletText("[%s] CheckSum: 0x%X", "DWORD", g_pOptionalHeader->CheckSum);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, CheckSum));

			ImGui::BulletText("[%s] Subsystem: 0x%X", "WORD", g_pOptionalHeader->Subsystem);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, Subsystem));

			ImGui::BulletText("[%s] DllCharacteristics: 0x%X", "WORD", g_pOptionalHeader->DllCharacteristics);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, DllCharacteristics));

#ifdef _WIN64
			ImGui::BulletText("[%s] SizeOfStackReserve: 0x%X", "ULONGLONG", g_pOptionalHeader->SizeOfStackReserve);
#else
			ImGui::BulletText("[%s] SizeOfStackReserve: 0x%X", "ULONG", g_pOptionalHeader->SizeOfStackReserve);
#endif
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfStackReserve));

#ifdef _WIN64
			ImGui::BulletText("[%s] SizeOfStackCommit: 0x%X", "ULONGLONG", g_pOptionalHeader->SizeOfStackCommit);
#else
			ImGui::BulletText("[%s] SizeOfStackCommit: 0x%X", "ULONG", g_pOptionalHeader->SizeOfStackCommit);
#endif
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfStackCommit));

#ifdef _WIN64
			ImGui::BulletText("[%s] SizeOfHeapReserve: 0x%X", "ULONGLONG", g_pOptionalHeader->SizeOfHeapReserve);
#else
			ImGui::BulletText("[%s] SizeOfHeapReserve: 0x%X", "ULONG", g_pOptionalHeader->SizeOfHeapReserve);
#endif
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfHeapReserve));

#ifdef _WIN64
			ImGui::BulletText("[%s] SizeOfHeapCommit: 0x%X", "ULONGLONG", g_pOptionalHeader->SizeOfHeapCommit);
#else
			ImGui::BulletText("[%s] SizeOfHeapCommit: 0x%X", "ULONG", g_pOptionalHeader->SizeOfHeapCommit);
#endif
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, SizeOfHeapCommit));

			ImGui::BulletText("[%s] LoaderFlags: 0x%X", "DWORD", g_pOptionalHeader->LoaderFlags);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, LoaderFlags));

			ImGui::BulletText("[%s] NumberOfRvaAndSizes: 0x%X", "DWORD", g_pOptionalHeader->NumberOfRvaAndSizes);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, NumberOfRvaAndSizes));

			bool Collapsing_ImageOptionalHeader_DataDirectory = ImGui::TreeNode("[IMAGE_DATA_DIRECTORY] DataDirectory[16]");
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory));

			if (Collapsing_ImageOptionalHeader_DataDirectory)
			{
				// Parsing the optional header's data directories. Actual implementations made elsewhere.
				static std::vector<char*> Collapsing_ImageOptionalHeader_DataDirectoryIds(16);
				for (int i = 0; i < ARRAYSIZE(g_pOptionalHeader->DataDirectory); i++)
				{
					PIMAGE_DATA_DIRECTORY pDataDirectoryIdx = &g_pOptionalHeader->DataDirectory[i];

					BaseOffset = (BYTE*)pDataDirectoryIdx - (BYTE*)g_pDosHeader;

					bool Collapsing_ImageOptionalHeader_DataDirectoryIdx = ImGui::TreeNode(&Collapsing_ImageOptionalHeader_DataDirectoryIds[i], "[%s] DataDirectory[%i]: 0x%X", "IMAGE_DATA_DIRECTORY", i, pDataDirectoryIdx);
					if (PRSR_TOOLTIP)
						ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DATA_DIRECTORY, VirtualAddress));
					
					if (Collapsing_ImageOptionalHeader_DataDirectoryIdx)
					{
						ImGui::BulletText("[%s] VirtualAddress: 0x%X", "DWORD", pDataDirectoryIdx->VirtualAddress);
						if (PRSR_TOOLTIP)
							ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DATA_DIRECTORY, VirtualAddress));

						ImGui::BulletText("[%s] Size: 0x%X", "DWORD", pDataDirectoryIdx->Size);
						if (PRSR_TOOLTIP)
							ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DATA_DIRECTORY, Size));

						ImGui::TreePop();
					}
				}

				ImGui::TreePop();
			}

			ImGui::TreePop();
		}

		// Parsing all sections.
		static std::vector<char*> Collapsing_ImageSectionHeaderIds(g_pFileHeader->NumberOfSections);
		Collapsing_ImageSectionHeaderIds.resize(g_pFileHeader->NumberOfSections);
		for (int i = 0; i < g_pFileHeader->NumberOfSections; i++)
		{
			const PIMAGE_SECTION_HEADER pIdxSection = &IMAGE_FIRST_SECTION(g_pNtHeaders)[i];

			BaseOffset = (BYTE*)pIdxSection - (BYTE*)g_pDosHeader;

			// Section names aren't guaranteed to be null-terminated (\0) so we guarantee it.
			std::string SectionName = (char*)pIdxSection->Name;
			SectionName.resize(8);

			const bool Collapsing_ImageSectionHeaderIdx = ImGui::TreeNode(&Collapsing_ImageSectionHeaderIds[i], "IMAGE_SECTION_HEADER (%s)", SectionName.c_str());
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_SECTION_HEADER, Name));

			if (Collapsing_ImageSectionHeaderIdx)
			{
				ImGui::BulletText("[%s] Name[8]: %s", "CHAR", SectionName.c_str());
				if (PRSR_TOOLTIP)
					ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_SECTION_HEADER, Name));

				ImGui::BulletText("[%s] VirtualSize: 0x%X", "DWORD", pIdxSection->Misc.VirtualSize);
				if (PRSR_TOOLTIP)
					ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_SECTION_HEADER, Misc.VirtualSize));

				ImGui::BulletText("[%s] VirtualAddress: 0x%X", "DWORD", pIdxSection->VirtualAddress);
				if (PRSR_TOOLTIP)
					ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_SECTION_HEADER, VirtualAddress));

				ImGui::BulletText("[%s] SizeOfRawData: 0x%X", "DWORD", pIdxSection->SizeOfRawData);
				if (PRSR_TOOLTIP)
					ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_SECTION_HEADER, SizeOfRawData));

				ImGui::BulletText("[%s] PointerToRawData: 0x%X", "DWORD", pIdxSection->PointerToRawData);
				if (PRSR_TOOLTIP)
					ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_SECTION_HEADER, PointerToRawData));

				ImGui::BulletText("[%s] PointerToRelocations: 0x%X", "DWORD", pIdxSection->PointerToRelocations);
				if (PRSR_TOOLTIP)
					ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_SECTION_HEADER, PointerToRelocations));

				ImGui::BulletText("[%s] PointerToLinenumbers: 0x%X", "DWORD", pIdxSection->PointerToLinenumbers);
				if (PRSR_TOOLTIP)
					ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_SECTION_HEADER, PointerToLinenumbers));

				ImGui::BulletText("[%s] NumberOfRelocations: 0x%X", "WORD", pIdxSection->NumberOfRelocations);
				if (PRSR_TOOLTIP)
					ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_SECTION_HEADER, NumberOfRelocations));

				ImGui::BulletText("[%s] NumberOfLinenumbers: 0x%X", "WORD", pIdxSection->NumberOfLinenumbers);
				if (PRSR_TOOLTIP)
					ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_SECTION_HEADER, NumberOfLinenumbers));

				ImGui::BulletText("[%s] Characteristics: 0x%X", "DWORD", pIdxSection->Characteristics);
				if (PRSR_TOOLTIP)
				{
					ImGui::BeginTooltip();

					ImGui::Text("Offset: 0x%X", BaseOffset + offsetof(IMAGE_SECTION_HEADER, Characteristics));

					ImGui::NewLine();

					const DWORD Characteristics = pIdxSection->Characteristics;
					if (Characteristics & IMAGE_SCN_TYPE_NO_PAD)
						ImGui::BulletText("IMAGE_SCN_TYPE_NO_PAD (0x%X)", IMAGE_SCN_TYPE_NO_PAD);

					if (Characteristics & IMAGE_SCN_CNT_CODE)
						ImGui::BulletText("IMAGE_SCN_CNT_CODE (0x%X)", IMAGE_SCN_CNT_CODE);

					if (Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
						ImGui::BulletText("IMAGE_SCN_CNT_INITIALIZED_DATA (0x%X)", IMAGE_SCN_CNT_INITIALIZED_DATA);

					if (Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
						ImGui::BulletText("IMAGE_SCN_CNT_UNINITIALIZED_DATA (0x%X)", IMAGE_SCN_CNT_UNINITIALIZED_DATA);

					if (Characteristics & IMAGE_SCN_LNK_INFO)
						ImGui::BulletText("IMAGE_SCN_LNK_INFO (0x%X)", IMAGE_SCN_LNK_INFO);

					if (Characteristics & IMAGE_SCN_LNK_REMOVE)
						ImGui::BulletText("IMAGE_SCN_LNK_REMOVE (0x%X)", IMAGE_SCN_LNK_REMOVE);

					if (Characteristics & IMAGE_SCN_LNK_COMDAT)
						ImGui::BulletText("IMAGE_SCN_LNK_COMDAT (0x%X)", IMAGE_SCN_LNK_COMDAT);

					if (Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC)
						ImGui::BulletText("IMAGE_SCN_NO_DEFER_SPEC_EXC (0x%X)", IMAGE_SCN_NO_DEFER_SPEC_EXC);

					if (Characteristics & IMAGE_SCN_GPREL)
						ImGui::BulletText("IMAGE_SCN_GPREL (0x%X)", IMAGE_SCN_GPREL);

					if (Characteristics & IMAGE_SCN_ALIGN_1BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_1BYTES (0x%X)", IMAGE_SCN_ALIGN_1BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_2BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_2BYTES (0x%X)", IMAGE_SCN_ALIGN_2BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_4BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_4BYTES (0x%X)", IMAGE_SCN_ALIGN_4BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_8BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_8BYTES (0x%X)", IMAGE_SCN_ALIGN_8BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_16BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_16BYTES (0x%X)", IMAGE_SCN_ALIGN_16BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_32BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_32BYTES (0x%X)", IMAGE_SCN_ALIGN_32BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_64BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_64BYTES (0x%X)", IMAGE_SCN_ALIGN_64BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_128BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_128BYTES (0x%X)", IMAGE_SCN_ALIGN_128BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_256BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_256BYTES (0x%X)", IMAGE_SCN_ALIGN_256BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_512BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_512BYTES (0x%X)", IMAGE_SCN_ALIGN_512BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_1024BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_1024BYTES (0x%X)", IMAGE_SCN_ALIGN_1024BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_2048BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_2048BYTES (0x%X)", IMAGE_SCN_ALIGN_2048BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_4096BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_4096BYTES (0x%X)", IMAGE_SCN_ALIGN_4096BYTES);

					if (Characteristics & IMAGE_SCN_ALIGN_8192BYTES)
						ImGui::BulletText("IMAGE_SCN_ALIGN_8192BYTES (0x%X)", IMAGE_SCN_ALIGN_8192BYTES);

					if (Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
						ImGui::BulletText("IMAGE_SCN_LNK_NRELOC_OVFL (0x%X)", IMAGE_SCN_LNK_NRELOC_OVFL);

					if (Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
						ImGui::BulletText("IMAGE_SCN_MEM_DISCARDABLE (0x%X)", IMAGE_SCN_MEM_DISCARDABLE);

					if (Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
						ImGui::BulletText("IMAGE_SCN_MEM_NOT_CACHED (0x%X)", IMAGE_SCN_MEM_NOT_CACHED);

					if (Characteristics & IMAGE_SCN_MEM_NOT_PAGED)
						ImGui::BulletText("IMAGE_SCN_MEM_NOT_PAGED (0x%X)", IMAGE_SCN_MEM_NOT_PAGED);

					if (Characteristics & IMAGE_SCN_MEM_SHARED)
						ImGui::BulletText("IMAGE_SCN_MEM_SHARED (0x%X)", IMAGE_SCN_MEM_SHARED);

					if (Characteristics & IMAGE_SCN_MEM_EXECUTE)
						ImGui::BulletText("IMAGE_SCN_MEM_EXECUTE (0x%X)", IMAGE_SCN_MEM_EXECUTE);

					if (Characteristics & IMAGE_SCN_MEM_READ)
						ImGui::BulletText("IMAGE_SCN_MEM_READ (0x%X)", IMAGE_SCN_MEM_READ);

					if (Characteristics & IMAGE_SCN_MEM_WRITE)
						ImGui::BulletText("IMAGE_SCN_MEM_WRITE (0x%X)", IMAGE_SCN_MEM_WRITE);

					ImGui::EndTooltip();
				}

				ImGui::TreePop();
			}
		}

		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();

		// The optional header's data directories' actual implementations.
		ImGui::Text("Data Directories");

		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();

		// Parsing the export directory.
		const PIMAGE_DATA_DIRECTORY pExportDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		BaseOffset = Helpers::RVAToFileOffset(pExportDir->VirtualAddress);

		const bool Collapsing_ImageExportDir = ImGui::TreeNode("IMAGE_EXPORT_DIRECTORY");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, Characteristics));

		if (Collapsing_ImageExportDir)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_EXPORT);
			}
			else
				ImGui::Text("This executable doesn't have exports.");

			ImGui::TreePop();
		}

		// Parsing the import directory.
		const PIMAGE_DATA_DIRECTORY pImportDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		BaseOffset = Helpers::RVAToFileOffset(pImportDir->VirtualAddress);

		const bool Collapsing_ImageImportDescr = ImGui::TreeNode("IMAGE_IMPORT_DESCRIPTOR");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_IMPORT_DESCRIPTOR, OriginalFirstThunk));

		if (Collapsing_ImageImportDescr)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_IMPORT);
			}
			else
				ImGui::Text("This executable doesn't have imports.");

			ImGui::TreePop();
		}

		// Parsing the resource directory.
		const PIMAGE_DATA_DIRECTORY pResourceDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
		BaseOffset = Helpers::RVAToFileOffset(pResourceDir->VirtualAddress);

		const bool Collapsing_ImageRsrcDir = ImGui::TreeNode("IMAGE_RESOURCE_DIRECTORY");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RESOURCE_DIRECTORY, Characteristics));

		if (Collapsing_ImageRsrcDir)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_RESOURCE);
			}
			else
				ImGui::Text("This executable doesn't have resources.");

			ImGui::TreePop();
		}

		// Parsing the exception directory.
		const PIMAGE_DATA_DIRECTORY pExceptionDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		BaseOffset = Helpers::RVAToFileOffset(pExceptionDir->VirtualAddress);

		const bool Collapsing_ExceptionDir = ImGui::TreeNode("IMAGE_RUNTIME_FUNCTION_ENTRY");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RUNTIME_FUNCTION_ENTRY, BeginAddress));

		if (Collapsing_ExceptionDir)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
			}
			else
				ImGui::Text("This executable doesn't have runtime functions.");

			ImGui::TreePop();
		}

		// Parsing the security directory.
		const PIMAGE_DATA_DIRECTORY pSecurityDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
		BaseOffset = Helpers::RVAToFileOffset(pSecurityDir->VirtualAddress);

		const bool Collapsing_SecurityDir = ImGui::TreeNode("WIN_CERTIFICATE");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(WIN_CERTIFICATE, dwLength));

		if (Collapsing_SecurityDir)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_SECURITY);
			}
			else
				ImGui::Text("This executable doesn't have wincertificate.");

			ImGui::TreePop();
		}

		// Parsing the base relocation directory.
		const PIMAGE_DATA_DIRECTORY pRelocDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		BaseOffset = Helpers::RVAToFileOffset(pRelocDir->VirtualAddress);

		const bool Collapsing_BaseRelocDir = ImGui::TreeNode("IMAGE_BASE_RELOCATION");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_BASE_RELOCATION, VirtualAddress));

		if (Collapsing_BaseRelocDir)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_BASERELOC);
			}
			else
				ImGui::Text("This executable doesn't have relocations.");

			ImGui::TreePop();
		}

		// Parsing the debug directory.
		const PIMAGE_DATA_DIRECTORY pDebugDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
		BaseOffset = Helpers::RVAToFileOffset(pDebugDir->VirtualAddress);

		const bool Collapsing_DebugDir = ImGui::TreeNode("IMAGE_DEBUG_DIRECTORY");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DEBUG_DIRECTORY, Characteristics));

		if (Collapsing_DebugDir)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_DEBUG);
			}
			else
				ImGui::Text("This executable doesn't have debug information.");

			ImGui::TreePop();
		}

		// Parsing the architecture-specific directory.
		const PIMAGE_DATA_DIRECTORY pArchDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE];
		BaseOffset = Helpers::RVAToFileOffset(pArchDir->VirtualAddress);

		const bool Collapsing_ArchDir = ImGui::TreeNode("ARCH DIRECTORY??");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DEBUG_DIRECTORY, Characteristics));

		if (Collapsing_ArchDir)
		{
			if (BaseOffset)
			{
				ImGui::Text("Not parsed yet.");
			}
			else
				ImGui::Text("This executable doesn't have architecture-specific data.");

			ImGui::TreePop();
		}

		// Parsing the global-ptr directory.
		const PIMAGE_DATA_DIRECTORY pGlobalPtrDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR];
		BaseOffset = Helpers::RVAToFileOffset(pGlobalPtrDir->VirtualAddress);

		const bool Collapsing_GlobalPtrDir = ImGui::TreeNode("GLOBAL PTR??");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DEBUG_DIRECTORY, Characteristics));

		if (Collapsing_GlobalPtrDir)
		{
			if (BaseOffset)
			{
				ImGui::Text("Not parsed yet.");
			}
			else
				ImGui::Text("This executable doesn't have a global pointer.");

			ImGui::TreePop();
		}

		// Parsing the thread local storage directory.
		const PIMAGE_DATA_DIRECTORY pTlsDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		BaseOffset = Helpers::RVAToFileOffset(pTlsDir->VirtualAddress);

		const bool Collapsing_TlsDir = ImGui::TreeNode("IMAGE_TLS_DIRECTORY");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_TLS_DIRECTORY, StartAddressOfRawData));

		if (Collapsing_TlsDir)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_TLS);
			}
			else
				ImGui::Text("This executable doesn't have thread local storage.");

			ImGui::TreePop();
		}

		// Parsing the load config directory.
		const PIMAGE_DATA_DIRECTORY pLoadConfigDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
		BaseOffset = Helpers::RVAToFileOffset(pLoadConfigDir->VirtualAddress);

		const bool Collapsing_LoadConfigDir = ImGui::TreeNode("IMAGE_LOAD_CONFIG_DIRECTORY");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_TLS_DIRECTORY, StartAddressOfRawData));

		if (Collapsing_LoadConfigDir)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
			}
			else
				ImGui::Text("This executable doesn't have load configs.");

			ImGui::TreePop();
		}

		// Parsing the bound imports directory.
		const PIMAGE_DATA_DIRECTORY pBoundImportDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
		BaseOffset = Helpers::RVAToFileOffset(pBoundImportDir->VirtualAddress);
	
		const bool Collapsing_BoundImportDir = ImGui::TreeNode("IMAGE_BOUND_IMPORT_DESCRIPTOR");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_BOUND_IMPORT_DESCRIPTOR, TimeDateStamp));

		if (Collapsing_BoundImportDir)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
			}
			else
				ImGui::Text("This executable doesn't have bound imports.");

			ImGui::TreePop();
		}

		// Parsing the Import Address Table (IAT).
		const PIMAGE_DATA_DIRECTORY pIATDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
		BaseOffset = Helpers::RVAToFileOffset(pIATDir->VirtualAddress);

		const bool Collapsing_IATDir = ImGui::TreeNode("IMAGE_THUNK_DATA");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_THUNK_DATA, u1.Function));

		if (Collapsing_IATDir)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_IAT);
			}
			else
				ImGui::Text("This executable doesn't have imports.");

			ImGui::TreePop();
		}

		// Parsing the delay load imports directory.
		const PIMAGE_DATA_DIRECTORY pDelayImportDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
		BaseOffset = Helpers::RVAToFileOffset(pDelayImportDir->VirtualAddress);

		const bool Collapsing_DelayImportDir = ImGui::TreeNode("IMAGE_DELAYLOAD_DESCRIPTOR");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DELAYLOAD_DESCRIPTOR, Attributes.AllAttributes));

		if (Collapsing_DelayImportDir)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
			}
			else
				ImGui::Text("This executable doesn't have delay load imports.");

			ImGui::TreePop();
		}

		// Parsing the Component Object Model (COM) descriptor directory.
		const PIMAGE_DATA_DIRECTORY pComDescr = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
		BaseOffset = Helpers::RVAToFileOffset(pComDescr->VirtualAddress);

		const bool Collapsing_ComDescr = ImGui::TreeNode("IMAGE_COR20_HEADER");
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, cb));

		if (Collapsing_ComDescr)
		{
			if (BaseOffset)
			{
				Helpers::Parse(BaseOffset, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
			}
			else
				ImGui::Text("This executable doesn't have COM.");

			ImGui::TreePop();
		}

		ImGui::Spacing();
		ImGui::Separator();
	}

	ImGui::End();

	ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x + MainAreaSize.x, viewport->Pos.y), true, ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2(viewport->Size.x - MainAreaSize.x, viewport->Size.y), true);

	ImGui::Begin("Misc", NULL, PRSR_MISC);

	if (g_OpenedFile.size())
	{
		ImVec2 MiscSize = ImGui::GetItemRectSize();

		ImGui::BeginTabBar("##MiscTabbar", ImGuiTabBarFlags_Reorderable);

		if (ImGui::BeginTabItem("Details"))
		{
			ImGui::Text("Not done yet.");

			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem("Hex View"))
		{
			if (ImGui::BeginTable("##HexViewTable", 2, ImGuiTableFlags_NoSavedSettings))
			{
				static ImVec2 FileOffsetTS = ImGui::CalcTextSize("File Offset");

				ImGui::TableSetupColumn("##HexViewTable_Setup", ImGuiTableColumnFlags_WidthFixed, FileOffsetTS.x + 10.0f);

				ImGui::TableNextColumn();

				ImGui::BeginGroup();

				static int InputFileOffset = 0;
				ImGui::Text("File Offset");

				ImGui::SetNextItemWidth(FileOffsetTS.x);
				ImGui::InputInt("##FileOffsetInput", &InputFileOffset, 0, 0);

				ImGui::Text("Show Size");

				ImGui::SetNextItemWidth(FileOffsetTS.x);
				static const char* ShowSizeItems[] = { "BYTE", "WORD", "DWORD" };
				static int ShowSizeCur = 0;
				ImGui::Combo("##ShowSize", &ShowSizeCur, ShowSizeItems, IM_ARRAYSIZE(ShowSizeItems));

				ImGui::NewLine();
				ImGui::TextWrapped("%i bytes starting from %i are shown", PRSR_HEXBYTEAMNT, InputFileOffset);
				ImGui::EndGroup();


				ImGui::TableNextColumn();

				ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 5.0f);

				ImVec2 HewViewSize = ImVec2(MiscSize.x - FileOffsetTS.x - FileOffsetTS.x / 2, MiscSize.y);
				ImGui::BeginChild("HexView", HewViewSize, true, ImGuiWindowFlags_AlwaysHorizontalScrollbar);
				ImVec2 HexViewPosMax = ImGui::GetItemRectMax();

				bool SetMultiplierOnce = true;

				DWORD Offset = 0;
				for (int i = InputFileOffset, i2 = 0; i2 < PRSR_HEXBYTEAMNT;i2++)
				{
					if (i >= g_OpenedFile.size())
					{
						ImGui::NewLine();
						ImGui::Text("-- END OF FILE --");
						break;
					}

					DWORD Read = 0;
					switch (ShowSizeCur)
					{
					case 0:
					{
						Read = *(BYTE*)&g_OpenedFile[i];
						i += sizeof(BYTE);
						Offset = i - sizeof(BYTE);

						ImGui::Text("0x%02X", Read);

						break;
					}
					case 1:
					{
						Read = *(WORD*)&g_OpenedFile[i];
						i += sizeof(WORD);
						Offset = i - sizeof(WORD);

						ImGui::Text("0x%04X", Read);

						break;
					}
					case 2:
					{
						Read = *(DWORD*)&g_OpenedFile[i];
						i += sizeof(DWORD);
						Offset = i - sizeof(DWORD);

						ImGui::Text("0x%08X", Read);
						break;
					}
					}

					if (PRSR_TOOLTIP)
						ImGui::SetTooltip("Offset: 0x%X", Offset);

					ImVec2 LastItemPosMax = ImGui::GetItemRectMax();
					ImVec2 LastItemSize = ImGui::GetItemRectSize();
					if (LastItemPosMax.x + LastItemSize.x < HexViewPosMax.x)
					{
						ImGui::SameLine();
					}
				}

				ImGui::EndChild();
				ImGui::PopStyleVar();

				ImGui::EndTable();
			}

			ImGui::EndTabItem();
		}

		ImGui::EndTabBar();
	}

	ImGui::End();

	if (g_bShowAbout)
	{
		ImGui::Begin("About", (bool*)&g_bShowAbout, PRSR_ABOUT);

		ImGui::Text("Portable Executable (PE) files parser");
		if (ImGui::IsItemHovered())
		{
			ImGui::Text("Click to open GitHub page");
			if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				ShellExecuteA(*g_pMainWnd, "open", "https://github.com/paskalian/PE-Parser", 0, 0, SW_SHOWNORMAL);
		}
		ImGui::Spacing();
		ImGui::Separator();
		ImGui::Spacing();
		ImGui::Text(u8"Copyright © 2023 - Paskalian");

		ImGui::End();
	}

	return Status;
}

VOID Parser::Helpers::Parse(DWORD BaseOffset, WORD Id)
{
	switch (Id)
	{
	case IMAGE_DIRECTORY_ENTRY_EXPORT:
	{
		ParseExportDir(BaseOffset);
		break;
	}
	case IMAGE_DIRECTORY_ENTRY_IMPORT:
	{
		ParseImportDir(BaseOffset);
		break;
	}
	case IMAGE_DIRECTORY_ENTRY_RESOURCE:
	{
		ParseRsrcDir(BaseOffset);
		break;
	}
	case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
	{
		ParseExceptionDir(BaseOffset);
		break;
	}
	case IMAGE_DIRECTORY_ENTRY_SECURITY:
	{
		ParseSecurityDir(BaseOffset);
		break;
	}
	case IMAGE_DIRECTORY_ENTRY_BASERELOC:
	{
		ParseBaseRelocDir(BaseOffset);
		break;
	}
	case IMAGE_DIRECTORY_ENTRY_DEBUG:
	{
		ParseDebugDir(BaseOffset);
		break;
	}
	// Architecture
	// GlobalPtr
	case IMAGE_DIRECTORY_ENTRY_TLS:
	{
		ParseTlsDir(BaseOffset);
		break;
	}
	case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
	{
		ParseLoadCfgDir(BaseOffset);
		break;
	}
	case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
	{
		ParseBoundImportDir(BaseOffset);
		break;
	}
	case IMAGE_DIRECTORY_ENTRY_IAT:
	{
		ParseIATDir(BaseOffset);
		break;
	}
	case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
	{
		ParseDelayLoadImportDir(BaseOffset);
		break;
	}
	case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
	{
		ParseCOMDir(BaseOffset);
		break;
	}
	}
}

VOID Parser::Helpers::ParseExportDir(DWORD BaseOffset)
{
	const PIMAGE_EXPORT_DIRECTORY pImageExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((UINT_PTR)g_pDosHeader + BaseOffset);

	ImGui::BulletText("[%s] Characteristics: 0x%X", "DWORD", pImageExportDir->Characteristics);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, Characteristics));

	ImGui::BulletText("[%s] TimeDateStamp: 0x%X", "DWORD", pImageExportDir->TimeDateStamp);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, TimeDateStamp));

	ImGui::BulletText("[%s] MajorVersion: 0x%X", "WORD", pImageExportDir->MajorVersion);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, MajorVersion));

	ImGui::BulletText("[%s] MinorVersion: 0x%X", "WORD", pImageExportDir->MinorVersion);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, MinorVersion));

	ImGui::BulletText("[%s] Name: 0x%X", "DWORD", pImageExportDir->Name);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, Name));

	ImGui::BulletText("[%s] Base: 0x%X", "DWORD", pImageExportDir->Base);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, Base));

	ImGui::BulletText("[%s] NumberOfFunctions: 0x%X", "DWORD", pImageExportDir->NumberOfFunctions);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfFunctions));

	ImGui::BulletText("[%s] NumberOfNames: 0x%X", "DWORD", pImageExportDir->NumberOfNames);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfNames));

	ImGui::BulletText("[%s] AddressOfFunctions: 0x%X", "DWORD", pImageExportDir->AddressOfFunctions);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfFunctions));

	ImGui::BulletText("[%s] AddressOfNames: 0x%X", "DWORD", pImageExportDir->AddressOfNames);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNames));

	ImGui::BulletText("[%s] AddressOfNameOrdinals: 0x%X", "DWORD", pImageExportDir->AddressOfNameOrdinals);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals));
}

VOID Parser::Helpers::ParseImportDir(DWORD BaseOffset)
{
	const PIMAGE_IMPORT_DESCRIPTOR pImageImportDescr = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>((UINT_PTR)g_pDosHeader + BaseOffset);

	static std::vector<char*> Collapsing_ImageImportDescrIds;
	for (int i = 0; ; i++)
	{
		if (Collapsing_ImageImportDescrIds.size() <= i)
			Collapsing_ImageImportDescrIds.push_back(nullptr);

		PIMAGE_IMPORT_DESCRIPTOR pImageImportDescrIdx = &pImageImportDescr[i];

		BaseOffset = (BYTE*)pImageImportDescrIdx - (BYTE*)g_pDosHeader;

		if (!pImageImportDescrIdx->Characteristics)
			break;

		const char* pImportName = reinterpret_cast<const char*>((BYTE*)g_pDosHeader + pImageImportDescrIdx->Name);
		bool Collapsing_ImageImportDescrIdx = ImGui::TreeNode(&Collapsing_ImageImportDescrIds[i], "[%i] %s: 0x%X", i, pImportName, BaseOffset);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_IMPORT_DESCRIPTOR, Characteristics));

		if (Collapsing_ImageImportDescrIdx)
		{
			ImGui::BulletText("[%s] OriginalFirstThunk: 0x%X", "DWORD", pImageImportDescrIdx->OriginalFirstThunk);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_IMPORT_DESCRIPTOR, OriginalFirstThunk));

			ImGui::BulletText("[%s] TimeDateStamp: 0x%X", "DWORD", pImageImportDescrIdx->TimeDateStamp);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_IMPORT_DESCRIPTOR, TimeDateStamp));

			ImGui::BulletText("[%s] ForwarderChain: 0x%X", "DWORD", pImageImportDescrIdx->ForwarderChain);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_IMPORT_DESCRIPTOR, ForwarderChain));

			ImGui::BulletText("[%s] Name: 0x%X", "DWORD", pImageImportDescrIdx->Name);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name));

			ImGui::BulletText("[%s] FirstThunk: 0x%X", "DWORD", pImageImportDescrIdx->FirstThunk);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk));

			ImGui::TreePop();
		}
	}
}

VOID Parser::Helpers::ParseRsrcDir(DWORD BaseOffset)
{
	static const PIMAGE_RESOURCE_DIRECTORY pBASE_ImageRsrcDir = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>((UINT_PTR)g_pDosHeader + BaseOffset);
	const PIMAGE_RESOURCE_DIRECTORY pImageRsrcDir = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>((UINT_PTR)g_pDosHeader + BaseOffset);

	ImGui::BulletText("[%s] Characteristics: 0x%X", "DWORD", pImageRsrcDir->Characteristics);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RESOURCE_DIRECTORY, Characteristics));

	ImGui::BulletText("[%s] TimeDateStamp: 0x%X", "DWORD", pImageRsrcDir->TimeDateStamp);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RESOURCE_DIRECTORY, TimeDateStamp));

	ImGui::BulletText("[%s] MajorVersion: 0x%X", "WORD", pImageRsrcDir->MajorVersion);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RESOURCE_DIRECTORY, MajorVersion));

	ImGui::BulletText("[%s] MinorVersion: 0x%X", "WORD", pImageRsrcDir->MinorVersion);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RESOURCE_DIRECTORY, MinorVersion));

	ImGui::BulletText("[%s] NumberOfNamedEntries: 0x%X", "WORD", pImageRsrcDir->NumberOfNamedEntries);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RESOURCE_DIRECTORY, NumberOfNamedEntries));

	ImGui::BulletText("[%s] NumberOfIdEntries: 0x%X", "WORD", pImageRsrcDir->NumberOfIdEntries);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RESOURCE_DIRECTORY, NumberOfIdEntries));

	const WORD NumberOfEntries = pImageRsrcDir->NumberOfNamedEntries + pImageRsrcDir->NumberOfIdEntries;

	ImGui::Spacing();

	static std::vector<char*> Collapsing_ImageRsrcDirEntryIds(NumberOfEntries);
	Collapsing_ImageRsrcDirEntryIds.clear();
	Collapsing_ImageRsrcDirEntryIds.resize(NumberOfEntries);
	for (int i = 0; i < Collapsing_ImageRsrcDirEntryIds.size(); i++)
	{
		const PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageRscrDirEntryIdx = &reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(pImageRsrcDir + 1)[i];

		BaseOffset = (BYTE*)pImageRscrDirEntryIdx - (BYTE*)g_pDosHeader;

		bool Collapsing_ImageRsrcDirEntryIdx = false;

		if (pImageRscrDirEntryIdx->NameIsString)
		{
			const PIMAGE_RESOURCE_DIR_STRING_U ResourceName = reinterpret_cast<PIMAGE_RESOURCE_DIR_STRING_U>((BYTE*)pImageRsrcDir + pImageRscrDirEntryIdx->NameOffset);

			std::wstring ResourceNameString = ResourceName->NameString;
			ResourceNameString.resize(ResourceName->Length);
			Collapsing_ImageRsrcDirEntryIdx = ImGui::TreeNode(&Collapsing_ImageRsrcDirEntryIds[i], "IMAGE_RESOURCE_DIRECTORY_ENTRY[%i] (%ws): 0x%X", i, ResourceNameString.c_str(), BaseOffset);
		}
		else
		{
			Collapsing_ImageRsrcDirEntryIdx = ImGui::TreeNode(&Collapsing_ImageRsrcDirEntryIds[i], "IMAGE_RESOURCE_DIRECTORY_ENTRY[%i]: 0x%X", i, BaseOffset);
		}

		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RESOURCE_DIRECTORY_ENTRY, Name));

		if (Collapsing_ImageRsrcDirEntryIdx)
		{
			if (pImageRscrDirEntryIdx->NameIsString)
				ImGui::BulletText("[%s] NameOffset: 0x%X", "DWORD", pImageRscrDirEntryIdx->NameOffset);
			else
				ImGui::BulletText("[%s] Id: 0x%X", "WORD", pImageRscrDirEntryIdx->Id);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RESOURCE_DIRECTORY_ENTRY, Name));

			if (pImageRscrDirEntryIdx->DataIsDirectory)
			{
				ImGui::BulletText("[%s] OffsetToDirectory: 0x%X", "DWORD", pImageRscrDirEntryIdx->OffsetToDirectory);

				//ImGui::Spacing();
				//ImGui::Text("IMAGE_RESOURCE_DIRECTORY - OFFSET DIRECTORY");
				//const DWORD OffsetDirectoryOffset = ((UINT_PTR)pBASE_ImageRsrcDir + pImageRscrDirEntryIdx->OffsetToDirectory) - (UINT_PTR)g_pDosHeader;
				//Helpers::ParseRsrcDir(OffsetDirectoryOffset);
			}
			else
				ImGui::BulletText("[%s] OffsetToData: 0x%X", "DWORD", pImageRscrDirEntryIdx->OffsetToData);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RESOURCE_DIRECTORY_ENTRY, OffsetToData));

			ImGui::TreePop();
		}
		ImGui::Spacing();
	}
}

VOID Parser::Helpers::ParseExceptionDir(DWORD BaseOffset)
{
	const PIMAGE_DATA_DIRECTORY pExceptionDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	const PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFunctions = reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>((UINT_PTR)g_pDosHeader + BaseOffset);
	const DWORD NumberOfRuntimeFunctions = pExceptionDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

	static std::vector<char*> Collapsing_ImageImportDescrIds(NumberOfRuntimeFunctions);
	Collapsing_ImageImportDescrIds.resize(NumberOfRuntimeFunctions);

	for (int i = 0; i < NumberOfRuntimeFunctions; i++)
	{
		PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFunctionIdx = &pRuntimeFunctions[i];

		BaseOffset = (BYTE*)pRuntimeFunctionIdx - (BYTE*)g_pDosHeader;

		bool Collapsing_RuntimeFunctionIdx = ImGui::TreeNode(&Collapsing_ImageImportDescrIds[i], "IMAGE_RUNTIME_FUNCTION_ENTRY[%i]: 0x%X", i, BaseOffset);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RUNTIME_FUNCTION_ENTRY, BeginAddress));

		if (Collapsing_RuntimeFunctionIdx)
		{
			ImGui::BulletText("[%s] BeginAddress: 0x%X", "DWORD", pRuntimeFunctionIdx->BeginAddress);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RUNTIME_FUNCTION_ENTRY, BeginAddress));

			ImGui::BulletText("[%s] EndAddress: 0x%X", "DWORD", pRuntimeFunctionIdx->EndAddress);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RUNTIME_FUNCTION_ENTRY, EndAddress));

			ImGui::BulletText("[%s] UnwindData: 0x%X", "DWORD", pRuntimeFunctionIdx->UnwindData);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_RUNTIME_FUNCTION_ENTRY, UnwindData));

			ImGui::TreePop();
		}
	}
}

VOID Parser::Helpers::ParseSecurityDir(DWORD BaseOffset)
{
	const LPWIN_CERTIFICATE pWinCertificate = reinterpret_cast<LPWIN_CERTIFICATE>((UINT_PTR)g_pDosHeader + BaseOffset);

	ImGui::BulletText("[%s] dwLength: 0x%X", "DWORD", pWinCertificate->dwLength);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(WIN_CERTIFICATE, dwLength));

	ImGui::BulletText("[%s] wRevision: 0x%X", "WORD", pWinCertificate->wRevision);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(WIN_CERTIFICATE, wRevision));

	ImGui::BulletText("[%s] wCertificateType: 0x%X", "WORD", pWinCertificate->wCertificateType);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(WIN_CERTIFICATE, wCertificateType));

	ImGui::BulletText("[%s] bCertificate[1]: 0x%X", "BYTE", pWinCertificate->bCertificate);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(WIN_CERTIFICATE, bCertificate));
}

VOID Parser::Helpers::ParseBaseRelocDir(DWORD BaseOffset)
{
	const PIMAGE_DATA_DIRECTORY pRelocDir = &g_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	const PIMAGE_BASE_RELOCATION pImageBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>((UINT_PTR)g_pDosHeader + BaseOffset);
	const DWORD NumberOfRelocs = pRelocDir->Size / sizeof(IMAGE_BASE_RELOCATION);

	static std::vector<char*> Collapsing_ImageBaseRelocIds(NumberOfRelocs);
	Collapsing_ImageBaseRelocIds.resize(NumberOfRelocs);

	PIMAGE_BASE_RELOCATION pImageBaseRelocIdx = pImageBaseReloc;
	for (int i = 0; i < NumberOfRelocs; i++)
	{
		const DWORD NumberOfRelocEntries = (pImageBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		BaseOffset = (BYTE*)pImageBaseRelocIdx - (BYTE*)g_pDosHeader;

		bool Collapsing_ImageBaseRelocIdx = ImGui::TreeNode(&Collapsing_ImageBaseRelocIds[i], "[%i] IMAGE_BASE_RELOCATION: 0x%X", i, BaseOffset);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_BASE_RELOCATION, VirtualAddress));

		if (Collapsing_ImageBaseRelocIdx)
		{
			ImGui::BulletText("[%s] VirtualAddress: 0x%X", "DWORD", pImageBaseRelocIdx->VirtualAddress);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_BASE_RELOCATION, VirtualAddress));

			ImGui::BulletText("[%s] SizeOfBlock: 0x%X", "DWORD", pImageBaseRelocIdx->SizeOfBlock);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_BASE_RELOCATION, SizeOfBlock));

			ImGui::Spacing();

			std::vector<char*> Collapsing_ImageBaseRelocEntryIds(NumberOfRelocEntries);
			for (int i2 = 0; i2 < NumberOfRelocEntries; i2++)
			{
				const PWORD RelocEntry = &reinterpret_cast<PWORD>(pImageBaseRelocIdx + 1)[i2];

				BaseOffset = (BYTE*)RelocEntry - (BYTE*)g_pDosHeader;

				ImGui::Text("[%i] Type: 0x%X |", i2, (*RelocEntry >> 12));
				if (PRSR_TOOLTIP)
					ImGui::SetTooltip("Offset: 0x%X", BaseOffset);

				ImGui::SameLine();

				ImGui::Text("Offset: 0x%X", (*RelocEntry & 0xFFF));
				if (PRSR_TOOLTIP)
					ImGui::SetTooltip("Offset: 0x%X", BaseOffset);

				ImGui::Spacing();
			}

			ImGui::TreePop();
		}

		pImageBaseRelocIdx = reinterpret_cast<PIMAGE_BASE_RELOCATION>((BYTE*)pImageBaseRelocIdx + pImageBaseRelocIdx->SizeOfBlock);
	}
}

VOID Parser::Helpers::ParseDebugDir(DWORD BaseOffset)
{
	const PIMAGE_DEBUG_DIRECTORY pImageDebugDir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>((UINT_PTR)g_pDosHeader + BaseOffset);

	ImGui::BulletText("[%s] Characteristics: 0x%X", "DWORD", pImageDebugDir->Characteristics);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DEBUG_DIRECTORY, Characteristics));

	ImGui::BulletText("[%s] TimeDateStamp: 0x%X", "DWORD", pImageDebugDir->TimeDateStamp);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DEBUG_DIRECTORY, TimeDateStamp));

	ImGui::BulletText("[%s] MajorVersion: 0x%X", "WORD", pImageDebugDir->MajorVersion);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DEBUG_DIRECTORY, MajorVersion));

	ImGui::BulletText("[%s] MinorVersion: 0x%X", "WORD", pImageDebugDir->MinorVersion);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DEBUG_DIRECTORY, MinorVersion));

	ImGui::BulletText("[%s] Type: 0x%X", "DWORD", pImageDebugDir->Type);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DEBUG_DIRECTORY, Type));

	ImGui::BulletText("[%s] SizeOfData: 0x%X", "DWORD", pImageDebugDir->SizeOfData);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DEBUG_DIRECTORY, SizeOfData));

	ImGui::BulletText("[%s] AddressOfRawData: 0x%X", "DWORD", pImageDebugDir->AddressOfRawData);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DEBUG_DIRECTORY, AddressOfRawData));

	ImGui::BulletText("[%s] PointerToRawData: 0x%X", "DWORD", pImageDebugDir->PointerToRawData);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DEBUG_DIRECTORY, PointerToRawData));

	ImGui::Spacing();

	BaseOffset = pImageDebugDir->PointerToRawData;

	static const PDWORD pCvInfo = reinterpret_cast<PDWORD>((UINT_PTR)g_pDosHeader + BaseOffset);
	switch (*pCvInfo)
	{
	case CV_SIGNATURE_NB10:
	{
		const PCV_INFO_PDB20 pCvInfoPdb20 = reinterpret_cast<PCV_INFO_PDB20>(pCvInfo);

		ImGui::Text("[%s] CvSignature: 0x%X", "DWORD", pCvInfoPdb20->CvSignature);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(CV_INFO_PDB20, CvSignature));

		ImGui::Text("[%s] Offset: 0x%X", "DWORD", pCvInfoPdb20->Offset);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(CV_INFO_PDB20, Offset));

		ImGui::Text("[%s] Signature: 0x%X", "DWORD", pCvInfoPdb20->Signature);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(CV_INFO_PDB20, Signature));

		ImGui::Text("[%s] Age: 0x%X", "DWORD", pCvInfoPdb20->Age);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(CV_INFO_PDB20, Age));

		ImGui::Text("[%s] PdbFileName[MAX_PATH]: %s", "CHAR", pCvInfoPdb20->PdbFileName);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(CV_INFO_PDB20, PdbFileName));

		break;
	}
	case CV_SIGNATURE_RSDS:
	{
		const PCV_INFO_PDB70 pCvInfoPdb70 = reinterpret_cast<PCV_INFO_PDB70>(pCvInfo);

		ImGui::Text("[%s] CvSignature: 0x%X", "DWORD", pCvInfoPdb70->CvSignature);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(CV_INFO_PDB70, CvSignature));

		ImGui::Text("[%s] Signature: 0x%X", "DWORD", pCvInfoPdb70->Signature);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(CV_INFO_PDB70, Signature));

		ImGui::Text("[%s] Age: 0x%X", "DWORD", pCvInfoPdb70->Age);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(CV_INFO_PDB70, Age));

		ImGui::Text("[%s] PdbFileName[MAX_PATH]: %s", "CHAR", pCvInfoPdb70->PdbFileName);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(CV_INFO_PDB70, PdbFileName));

		break;
	}
	}
}

// Architecture
// GlobalPtr

VOID Parser::Helpers::ParseTlsDir(DWORD BaseOffset)
{
	const PIMAGE_TLS_DIRECTORY pImageTlsDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>((UINT_PTR)g_pDosHeader + BaseOffset);

	// The absolute virtual addresses aren't converted, it's as they are in here.
#ifdef _WIN64
	ImGui::BulletText("[%s] StartAddressOfRawData: 0x%X", "ULONGLONG", pImageTlsDir->StartAddressOfRawData);
#else
	ImGui::BulletText("[%s] StartAddressOfRawData: 0x%X", "ULONG", pImageTlsDir->StartAddressOfRawData);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_TLS_DIRECTORY, StartAddressOfRawData));

#ifdef _WIN64
	ImGui::BulletText("[%s] EndAddressOfRawData: 0x%X", "ULONGLONG", pImageTlsDir->EndAddressOfRawData);
#else
	ImGui::BulletText("[%s] EndAddressOfRawData: 0x%X", "ULONG", pImageTlsDir->EndAddressOfRawData);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_TLS_DIRECTORY, EndAddressOfRawData));

#ifdef _WIN64
	ImGui::BulletText("[%s] AddressOfIndex: 0x%X", "ULONGLONG", pImageTlsDir->AddressOfIndex);
#else
	ImGui::BulletText("[%s] AddressOfIndex: 0x%X", "ULONG", pImageTlsDir->AddressOfIndex);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_TLS_DIRECTORY, AddressOfIndex));

#ifdef _WIN64
	ImGui::BulletText("[%s] AddressOfCallBacks: 0x%X", "ULONGLONG", pImageTlsDir->AddressOfCallBacks);
#else
	ImGui::BulletText("[%s] AddressOfCallBacks: 0x%X", "ULONG", pImageTlsDir->AddressOfCallBacks);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_TLS_DIRECTORY, AddressOfCallBacks));

	ImGui::BulletText("[%s] SizeOfZeroFill: 0x%X", "DWORD", pImageTlsDir->SizeOfZeroFill);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_TLS_DIRECTORY, SizeOfZeroFill));

	ImGui::BulletText("[%s] Characteristics: 0x%X", "DWORD", pImageTlsDir->Characteristics);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_TLS_DIRECTORY, Characteristics));

	ImGui::Spacing();

	// pImageTlsDir->AddressOfCallBacks is an absolute virtual address (based on g_pOptionalHeader->ImageBase), so we are subtracting g_pOptionalHeader->ImageBase from it to get
	// the virtual address, then convert that to file offset so we can use it.
	const DWORD TlsCallbacksOffset = Helpers::RVAToFileOffset(pImageTlsDir->AddressOfCallBacks - g_pOptionalHeader->ImageBase);

	for (int i = 0; ; i++)
	{
		PIMAGE_TLS_CALLBACK pTlsCallbackIdx = reinterpret_cast<PIMAGE_TLS_CALLBACK*>((BYTE*)g_pDosHeader + TlsCallbacksOffset)[i];
		if (!pTlsCallbackIdx)
			break;

		// Same
		BaseOffset = Helpers::RVAToFileOffset((UINT_PTR)pTlsCallbackIdx - g_pOptionalHeader->ImageBase);

		ImGui::Text("PIMAGE_TLS_CALLBACK[%i]: 0x%X", i, pTlsCallbackIdx);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset);

		ImGui::Spacing();
	}
}

VOID Parser::Helpers::ParseLoadCfgDir(DWORD BaseOffset)
{
	const PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDir = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY>((UINT_PTR)g_pDosHeader + BaseOffset);

	ImGui::BulletText("[%s] Size: 0x%X", "DWORD", pImageLoadConfigDir->Size);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, Size));

	ImGui::BulletText("[%s] TimeDateStamp: 0x%X", "DWORD", pImageLoadConfigDir->TimeDateStamp);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, TimeDateStamp));

	ImGui::BulletText("[%s] MajorVersion: 0x%X", "WORD", pImageLoadConfigDir->MajorVersion);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, MajorVersion));

	ImGui::BulletText("[%s] MinorVersion: 0x%X", "WORD", pImageLoadConfigDir->MinorVersion);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, MinorVersion));

	ImGui::BulletText("[%s] GlobalFlagsClear: 0x%X", "DWORD", pImageLoadConfigDir->GlobalFlagsClear);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GlobalFlagsClear));

	ImGui::BulletText("[%s] GlobalFlagsSet: 0x%X", "DWORD", pImageLoadConfigDir->GlobalFlagsSet);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GlobalFlagsSet));

	ImGui::BulletText("[%s] CriticalSectionDefaultTimeout: 0x%X", "DWORD", pImageLoadConfigDir->CriticalSectionDefaultTimeout);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, CriticalSectionDefaultTimeout));

#ifdef _WIN64
	ImGui::BulletText("[%s] DeCommitFreeBlockThreshold: 0x%X", "ULONGLONG", pImageLoadConfigDir->DeCommitFreeBlockThreshold);
#else
	ImGui::BulletText("[%s] DeCommitFreeBlockThreshold: 0x%X", "ULONG", pImageLoadConfigDir->DeCommitFreeBlockThreshold);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, DeCommitFreeBlockThreshold));

#ifdef _WIN64
	ImGui::BulletText("[%s] DeCommitTotalFreeThreshold: 0x%X", "ULONGLONG", pImageLoadConfigDir->DeCommitTotalFreeThreshold);
#else
	ImGui::BulletText("[%s] DeCommitTotalFreeThreshold: 0x%X", "ULONG", pImageLoadConfigDir->DeCommitTotalFreeThreshold);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, DeCommitTotalFreeThreshold));

#ifdef _WIN64
	ImGui::BulletText("[%s] LockPrefixTable: 0x%X", "ULONGLONG", pImageLoadConfigDir->LockPrefixTable);
#else
	ImGui::BulletText("[%s] LockPrefixTable: 0x%X", "ULONG", pImageLoadConfigDir->LockPrefixTable);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, LockPrefixTable));

#ifdef _WIN64
	ImGui::BulletText("[%s] LockPrefixTable: 0x%X", "ULONGLONG", pImageLoadConfigDir->LockPrefixTable);
#else
	ImGui::BulletText("[%s] LockPrefixTable: 0x%X", "ULONG", pImageLoadConfigDir->LockPrefixTable);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, LockPrefixTable));

#ifdef _WIN64
	ImGui::BulletText("[%s] MaximumAllocationSize: 0x%X", "ULONGLONG", pImageLoadConfigDir->MaximumAllocationSize);
#else
	ImGui::BulletText("[%s] MaximumAllocationSize: 0x%X", "ULONG", pImageLoadConfigDir->MaximumAllocationSize);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, MaximumAllocationSize));

#ifdef _WIN64
	ImGui::BulletText("[%s] VirtualMemoryThreshold: 0x%X", "ULONGLONG", pImageLoadConfigDir->VirtualMemoryThreshold);
#else
	ImGui::BulletText("[%s] VirtualMemoryThreshold: 0x%X", "ULONG", pImageLoadConfigDir->VirtualMemoryThreshold);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, VirtualMemoryThreshold));

#ifdef _WIN64
	ImGui::BulletText("[%s] ProcessAffinityMask: 0x%X", "ULONGLONG", pImageLoadConfigDir->ProcessAffinityMask);
#else
	ImGui::BulletText("[%s] ProcessAffinityMask: 0x%X", "ULONG", pImageLoadConfigDir->ProcessAffinityMask);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, ProcessAffinityMask));

	ImGui::BulletText("[%s] ProcessHeapFlags: 0x%X", "DWORD", pImageLoadConfigDir->ProcessHeapFlags);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, ProcessHeapFlags));

	ImGui::BulletText("[%s] CSDVersion: 0x%X", "WORD", pImageLoadConfigDir->CSDVersion);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, CSDVersion));

	ImGui::BulletText("[%s] DependentLoadFlags: 0x%X", "WORD", pImageLoadConfigDir->DependentLoadFlags);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, DependentLoadFlags));

#ifdef _WIN64
	ImGui::BulletText("[%s] EditList: 0x%X", "ULONGLONG", pImageLoadConfigDir->EditList);
#else
	ImGui::BulletText("[%s] EditList: 0x%X", "ULONG", pImageLoadConfigDir->EditList);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, EditList));

#ifdef _WIN64
	ImGui::BulletText("[%s] SecurityCookie: 0x%X", "ULONGLONG", pImageLoadConfigDir->SecurityCookie);
#else
	ImGui::BulletText("[%s] SecurityCookie: 0x%X", "ULONG", pImageLoadConfigDir->SecurityCookie);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie));

#ifdef _WIN64
	ImGui::BulletText("[%s] SEHandlerTable: 0x%X", "ULONGLONG", pImageLoadConfigDir->SEHandlerTable);
#else
	ImGui::BulletText("[%s] SEHandlerTable: 0x%X", "ULONG", pImageLoadConfigDir->SEHandlerTable);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SEHandlerTable));

#ifdef _WIN64
	ImGui::BulletText("[%s] SEHandlerCount: 0x%X", "ULONGLONG", pImageLoadConfigDir->SEHandlerCount);
#else
	ImGui::BulletText("[%s] SEHandlerCount: 0x%X", "ULONG", pImageLoadConfigDir->SEHandlerCount);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SEHandlerCount));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardCFCheckFunctionPointer: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardCFCheckFunctionPointer);
#else
	ImGui::BulletText("[%s] GuardCFCheckFunctionPointer: 0x%X", "ULONG", pImageLoadConfigDir->GuardCFCheckFunctionPointer);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardCFCheckFunctionPointer));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardCFDispatchFunctionPointer: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardCFDispatchFunctionPointer);
#else
	ImGui::BulletText("[%s] GuardCFDispatchFunctionPointer: 0x%X", "ULONG", pImageLoadConfigDir->GuardCFDispatchFunctionPointer);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardCFDispatchFunctionPointer));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardCFFunctionTable: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardCFFunctionTable);
#else
	ImGui::BulletText("[%s] GuardCFFunctionTable: 0x%X", "ULONG", pImageLoadConfigDir->GuardCFFunctionTable);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardCFFunctionTable));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardCFFunctionCount: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardCFFunctionCount);
#else
	ImGui::BulletText("[%s] GuardCFFunctionCount: 0x%X", "ULONG", pImageLoadConfigDir->GuardCFFunctionCount);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardCFFunctionCount));

	ImGui::BulletText("[%s] GuardFlags: 0x%X", "DWORD", pImageLoadConfigDir->GuardFlags);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardFlags));

	const bool Collapsing_ImageLoadConfigDir_CodeIntegrity = ImGui::TreeNode(static_cast<void*>(nullptr), "[%s] CodeIntegrity", "IMAGE_LOAD_CONFIG_CODE_INTEGRITY");
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, CodeIntegrity));

	if (Collapsing_ImageLoadConfigDir_CodeIntegrity)
	{
		ImGui::BulletText("[%s] Flags: 0x%X", "WORD", pImageLoadConfigDir->CodeIntegrity.Flags);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, CodeIntegrity.Flags));

		ImGui::BulletText("[%s] Catalog: 0x%X", "WORD", pImageLoadConfigDir->CodeIntegrity.Catalog);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, CodeIntegrity.Catalog));

		ImGui::BulletText("[%s] CatalogOffset: 0x%X", "DWORD", pImageLoadConfigDir->CodeIntegrity.CatalogOffset);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, CodeIntegrity.CatalogOffset));

		ImGui::BulletText("[%s] Reserved: 0x%X", "DWORD", pImageLoadConfigDir->CodeIntegrity.Reserved);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, CodeIntegrity.Reserved));

		ImGui::TreePop();
	}

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardAddressTakenIatEntryTable: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardAddressTakenIatEntryTable);
#else
	ImGui::BulletText("[%s] GuardAddressTakenIatEntryTable: 0x%X", "ULONG", pImageLoadConfigDir->GuardAddressTakenIatEntryTable);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardAddressTakenIatEntryTable));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardAddressTakenIatEntryCount: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardAddressTakenIatEntryCount);
#else
	ImGui::BulletText("[%s] GuardAddressTakenIatEntryCount: 0x%X", "ULONG", pImageLoadConfigDir->GuardAddressTakenIatEntryCount);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardAddressTakenIatEntryCount));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardLongJumpTargetTable: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardLongJumpTargetTable);
#else
	ImGui::BulletText("[%s] GuardLongJumpTargetTable: 0x%X", "ULONG", pImageLoadConfigDir->GuardLongJumpTargetTable);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardLongJumpTargetTable));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardLongJumpTargetCount: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardLongJumpTargetCount);
#else
	ImGui::BulletText("[%s] GuardLongJumpTargetCount: 0x%X", "ULONG", pImageLoadConfigDir->GuardLongJumpTargetCount);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardLongJumpTargetCount));

#ifdef _WIN64
	ImGui::BulletText("[%s] DynamicValueRelocTable: 0x%X", "ULONGLONG", pImageLoadConfigDir->DynamicValueRelocTable);
#else
	ImGui::BulletText("[%s] DynamicValueRelocTable: 0x%X", "ULONG", pImageLoadConfigDir->DynamicValueRelocTable);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, DynamicValueRelocTable));

#ifdef _WIN64
	ImGui::BulletText("[%s] CHPEMetadataPointer: 0x%X", "ULONGLONG", pImageLoadConfigDir->CHPEMetadataPointer);
#else
	ImGui::BulletText("[%s] CHPEMetadataPointer: 0x%X", "ULONG", pImageLoadConfigDir->CHPEMetadataPointer);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardRFFailureRoutine: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardRFFailureRoutine);
#else
	ImGui::BulletText("[%s] GuardRFFailureRoutine: 0x%X", "ULONG", pImageLoadConfigDir->GuardRFFailureRoutine);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardRFFailureRoutine));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardRFFailureRoutineFunctionPointer: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardRFFailureRoutineFunctionPointer);
#else
	ImGui::BulletText("[%s] GuardRFFailureRoutineFunctionPointer: 0x%X", "ULONG", pImageLoadConfigDir->GuardRFFailureRoutineFunctionPointer);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardRFFailureRoutineFunctionPointer));

	ImGui::BulletText("[%s] DynamicValueRelocTableOffset: 0x%X", "DWORD", pImageLoadConfigDir->DynamicValueRelocTableOffset);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, DynamicValueRelocTableOffset));

	ImGui::BulletText("[%s] DynamicValueRelocTableSection: 0x%X", "WORD", pImageLoadConfigDir->DynamicValueRelocTableSection);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, DynamicValueRelocTableSection));

	ImGui::BulletText("[%s] Reserved2: 0x%X", "WORD", pImageLoadConfigDir->Reserved2);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, Reserved2));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardRFVerifyStackPointerFunctionPointer: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardRFVerifyStackPointerFunctionPointer);
#else
	ImGui::BulletText("[%s] GuardRFVerifyStackPointerFunctionPointer: 0x%X", "ULONG", pImageLoadConfigDir->GuardRFVerifyStackPointerFunctionPointer);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardRFVerifyStackPointerFunctionPointer));

	ImGui::BulletText("[%s] HotPatchTableOffset: 0x%X", "DWORD", pImageLoadConfigDir->HotPatchTableOffset);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, HotPatchTableOffset));

	ImGui::BulletText("[%s] Reserved3: 0x%X", "DWORD", pImageLoadConfigDir->Reserved3);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, Reserved3));

#ifdef _WIN64
	ImGui::BulletText("[%s] EnclaveConfigurationPointer: 0x%X", "ULONGLONG", pImageLoadConfigDir->EnclaveConfigurationPointer);
#else
	ImGui::BulletText("[%s] EnclaveConfigurationPointer: 0x%X", "ULONG", pImageLoadConfigDir->EnclaveConfigurationPointer);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, EnclaveConfigurationPointer));

#ifdef _WIN64
	ImGui::BulletText("[%s] VolatileMetadataPointer: 0x%X", "ULONGLONG", pImageLoadConfigDir->VolatileMetadataPointer);
#else
	ImGui::BulletText("[%s] VolatileMetadataPointer: 0x%X", "ULONG", pImageLoadConfigDir->VolatileMetadataPointer);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, VolatileMetadataPointer));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardEHContinuationTable: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardEHContinuationTable);
#else
	ImGui::BulletText("[%s] GuardEHContinuationTable: 0x%X", "ULONG", pImageLoadConfigDir->GuardEHContinuationTable);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardEHContinuationTable));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardEHContinuationCount: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardEHContinuationCount);
#else
	ImGui::BulletText("[%s] GuardEHContinuationCount: 0x%X", "ULONG", pImageLoadConfigDir->GuardEHContinuationCount);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardEHContinuationCount));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardXFGCheckFunctionPointer: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardXFGCheckFunctionPointer);
#else
	ImGui::BulletText("[%s] GuardXFGCheckFunctionPointer: 0x%X", "ULONG", pImageLoadConfigDir->GuardXFGCheckFunctionPointer);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardXFGCheckFunctionPointer));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardXFGDispatchFunctionPointer: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardXFGDispatchFunctionPointer);
#else
	ImGui::BulletText("[%s] GuardXFGDispatchFunctionPointer: 0x%X", "ULONG", pImageLoadConfigDir->GuardXFGDispatchFunctionPointer);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardXFGDispatchFunctionPointer));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardXFGTableDispatchFunctionPointer: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardXFGTableDispatchFunctionPointer);
#else
	ImGui::BulletText("[%s] GuardXFGTableDispatchFunctionPointer: 0x%X", "ULONG", pImageLoadConfigDir->GuardXFGTableDispatchFunctionPointer);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardXFGTableDispatchFunctionPointer));

#ifdef _WIN64
	ImGui::BulletText("[%s] CastGuardOsDeterminedFailureMode: 0x%X", "ULONGLONG", pImageLoadConfigDir->CastGuardOsDeterminedFailureMode);
#else
	ImGui::BulletText("[%s] CastGuardOsDeterminedFailureMode: 0x%X", "ULONG", pImageLoadConfigDir->CastGuardOsDeterminedFailureMode);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, CastGuardOsDeterminedFailureMode));

#ifdef _WIN64
	ImGui::BulletText("[%s] GuardMemcpyFunctionPointer: 0x%X", "ULONGLONG", pImageLoadConfigDir->GuardMemcpyFunctionPointer);
#else
	ImGui::BulletText("[%s] GuardMemcpyFunctionPointer: 0x%X", "ULONG", pImageLoadConfigDir->GuardMemcpyFunctionPointer);
#endif
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardMemcpyFunctionPointer));
}

VOID Parser::Helpers::ParseBoundImportDir(DWORD BaseOffset)
{
	const PIMAGE_BOUND_IMPORT_DESCRIPTOR pImageBoundImportDescr = reinterpret_cast<PIMAGE_BOUND_IMPORT_DESCRIPTOR>((UINT_PTR)g_pDosHeader + BaseOffset);

	static std::vector<char*> Collapsing_ImageBoundImportDescrIds;

	DWORD ForwarderRefCount = 0;
	for (int i = 0; ; i++)
	{
		if (Collapsing_ImageBoundImportDescrIds.size() <= i)
			Collapsing_ImageBoundImportDescrIds.push_back(nullptr);

		const PIMAGE_BOUND_IMPORT_DESCRIPTOR pImageBoundImportDescrIdx = &pImageBoundImportDescr[i];

		BaseOffset = (BYTE*)pImageBoundImportDescrIdx - (BYTE*)g_pDosHeader;

		if (!pImageBoundImportDescrIdx->TimeDateStamp)
			break;

		const char* pBoundImportName = reinterpret_cast<const char*>((BYTE*)pImageBoundImportDescr + pImageBoundImportDescrIdx->OffsetModuleName);
		bool Collapsing_ImageBoundImportDescrIdx = ImGui::TreeNode(&Collapsing_ImageBoundImportDescrIds[i], "[%i] %s - %s: 0x%X", i, ForwarderRefCount ? "IMAGE_BOUND_FORWARDER_REF" : "IMAGE_BOUND_IMPORT_DESCRIPTOR", pBoundImportName, BaseOffset);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_BOUND_IMPORT_DESCRIPTOR, TimeDateStamp));

		if (Collapsing_ImageBoundImportDescrIdx)
		{
			ImGui::BulletText("[%s] TimeDateStamp: 0x%X", "DWORD", pImageBoundImportDescrIdx->TimeDateStamp);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_BOUND_IMPORT_DESCRIPTOR, TimeDateStamp));

			ImGui::BulletText("[%s] OffsetModuleName: 0x%X", "WORD", pImageBoundImportDescrIdx->OffsetModuleName);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_BOUND_IMPORT_DESCRIPTOR, OffsetModuleName));

			ImGui::BulletText("[%s] %s: 0x%X", "WORD", ForwarderRefCount ? "Reserved" : "NumberOfModuleForwarderRefs", pImageBoundImportDescrIdx->NumberOfModuleForwarderRefs);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_BOUND_IMPORT_DESCRIPTOR, NumberOfModuleForwarderRefs));

			ImGui::TreePop();
		}

		if (ForwarderRefCount)
			ForwarderRefCount--;
		else
			ForwarderRefCount = pImageBoundImportDescrIdx->NumberOfModuleForwarderRefs;
	}
}

VOID Parser::Helpers::ParseIATDir(DWORD BaseOffset)
{
	const PIMAGE_THUNK_DATA pImageThunkData = reinterpret_cast<PIMAGE_THUNK_DATA>((UINT_PTR)g_pDosHeader + BaseOffset);

	static std::vector<char*> Collapsing_ImageThunkDataIds;
	for (int i = 0; ; i++)
	{
		if (Collapsing_ImageThunkDataIds.size() <= i)
			Collapsing_ImageThunkDataIds.push_back(nullptr);

		const PIMAGE_THUNK_DATA pImageThunkDataIdx = &pImageThunkData[i];

		BaseOffset = (BYTE*)pImageThunkDataIdx - (BYTE*)g_pDosHeader;

		if (!pImageThunkDataIdx->u1.Function)
			break;

		bool Collapsing_ImageThunkDataIdx = ImGui::TreeNode(&Collapsing_ImageThunkDataIds[i], "[%i] IMAGE_THUNK_DATA: 0x%X", i, BaseOffset);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_THUNK_DATA, u1.Function));

		if (Collapsing_ImageThunkDataIdx)
		{
#ifdef _WIN64
			ImGui::BulletText("[%s] Function: 0x%X", "ULONGLONG", pImageThunkDataIdx->u1.Function);
#else
			ImGui::BulletText("[%s] Function: 0x%X", "ULONG", pImageThunkDataIdx->u1.Function);
#endif

			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_THUNK_DATA, u1.Function));

			ImGui::TreePop();
		}
	}
}

VOID Parser::Helpers::ParseDelayLoadImportDir(DWORD BaseOffset)
{
	const PIMAGE_DELAYLOAD_DESCRIPTOR pImageDelayLoad = reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>((UINT_PTR)g_pDosHeader + BaseOffset);

	static std::vector<char*> Collapsing_ImageDelayLoadIds;
	for (int i = 0; ; i++)
	{
		if (Collapsing_ImageDelayLoadIds.size() <= i)
			Collapsing_ImageDelayLoadIds.push_back(nullptr);

		const PIMAGE_DELAYLOAD_DESCRIPTOR pImageDelayLoadIdx = &pImageDelayLoad[i];

		BaseOffset = (BYTE*)pImageDelayLoadIdx - (BYTE*)g_pDosHeader;

		if (!pImageDelayLoadIdx->Attributes.AllAttributes)
			break;

		const char* DelayDllName = (char*)g_pDosHeader + Helpers::RVAToFileOffset(pImageDelayLoadIdx->DllNameRVA);
		bool Collapsing_ImageDelayLoadIdx = ImGui::TreeNode(&Collapsing_ImageDelayLoadIds[i], "IMAGE_DELAYLOAD_DESCRIPTOR[%i] (%s): 0x%X", i, DelayDllName, BaseOffset);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DELAYLOAD_DESCRIPTOR, Attributes.AllAttributes));

		if (Collapsing_ImageDelayLoadIdx)
		{
			ImGui::BulletText("[%s] AllAttributes: 0x%X", "DWORD", pImageDelayLoadIdx->Attributes.AllAttributes);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DELAYLOAD_DESCRIPTOR, Attributes.AllAttributes));

			ImGui::BulletText("[%s] DllNameRVA: 0x%X", "DWORD", pImageDelayLoadIdx->DllNameRVA);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DELAYLOAD_DESCRIPTOR, DllNameRVA));

			ImGui::BulletText("[%s] ModuleHandleRVA: 0x%X", "DWORD", pImageDelayLoadIdx->ModuleHandleRVA);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DELAYLOAD_DESCRIPTOR, ModuleHandleRVA));

			ImGui::BulletText("[%s] ImportAddressTableRVA: 0x%X", "DWORD", pImageDelayLoadIdx->ImportAddressTableRVA);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DELAYLOAD_DESCRIPTOR, ImportAddressTableRVA));

			ImGui::BulletText("[%s] ImportNameTableRVA: 0x%X", "DWORD", pImageDelayLoadIdx->ImportNameTableRVA);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DELAYLOAD_DESCRIPTOR, ImportNameTableRVA));

			ImGui::BulletText("[%s] BoundImportAddressTableRVA: 0x%X", "DWORD", pImageDelayLoadIdx->BoundImportAddressTableRVA);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DELAYLOAD_DESCRIPTOR, BoundImportAddressTableRVA));

			ImGui::BulletText("[%s] UnloadInformationTableRVA: 0x%X", "DWORD", pImageDelayLoadIdx->UnloadInformationTableRVA);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DELAYLOAD_DESCRIPTOR, UnloadInformationTableRVA));

			ImGui::BulletText("[%s] TimeDateStamp: 0x%X", "DWORD", pImageDelayLoadIdx->TimeDateStamp);
			if (PRSR_TOOLTIP)
				ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_DELAYLOAD_DESCRIPTOR, TimeDateStamp));

			ImGui::TreePop();
		}
	}
}

VOID Parser::Helpers::ParseCOMDir(DWORD BaseOffset)
{
	const PIMAGE_COR20_HEADER pImageCor20Header = reinterpret_cast<PIMAGE_COR20_HEADER>((UINT_PTR)g_pDosHeader + BaseOffset);

	ImGui::BulletText("[%s] cb: 0x%X", "DWORD", pImageCor20Header->cb);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, cb));

	ImGui::BulletText("[%s] MajorRuntimeVersion: 0x%X", "WORD", pImageCor20Header->MajorRuntimeVersion);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, MajorRuntimeVersion));

	ImGui::BulletText("[%s] MinorRuntimeVersion: 0x%X", "WORD", pImageCor20Header->MinorRuntimeVersion);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, MinorRuntimeVersion));

	const bool Collapsing_ImageCor20Header_MetaData = ImGui::TreeNode(static_cast<void*>(nullptr), "[%s] MetaData", "IMAGE_DATA_DIRECTORY");
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, MetaData));

	if (Collapsing_ImageCor20Header_MetaData)
	{
		ImGui::BulletText("[%s] VirtualAddress: 0x%X", "DWORD", pImageCor20Header->MetaData.VirtualAddress);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, MetaData.VirtualAddress));

		ImGui::BulletText("[%s] Size: 0x%X", "DWORD", pImageCor20Header->MetaData.Size);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, MetaData.Size));

		ImGui::TreePop();
	}

	ImGui::BulletText("[%s] Flags: 0x%X", "DWORD", pImageCor20Header->Flags);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, Flags));

	ImGui::BulletText("[%s] %s: 0x%X", "DWORD", (pImageCor20Header->Flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) ? "EntryPointRVA" : "EntryPointToken", pImageCor20Header->EntryPointRVA);
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, EntryPointRVA));

	const bool Collapsing_ImageCor20Header_Resources = ImGui::TreeNode(static_cast<void*>(nullptr), "[%s] Resources", "IMAGE_DATA_DIRECTORY");
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, Resources));

	if (Collapsing_ImageCor20Header_Resources)
	{
		ImGui::BulletText("[%s] VirtualAddress: 0x%X", "DWORD", pImageCor20Header->Resources.VirtualAddress);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, Resources.VirtualAddress));

		ImGui::BulletText("[%s] Size: 0x%X", "DWORD", pImageCor20Header->Resources.Size);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, Resources.Size));

		ImGui::TreePop();
	}

	const bool Collapsing_ImageCor20Header_StrongNameSignature = ImGui::TreeNode(static_cast<void*>(nullptr), "[%s] StrongNameSignature", "IMAGE_DATA_DIRECTORY");
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, StrongNameSignature));

	if (Collapsing_ImageCor20Header_StrongNameSignature)
	{
		ImGui::BulletText("[%s] VirtualAddress: 0x%X", "DWORD", pImageCor20Header->StrongNameSignature.VirtualAddress);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, StrongNameSignature.VirtualAddress));

		ImGui::BulletText("[%s] Size: 0x%X", "DWORD", pImageCor20Header->StrongNameSignature.Size);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, StrongNameSignature.Size));

		ImGui::TreePop();
	}

	const bool Collapsing_ImageCor20Header_CodeManagerTable = ImGui::TreeNode(static_cast<void*>(nullptr), "[%s] CodeManagerTable", "IMAGE_DATA_DIRECTORY");
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, CodeManagerTable));

	if (Collapsing_ImageCor20Header_CodeManagerTable)
	{
		ImGui::BulletText("[%s] VirtualAddress: 0x%X", "DWORD", pImageCor20Header->CodeManagerTable.VirtualAddress);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, CodeManagerTable.VirtualAddress));

		ImGui::BulletText("[%s] Size: 0x%X", "DWORD", pImageCor20Header->CodeManagerTable.Size);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, CodeManagerTable.Size));

		ImGui::TreePop();
	}

	const bool Collapsing_ImageCor20Header_VTableFixups = ImGui::TreeNode(static_cast<void*>(nullptr), "[%s] VTableFixups", "IMAGE_DATA_DIRECTORY");
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, VTableFixups));

	if (Collapsing_ImageCor20Header_VTableFixups)
	{
		ImGui::BulletText("[%s] VirtualAddress: 0x%X", "DWORD", pImageCor20Header->VTableFixups.VirtualAddress);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, VTableFixups.VirtualAddress));

		ImGui::BulletText("[%s] Size: 0x%X", "DWORD", pImageCor20Header->VTableFixups.Size);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, VTableFixups.Size));

		ImGui::TreePop();
	}

	const bool Collapsing_ImageCor20Header_ExportAddressTableJumps = ImGui::TreeNode(static_cast<void*>(nullptr), "[%s] ExportAddressTableJumps", "IMAGE_DATA_DIRECTORY");
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, ExportAddressTableJumps));

	if (Collapsing_ImageCor20Header_ExportAddressTableJumps)
	{
		ImGui::BulletText("[%s] VirtualAddress: 0x%X", "DWORD", pImageCor20Header->ExportAddressTableJumps.VirtualAddress);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, ExportAddressTableJumps.VirtualAddress));

		ImGui::BulletText("[%s] Size: 0x%X", "DWORD", pImageCor20Header->ExportAddressTableJumps.Size);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, ExportAddressTableJumps.Size));

		ImGui::TreePop();
	}

	const bool Collapsing_ImageCor20Header_ManagedNativeHeader = ImGui::TreeNode(static_cast<void*>(nullptr), "[%s] ManagedNativeHeader", "IMAGE_DATA_DIRECTORY");
	if (PRSR_TOOLTIP)
		ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, ManagedNativeHeader));

	if (Collapsing_ImageCor20Header_ManagedNativeHeader)
	{
		ImGui::BulletText("[%s] VirtualAddress: 0x%X", "DWORD", pImageCor20Header->ManagedNativeHeader.VirtualAddress);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, ManagedNativeHeader.VirtualAddress));

		ImGui::BulletText("[%s] Size: 0x%X", "DWORD", pImageCor20Header->ManagedNativeHeader.Size);
		if (PRSR_TOOLTIP)
			ImGui::SetTooltip("Offset: 0x%X", BaseOffset + offsetof(IMAGE_COR20_HEADER, ManagedNativeHeader.Size));

		ImGui::TreePop();
	}
}

DWORD Parser::Helpers::RVAToFileOffset(DWORD RVA)
{
	for (int i = 0; i < g_pFileHeader->NumberOfSections; i++)
	{
		const PIMAGE_SECTION_HEADER pIdxSection = &IMAGE_FIRST_SECTION(g_pNtHeaders)[i];

		if (RVA >= pIdxSection->VirtualAddress && RVA < pIdxSection->VirtualAddress + pIdxSection->Misc.VirtualSize)
			return RVA - pIdxSection->VirtualAddress + pIdxSection->PointerToRawData;
	}

	return RVA;
}