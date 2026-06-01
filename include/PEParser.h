#include "PESectionHeaders.h"
#include <Windows.h>
#include <string>

class PEParser {
private:
    std::wstring m_filePath; // the .exe file path given by the user.
    LARGE_INTEGER m_fileSize; // the file size in bytes.
    HANDLE m_peFileHandle;  // the handle to the .exe file we open using CreateFileW.
    HANDLE m_sectionHandle; // the handle for the section we made for the PE file.
    LPVOID m_baseAddress; // the base address of the memory mapped PE file.
    LPVOID m_ntHeadersBaseAddress; // the base address of the NT headers of the PE file.
    IMAGE_DOS_HEADER* m_dosHeader; // the DOS header of the PE file.
    // IMAGE_DOS_STUB* m_dosStub; // the DOS stub of the PE file.
    IMAGE_NT_HEADERS* m_ntHeaders; // the NT headers of the PE file.
    PESectionHeaders* m_sectionHeaders; // the section headers of the PE file.

public:
    PEParser(const wchar_t* filePath);
    ~PEParser();

    bool Load(); // Load() opens and loads the PE file to memory.
    bool ParseDOSHeader(); // ParseDOSHeader() validates and parses the DOS header.
    // bool ParseDOSStub(); // ParseDOSStub() validates and parses the DOS stub.
    bool ParseNTHeaders(); // ParseNTHeaders() validates and parses the DOS NT headers.
    bool ParseSectionHeaders(); // ParseSectionHeaders() validates and parses the section headers.
    bool ParseDataDirectories(); // ParseDataDirectories() parses the data directories inside the PE file.
    DWORD RVAToOffset(DWORD dataDirVirtAddr, DWORD sectionVirtAddr, DWORD rawAddr); // RVAToOffset returns the raw file offset for the RVA.
};