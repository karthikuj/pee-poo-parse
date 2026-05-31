#include "PEParser.h"
#include <Windows.h>
#include <string>
#include <iostream>

PEParser::PEParser(const wchar_t* filePath) {
    // step 1: check if the file path is empty
    if (filePath[0] == L'\0') {
        std::wcout << L"ayo! the file path is empty\n";
    }

    // step 2: store it in our private member variable
    m_filePath = filePath;
    std::wcout << L"The file path is " << m_filePath << L"\n";
}

PEParser::~PEParser() {
    if (m_baseAddress != NULL) {
        UnmapViewOfFile(m_baseAddress);
    }
    
    if (m_sectionHandle != NULL) {
        CloseHandle(m_sectionHandle);
    }

    if (m_peFileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_peFileHandle);
    }
}

bool PEParser::Load() {
    // step 1: open the PE file using CreateFileW
    std::wcout << L"\nopening the PE file...\n";
    m_peFileHandle = CreateFileW(m_filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_peFileHandle == INVALID_HANDLE_VALUE) {
        std::wcout << L"could not open a handle to the specified file.\n";
        return false;
    }
    std::wcout << L"PE file opened successfully.\n";

    // step 2: get the file size
    std::wcout << L"\nfetching the file size...\n";
    if (GetFileSizeEx(m_peFileHandle, &m_fileSize) == 0) {
        std::wcout << L"could not fetch the file size.\n";
        return false;
    }
    std::wcout << L"file size fetched sucessfully: " << m_fileSize.QuadPart << L" bytes.\n";

    // step 3: create a section object for the opened PE file
    std::wcout << L"\ncreating the section object for the opened PE file...\n";
    m_sectionHandle = CreateFileMappingW(m_peFileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (m_sectionHandle == NULL) {
        // TODO: call GetLastError and log why it failed.
        std::wcout << L"could not create a section object for the opened PE file.\n";
        return false;
    }
    std::wcout << L"section object created successfully.\n";
    
    // step 4: map the section to the memory of the current process
    std::wcout << L"\nmapping the section to the current process's virtual address space...\n";
    m_baseAddress = MapViewOfFile(m_sectionHandle, FILE_MAP_READ, 0, 0, 0);
    if (m_baseAddress == NULL) {
        // TODO: call GetLastError and log why it failed.
        std::wcout << L"could not map the section to memory.\n";
        return false;
    }
    std::wcout << L"successfully mapped the section to memory.\n";
    return true;
}

bool PEParser::ParseDOSHeader() {
    // step 1: cast the m_baseAddress pointer as an IMAGE_DOS_HEADER* pointer
    std::wcout << L"\nparsing the DOS header...\n";
    m_dosHeader = reinterpret_cast <IMAGE_DOS_HEADER*>(m_baseAddress);

    // step 2: validate if the magic bytes are correct
    // printf("magic of DOS header: %c%c\n",
    //    m_dosHeader->e_magic & 0xFF,
    //    (m_dosHeader->e_magic >> 8) & 0xFF);
    if (m_dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::wcout << L"magic bytes are invalid, exiting...\n";
        return false;
    }
    std::wcout << L"magic bytes are valid.\n";

    return true;
}

bool PEParser::ParseNTHeaders() {
    // step 1: validate the value of m_dosHeader->e_lfanew
    std::wcout << L"\nvalidating DOS header's e_lfanew...\n";
    // std::wcout << L"e_lfanew = " << m_dosHeader->e_lfanew << std::endl;
    // check if it is not negative or inside DOS header
    if (m_dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER)) {
        std::wcout << L"invalid e_lfanew value, should not be smaller than size of DOS header.\n";
        return false;
    }
    std::wcout << L"e_lfanew DOS header check passed.\n";

    // check if it is inside the scope of the file and there is enough space for the NT headers
    // calculate the size of signature (DWORD) and image file header
    size_t signatureAndImageFileHeaderSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if((static_cast<size_t>(m_dosHeader->e_lfanew) + signatureAndImageFileHeaderSize) > m_fileSize.QuadPart) {
        std::wcout << L"invalid e_lfanew, no space left for NT headers.\n";
        return false;
    }
    std::wcout << L"e_lfanew NT headers space check passed.\n";

    // validation for signature
    std::wcout << L"\nvalidating NT headers signature...\n";
    m_ntHeadersBaseAddress = reinterpret_cast<BYTE*>(m_baseAddress) + m_dosHeader->e_lfanew;
    DWORD* signature = reinterpret_cast<DWORD*>(m_ntHeadersBaseAddress);
    if (*signature != IMAGE_NT_SIGNATURE) {
        std::wcout << L"invalid NT header signature.\n";
        return false;
    }
    std::wcout << L"signature validated successfully.\n";
    

    // step 2: Fetch IMAGE_FILE_HEADER and check the value of SizeOfOptional header
    // validate that as well and read it if everything seems okay.
    std::wcout << L"\nparsing NT headers...\n";
    IMAGE_FILE_HEADER* imgFileHeader = reinterpret_cast <IMAGE_FILE_HEADER*>(
        reinterpret_cast<BYTE*>(m_ntHeadersBaseAddress) + sizeof(DWORD)
    );
    std::wcout << L"size of optional header is " << imgFileHeader->SizeOfOptionalHeader << L" bytes.\n";
    if((static_cast<size_t>(m_dosHeader->e_lfanew) + signatureAndImageFileHeaderSize + imgFileHeader->SizeOfOptionalHeader) > m_fileSize.QuadPart) {
        std::wcout << L"invalid SizeOfOptionalHeader, no space left for optional header.\n";
        return false;
    }
    IMAGE_NT_HEADERS* m_ntHeaders = reinterpret_cast <IMAGE_NT_HEADERS*>(m_ntHeadersBaseAddress);
    std::wcout << L"NT headers parsed successfully\n";

    return true;
}