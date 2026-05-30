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

    // step 2: create a section object for the opened PE file
    std::wcout << L"\ncreating the section object for the opened PE file...\n";
    m_sectionHandle = CreateFileMappingW(m_peFileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (m_sectionHandle == NULL) {
        // TODO: call GetLastError and log why it failed.
        std::wcout << L"could not create a section object for the opened PE file.\n";
        return false;
    }
    std::wcout << L"section object created successfully.\n";
    
    // step 3: map the section to the memory of the current process
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
    std::wcout << L"magic bytes are valid.";

    return true;
}

bool PEParser::ParseDOSStub() {
    // step 1: cast the address of DOS stub as an IMAGE_DOS_STUB* pointer (m_baseAddress + sizeof())
    return true;
}