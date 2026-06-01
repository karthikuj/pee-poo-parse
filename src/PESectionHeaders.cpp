#include "PESectionHeaders.h"
#include <Windows.h>
#include <iostream>

PESectionHeaders::PESectionHeaders(WORD numberOfSections) {
    m_sectionHeaders.reserve(numberOfSections);
    // m_numberOfSections = numberOfSections;
}

bool PESectionHeaders::ParseSectionHeaders(IMAGE_NT_HEADERS* ntHeaders) {
    IMAGE_SECTION_HEADER* sectionHeaderArray = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* currSection = &sectionHeaderArray[i];
        m_sectionHeaders.push_back(currSection);
        std::string safeSectionName(reinterpret_cast<char*>(currSection->Name), 8);
    }
    return true;
}

std::vector<IMAGE_SECTION_HEADER*> PESectionHeaders::GetSectionHeaders() {
    return m_sectionHeaders;
}