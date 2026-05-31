#include <vector>
#include <Windows.h>

class PESectionHeaders {
private:
    std::vector<IMAGE_SECTION_HEADER*> m_sectionHeaders; // m_sectionHeaders is a vector which stores all section headers.
    // WORD m_numberOfSections; // total number of sections in the PE file.
public:
    PESectionHeaders(WORD numberOfSections); // PESectionHeaders contructor

    bool ParseSectionHeaders(IMAGE_NT_HEADERS* ntHeaders);
};