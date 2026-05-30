#include <stdio.h>
#include <PEParser.h>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        printf("Please provide a file path.\n");
        return 1;
    }

    PEParser pep(argv[1]);

    if(!pep.Load()) return 1;
    if(!pep.ParseDOSHeader()) return 1;
    if (!pep.ParseNTHeaders()) return 1;

    return 0;
}