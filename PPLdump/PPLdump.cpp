#include "exploit.h"

#include <iostream>

BOOL g_bVerbose = FALSE;
BOOL g_bDebug = FALSE;
BOOL g_bForce = TRUE;

int wmain(int argc, wchar_t* argv[])
{
    DumpProcess();
    return 0;
}
