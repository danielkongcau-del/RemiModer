#include <windows.h>
extern "C" __declspec(dllexport) unsigned FixtureDependency(){return 42;}
BOOL WINAPI DllMain(HINSTANCE,DWORD,LPVOID){return TRUE;}
