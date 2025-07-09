#ifndef DRIVER_CONTROL_H
#define DRIVER_CONTROL_H

#include <windows.h>

// IOCTL codes for ProcExp driver communication
#define IOCTL_PROCEXP_CLOSE_HANDLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structure for close handle input
typedef struct _PROCEXP_CLOSE_HANDLE_INPUT {
    ULONG ProcessId;
    ULONG_PTR Handle;
} PROCEXP_CLOSE_HANDLE_INPUT, *PPROCEXP_CLOSE_HANDLE_INPUT;

// Function declarations
BOOL ExtractDriverFromResource(LPCWSTR driverPath);
BOOL LoadDriver(LPCWSTR driverPath);
BOOL UnloadDriver(void);
BOOL CloseProtectedHandle(DWORD processId, HANDLE handle);

#endif // DRIVER_CONTROL_H
