#include <windows.h>
#include <stdio.h>
#include <winsvc.h>
#include "driver_control.h"

// Resource ID for the embedded driver
#define IDR_PROCEXP_SYS 101

// Driver service name
#define DRIVER_SERVICE_NAME L"ProcExpByok"
#define DRIVER_DISPLAY_NAME L"Process Explorer BYOK Driver"

BOOL ExtractDriverFromResource(LPCWSTR driverPath) {
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_PROCEXP_SYS), RT_RCDATA);
    if (!hResource) {
        printf("Failed to find driver resource. Error: %lu\n", GetLastError());
        return FALSE;
    }

    HGLOBAL hGlobal = LoadResource(NULL, hResource);
    if (!hGlobal) {
        printf("Failed to load driver resource. Error: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD resourceSize = SizeofResource(NULL, hResource);
    LPVOID resourceData = LockResource(hGlobal);
    
    if (!resourceData) {
        printf("Failed to lock driver resource. Error: %lu\n", GetLastError());
        return FALSE;
    }

    HANDLE hFile = CreateFileW(driverPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create driver file. Error: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD bytesWritten;
    BOOL result = WriteFile(hFile, resourceData, resourceSize, &bytesWritten, NULL);
    CloseHandle(hFile);

    if (!result || bytesWritten != resourceSize) {
        printf("Failed to write driver file. Error: %lu\n", GetLastError());
        return FALSE;
    }

    printf("Driver extracted successfully to: %ws\n", driverPath);
    return TRUE;
}

BOOL LoadDriver(LPCWSTR driverPath) {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scManager) {
        printf("Failed to open Service Control Manager. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Try to open existing service first
    SC_HANDLE scService = OpenServiceW(scManager, DRIVER_SERVICE_NAME, SERVICE_ALL_ACCESS);
    
    if (!scService) {
        // Create new service
        scService = CreateServiceW(
            scManager,
            DRIVER_SERVICE_NAME,
            DRIVER_DISPLAY_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPath,
            NULL, NULL, NULL, NULL, NULL
        );
        
        if (!scService) {
            printf("Failed to create driver service. Error: %lu\n", GetLastError());
            CloseServiceHandle(scManager);
            return FALSE;
        }
        printf("Driver service created successfully.\n");
    }

    // Start the service
    BOOL result = StartService(scService, 0, NULL);
    if (!result) {
        DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("Failed to start driver service. Error: %lu\n", error);
            CloseServiceHandle(scService);
            CloseServiceHandle(scManager);
            return FALSE;
        }
        printf("Driver service already running.\n");
    } else {
        printf("Driver service started successfully.\n");
    }

    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
    return TRUE;
}

BOOL UnloadDriver() {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scManager) {
        printf("Failed to open Service Control Manager. Error: %lu\n", GetLastError());
        return FALSE;
    }

    SC_HANDLE scService = OpenServiceW(scManager, DRIVER_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!scService) {
        printf("Failed to open driver service. Error: %lu\n", GetLastError());
        CloseServiceHandle(scManager);
        return FALSE;
    }

    SERVICE_STATUS serviceStatus;
    BOOL result = ControlService(scService, SERVICE_CONTROL_STOP, &serviceStatus);
    if (!result) {
        printf("Failed to stop driver service. Error: %lu\n", GetLastError());
    } else {
        printf("Driver service stopped successfully.\n");
    }

    // Delete the service
    if (DeleteService(scService)) {
        printf("Driver service deleted successfully.\n");
    } else {
        printf("Failed to delete driver service. Error: %lu\n", GetLastError());
    }

    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
    return result;
}

BOOL CloseProtectedHandle(DWORD processId, HANDLE handle) {
    HANDLE hDevice = CreateFileW(L"\\\\.\\ProcExp152", 
                                GENERIC_READ | GENERIC_WRITE,
                                0, NULL, OPEN_EXISTING, 0, NULL);
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open driver device. Error: %lu\n", GetLastError());
        return FALSE;
    }

    PROCEXP_CLOSE_HANDLE_INPUT input = {0};
    input.ProcessId = processId;
    input.Handle = (ULONG_PTR)handle;

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(hDevice, IOCTL_PROCEXP_CLOSE_HANDLE,
                                 &input, sizeof(input),
                                 NULL, 0,
                                 &bytesReturned, NULL);

    if (!result) {
        printf("Failed to close protected handle. Error: %lu\n", GetLastError());
    } else {
        printf("Protected handle closed successfully.\n");
    }

    CloseHandle(hDevice);
    return result;
}

void PrintUsage() {
    printf("Usage: ProcExpBYOK.exe [options]\n");
    printf("Options:\n");
    printf("  -load              Load the driver\n");
    printf("  -unload            Unload the driver\n");
    printf("  -close <pid> <handle>  Close protected handle\n");
    printf("  -help              Show this help message\n");
}

int main(int argc, char* argv[]) {
    printf("Process Explorer BYOK (Bring Your Own Kernel) v1.0\n");
    printf("========================================\n\n");

    // Check for administrator privileges
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    if (!isAdmin) {
        printf("Error: This program requires administrator privileges.\n");
        return 1;
    }

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    wcscat_s(tempPath, MAX_PATH, L"procexp152.sys");

    if (strcmp(argv[1], "-load") == 0) {
        printf("Extracting driver from resources...\n");
        if (!ExtractDriverFromResource(tempPath)) {
            return 1;
        }

        printf("Loading driver...\n");
        if (!LoadDriver(tempPath)) {
            return 1;
        }

        printf("Driver loaded successfully. Device available at \\\\.\\ProcExp152\n");
    }
    else if (strcmp(argv[1], "-unload") == 0) {
        printf("Unloading driver...\n");
        if (!UnloadDriver()) {
            return 1;
        }

        // Clean up the extracted driver file
        DeleteFileW(tempPath);
        printf("Driver unloaded successfully.\n");
    }
    else if (strcmp(argv[1], "-close") == 0) {
        if (argc < 4) {
            printf("Error: -close requires process ID and handle value.\n");
            PrintUsage();
            return 1;
        }

        DWORD processId = (DWORD)strtoul(argv[2], NULL, 0);
        HANDLE handle = (HANDLE)(ULONG_PTR)strtoull(argv[3], NULL, 0);

        printf("Attempting to close handle 0x%p in process %lu...\n", handle, processId);
        if (!CloseProtectedHandle(processId, handle)) {
            return 1;
        }
    }
    else if (strcmp(argv[1], "-help") == 0) {
        PrintUsage();
    }
    else {
        printf("Error: Unknown option '%s'\n\n", argv[1]);
        PrintUsage();
        return 1;
    }

    return 0;
}
