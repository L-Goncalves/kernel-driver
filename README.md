## Kernel Driver Features


The kernel driver has been tested on the following Windows version:

- Windows 10 Pro Version 22H2 (OS Build 19045.4412)

I am not responsible if you test it in any other versions. I am not responsible for blue screens.

### Features:

- Write to Memory ✅
- Read Memory ✅
- Query Memory Information ✅
- Get Process ID ✅

### This kernel driver supports the following IOCTL operations:

- **Read Memory**
  - **IOCTL Code:** `IOCTL_READ_MEMORY`
  - **Description:** Reads memory from a specified process.
  - **IOCTL Definition:** `#define IOCTL_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)`

- **Write Memory**
  - **IOCTL Code:** `IOCTL_WRITE_MEMORY`
  - **Description:** Writes memory to a specified process.
  - **IOCTL Definition:** `#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)`

- **Query Memory Information**
  - **IOCTL Code:** `IOCTL_QUERY_MEMORY_INFO`
  - **Description:** Queries information about a specified memory region in a process.
  - **IOCTL Definition:** `#define IOCTL_QUERY_MEMORY_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)`

- **Get Process ID**
  - **IOCTL Code:** `IOCTL_GET_PROCESS_ID`
  - **Description:** Retrieves the process ID of a specified process by name.
  - **IOCTL Definition:** `#define IOCTL_GET_PROCESS_ID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)`

