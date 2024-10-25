#ifndef __LPC_PRIVATE_H
#define __LPC_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _NTDDK_
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x501
#include <Windows.h>
#include <winternl.h>

#ifndef _NTDLL_SELF_  // Auto-insert the library
#pragma comment(lib, "Ntdll.lib")
#endif

#endif

// Valid values for PORT_MESSAGE::u2::s2::Type
#define LPC_REQUEST 1
#define LPC_REPLY 2
#define LPC_DATAGRAM 3
#define LPC_LOST_REPLY 4
#define LPC_PORT_CLOSED 5
#define LPC_CLIENT_DIED 6
#define LPC_EXCEPTION 7
#define LPC_DEBUG_EVENT 8
#define LPC_ERROR_EVENT 9
#define LPC_CONNECTION_REQUEST 10

typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MY_CLIENT_ID;

typedef struct _PORT_MESSAGE {
    union {
        struct
        {
            USHORT DataLength;   // Length of data following the header (bytes)
            USHORT TotalLength;  // Length of data + sizeof(PORT_MESSAGE)
        } s1;
        ULONG Length;
    } u1;

    union {
        struct
        {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;

    union {
        MY_CLIENT_ID ClientId;
        double DoNotUseThisField;  // Force quadword alignment
    };

    ULONG MessageId;  // Identifier of the particular message instance

    union {
        ULONG_PTR ClientViewSize;  // Size of section created by the sender (in bytes)
        ULONG CallbackId;          //
    };

} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _PORT_VIEW {
    ULONG Length;          // Size of this structure
    HANDLE SectionHandle;  // Handle to section object with
                           // SECTION_MAP_WRITE and SECTION_MAP_READ
    ULONG SectionOffset;   // The offset in the section to map a view for
                           // the port data area. The offset must be aligned
                           // with the allocation granularity of the system.
    SIZE_T ViewSize;       // The size of the view (in bytes)
    PVOID ViewBase;        // The base address of the view in the creator
                           //
    PVOID ViewRemoteBase;  // The base address of the view in the process
                           // connected to the port.
} PORT_VIEW, *PPORT_VIEW;

//
// Define structure for shared memory coming from remote side of the port
//

typedef struct _REMOTE_PORT_VIEW {
    ULONG Length;     // Size of this structure
    SIZE_T ViewSize;  // The size of the view (bytes)
    PVOID ViewBase;   // Base address of the view

} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

#define InitializeMessageHeader(ph, l, t)                            \
    {                                                                \
        (ph)->u1.s1.TotalLength = (USHORT)(l);                       \
        (ph)->u1.s1.DataLength = (USHORT)(l - sizeof(PORT_MESSAGE)); \
        (ph)->u2.s2.Type = (USHORT)(t);                              \
        (ph)->u2.s2.DataInfoOffset = 0;                              \
        (ph)->ClientId.UniqueProcess = NULL;                         \
        (ph)->ClientId.UniqueThread = NULL;                          \
        (ph)->MessageId = 0;                                         \
        (ph)->ClientViewSize = 0;                                    \
    }

#ifdef _NTDDK_

typedef NTSTATUS(NTAPI* pFuncZwConnectPort)(
    __out PHANDLE PortHandle,
    __in PUNICODE_STRING PortName,
    __in PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    __inout_opt PPORT_VIEW ClientView,
    __inout_opt PREMOTE_PORT_VIEW ServerView,
    __out_opt PULONG MaxMessageLength,
    __inout_opt PVOID ConnectionInformation,
    __inout_opt PULONG ConnectionInformationLength);

typedef NTSTATUS(NTAPI* pFuncZwRequestWaitReplyPort)(
    __in HANDLE PortHandle,
    __in PPORT_MESSAGE RequestMessage,
    __out PPORT_MESSAGE ReplyMessage);
#else
/*++

    NtCreatePort
    ============

    Creates a LPC port object. The creator of the LPC port becomes a server
    of LPC communication

    PortHandle - Points to a variable that will receive the
        port object handle if the call is successful.

    ObjectAttributes - Points to a structure that specifies the object�s
        attributes. OBJ_KERNEL_HANDLE, OBJ_OPENLINK, OBJ_OPENIF, OBJ_EXCLUSIVE,
        OBJ_PERMANENT, and OBJ_INHERIT are not valid attributes for a port object.

    MaxConnectionInfoLength - The maximum size, in bytes, of data that can
        be sent through the port.

    MaxMessageLength - The maximum size, in bytes, of a message
        that can be sent through the port.

    MaxPoolUsage - Specifies the maximum amount of NonPaged pool that can be used for
        message storage. Zero means default value.

    ZwCreatePort verifies that (MaxDataSize <= 0x104) and (MaxMessageSize <= 0x148).

--*/

NTSYSAPI
NTSTATUS
NTAPI
NtCreatePort(
    OUT PHANDLE PortHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG MaxConnectionInfoLength,
    IN ULONG MaxMessageLength,
    IN ULONG MaxPoolUsage);

/*++

    NtReplyWaitReceivePort
    ======================

    Optionally sends a reply message to a port and waits for a
    message

    PortHandle - A handle to a port object. The handle doesn't need
        to grant any specific access.

    PortContext - Optionally points to a variable that receives
        a numeric identifier associated with the port.

    ReplyMessage - Optionally points to a caller-allocated buffer
        or variable that specifies the reply message to send to the port.

    ReceiveMessage - Points to a caller-allocated buffer or variable
        that receives the message sent to the port.

--*/
NTSYSAPI
NTSTATUS
NTAPI
NtReplyWaitReceivePort(
    IN HANDLE PortHandle,
    OUT PVOID* PortContext OPTIONAL,
    IN PPORT_MESSAGE ReplyMessage OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage);

/*++

    NtCreateSection
    ===============

    Creates a section object.

    SectionHandle - Points to a variable that will receive the section
        object handle if the call is successful.

    DesiredAccess - Specifies the type of access that the caller requires
        to the section object. This parameter can be zero, or any combination
        of the following flags:

        SECTION_QUERY       - Query access
        SECTION_MAP_WRITE   - Can be written when mapped
        SECTION_MAP_READ    - Can be read when mapped
        SECTION_MAP_EXECUTE - Can be executed when mapped
        SECTION_EXTEND_SIZE - Extend access
        SECTION_ALL_ACCESS  - All of the preceding +
                              STANDARD_RIGHTS_REQUIRED

    ObjectAttributes - Points to a structure that specifies the object�s attributes.
        OBJ_OPENLINK is not a valid attribute for a section object.

    MaximumSize - Optionally points to a variable that specifies the size,
        in bytes, of the section. If FileHandle is zero, the size must be
        specified; otherwise, it can be defaulted from the size of the file
        referred to by FileHandle.

    SectionPageProtection - The protection desired for the pages
        of the section when the section is mapped. This parameter can take
        one of the following values:

        PAGE_READONLY
        PAGE_READWRITE
        PAGE_WRITECOPY
        PAGE_EXECUTE
        PAGE_EXECUTE_READ
        PAGE_EXECUTE_READWRITE
        PAGE_EXECUTE_WRITECOPY

    AllocationAttributes - The attributes for the section. This parameter must
        be a combination of the following values:

        SEC_BASED     0x00200000    // Map section at same address in each process
        SEC_NO_CHANGE 0x00400000    // Disable changes to protection of pages
        SEC_IMAGE     0x01000000    // Map section as an image
        SEC_VLM       0x02000000    // Map section in VLM region
        SEC_RESERVE   0x04000000    // Reserve without allocating pagefile storage
        SEC_COMMIT    0x08000000    // Commit pages; the default behavior
        SEC_NOCACHE   0x10000000    // Mark pages as non-cacheable

    FileHandle - Identifies the file from which to create the section object.
        The file must be opened with an access mode compatible with the protection
        flags specified by the Protect parameter. If FileHandle is zero,
        the function creates a section object of the specified size backed
        by the paging file rather than by a named file in the file system.

--*/
NTSYSAPI
NTSTATUS
NTAPI
NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL);

/*++

    NtAcceptConnectPort
    ===================

    Accepts or rejects a connection request on the server side.

    PortHandle - Points to a variable that will receive the port object
        handle if the call is successful.

    PortContext - A numeric identifier to be associated with the port.

    ConnectionRequest - Points to a caller-allocated buffer or variable
        that identifies the connection request and contains any connect
        data that should be returned to requestor of the connection

    AcceptConnection - Specifies whether the connection should
        be accepted or not

    ServerView - Optionally points to a structure describing
        the shared memory region used to send large amounts of data to the
        requestor; if the call is successful, this will be updated

    ClientView - Optionally points to a caller-allocated buffer
        or variable that receives information on the shared memory
        region used by the requestor to send large amounts of data to the
        caller

--*/
NTSYSAPI
NTSTATUS
NTAPI
NtAcceptConnectPort(
    OUT PHANDLE PortHandle,
    IN PVOID PortContext OPTIONAL,
    IN PPORT_MESSAGE ConnectionRequest,
    IN BOOLEAN AcceptConnection,
    IN OUT PPORT_VIEW ServerView OPTIONAL,
    OUT PREMOTE_PORT_VIEW ClientView OPTIONAL);

/*++

    NtCompleteConnectPort
    =====================

    Completes the port connection process on the server side.

    PortHandle - A handle to a port object. The handle doesn't need
        to grant any specific access.

--*/
NTSYSAPI
NTSTATUS
NTAPI
NtCompleteConnectPort(
    IN HANDLE PortHandle);

/*++
    NtReplyPort
    ===========

    Sends a reply message to a port (Server side)

    PortHandle - A handle to a port object. The handle doesn't need
        to grant any specific access.

    ReplyMessage - Points to a caller-allocated buffer or variable
        that specifies the reply message to send to the port.
--*/
NTSYSAPI
NTSTATUS
NTAPI
NtReplyPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE ReplyMessage);
#endif

// TODO(whether)
#ifdef _WIN64
#define MAX_LPC_MESSAGE_LENGTH 648  // 0x288
#else
#define MAX_LPC_MESSAGE_LENGTH 328  // 0x148
#endif
#define MAX_LPC_DATA_LENGTH MAX_LPC_MESSAGE_LENGTH - sizeof(LPC_MSG)

// single message size limit by shared memory
#define LARGE_MESSAGE_SIZE 0x1000

// struct for lpc connection
typedef struct _CONN_INFO {
    HANDLE hPort;
    HANDLE hSection;
    PUINT8 pInData;
    PUINT8 pOutData;
} CONN_INFO, *PCONN_INFO;

// struct for lpc buffer
typedef struct _LPC_MSG {
    PORT_MESSAGE Header;
    ULONG Command;
    ULONG DataSize;
    BOOLEAN UseSection;  // 1 byte
    UINT8 Content[1];
} LPC_MSG, *PLPC_MSG;

#ifdef __cplusplus
}
#endif

#endif