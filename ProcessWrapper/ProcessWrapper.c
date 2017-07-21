#include <stdio.h>
#include <WS2tcpip.h>
#include "Utils.h"
#include "Errors.h"
#include "Args.h"

#pragma comment(lib, "Ws2_32.lib")

#define SOCKET_COUNT 3
#define BUFFER_SIZE 1024

typedef enum _socket_state {
    SOCKET_STATE_WAIT_CONNECT,
    SOCKET_STATE_WAIT_ACK,
    SOCKET_STATE_CONNECTED,
    SOCKET_STATE_ERROR,
} socket_state_t;

typedef struct _socket_info {
    int id;
    SOCKET socket;
    socket_state_t state;
} socket_info_t;

typedef struct _pipe {
    HANDLE read;
    HANDLE write;
} pipe_t;

typedef struct _process_info {
    pipe_t pipes[3];
    PROCESS_INFORMATION process_info;
    SECURITY_ATTRIBUTES security_attributes;
    STARTUPINFO start_info;
} process_info_t;

typedef struct _file_socket_pair {
	int id;
    HANDLE file;
    SOCKET socket;
} file_socket_pair_t;

WSADATA wsa_data;

static program_arguments_t program_arguments;

static BOOL socket_connect(socket_info_t* socket_info)
{
    SOCKADDR* sockaddr;
    int namelen;
    u_long non_blocking = 1;

    int result = ioctlsocket(socket_info->socket, FIONBIO, &non_blocking);

    if (result != NO_ERROR) {
        error_push("Failed to set socket #%d to non-blocking mode, failed with %d", socket_info->id, result);
        return FALSE;
    }

    if (program_arguments.server_address_is_in6) {
        struct sockaddr_in6 addr;
        namelen = sizeof(addr);
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = *program_arguments.server_address.in6_addr;
        addr.sin6_flowinfo = 0; /* todo: I have no idea what this is for... */
        addr.sin6_port = htons(program_arguments.server_port);
        sockaddr = (SOCKADDR*)&addr;
    } else {
        struct sockaddr_in addr;
        namelen = sizeof(addr);
        addr.sin_family = AF_INET;
        addr.sin_addr = *program_arguments.server_address.in_addr;
        addr.sin_port = htons(program_arguments.server_port);
        sockaddr = (SOCKADDR*)&addr;
    }

    result = WSAConnect(socket_info->socket, sockaddr, namelen, NULL, NULL, NULL, NULL);

    /* Should fail with WSAEWOULDBLOCK */
    if (result != SOCKET_ERROR) {
        error_push("Connecting socket #%d unexpectedly succeeded", socket_info->id);
        return FALSE;
    }

    int error = WSAGetLastError();

    if (error != WSAEWOULDBLOCK) {
        system_error_push(error, "Connecting socket #%d failed", socket_info->id);
        return FALSE;
    }

    return TRUE;
}

/*
 * Process writability on a socket which is connecting
 */
static BOOL socket_process_connect_writable(socket_info_t* socket_info)
{
    WSABUF buffer;
    DWORD bytes_written;
    u_long non_blocking = 0;

    int result = ioctlsocket(socket_info->socket, FIONBIO, &non_blocking);

    if (result != NO_ERROR) {
        error_push("Failed to set socket #%d to blocking mode, failed with %d", socket_info->id, result);
        return FALSE;
    }

    buffer.len = asprintf(&buffer.buf, "%d;%s\n", socket_info->id, program_arguments.process_label);

    result = WSASend(socket_info->socket, &buffer, 1, &bytes_written, 0, NULL, NULL);
    free(buffer.buf);

    if (result == SOCKET_ERROR) {
        system_error_push(WSAGetLastError(), "Failed to send handshake to socket #%d", socket_info->id);
        return FALSE;
    }

    if (bytes_written != buffer.len) {
        error_push("Failed to send handshake to socket #%d: sent %d of %d bytes", socket_info->id, bytes_written, buffer.len);
        return FALSE;
    }

    socket_info->state = SOCKET_STATE_WAIT_ACK;

    return TRUE;
}

/*
 * Process readability on a socket which is connecting
 */
static BOOL socket_process_connect_readable(socket_info_t* socket_info)
{
    WSABUF buffer;
    DWORD bytes_read, flags = 0;

    buffer.buf = malloc(2);
    buffer.len = 2;

    int result = WSARecv(socket_info->socket, &buffer, 1, &bytes_read, &flags, NULL, NULL);

    if (result == SOCKET_ERROR) {
        system_error_push(WSAGetLastError(), "Failed to read handshake data from socket #%d", socket_info->id);
        free(buffer.buf);
        return FALSE;
    }

    if (bytes_read != buffer.len) {
        error_push("Failed to read handshake data from socket #%d: recieved %d of expected %d bytes", socket_info->id, bytes_read, buffer.len);
        free(buffer.buf);
        return FALSE;
    }

    if (buffer.buf[1] != '\n') {
        error_push("Handshake failed for socket #%d: Invalid data recieved: 0x%02X 0x%02X", socket_info->id, (int)buffer.buf[0], (int)buffer.buf[1]);
        free(buffer.buf);
        return FALSE;
    }

    char code = buffer.buf[0];
    free(buffer.buf);


    if (code != SUCCESS) {
        error_push("Handshake failed for socket #%d: Server rejected connection with code %d", socket_info->id, code);
        return FALSE;
    }

    socket_info->state = SOCKET_STATE_CONNECTED;

    return TRUE;
}

/*
 * Process error on a socket which is connecting
 */
static void socket_process_connect_error(socket_info_t* socket_info)
{
    int code;
    int len = sizeof(int);

    int result = getsockopt(socket_info->socket, SOL_SOCKET, SO_ERROR, (char*)&code, &len);

    if (result == SOCKET_ERROR) {
        error_push("Failed to connect socket #%d: Unkown error", socket_info->id);
    } else {
        system_error_push(code, "Failed to connect socket #%d", socket_info->id);
    }
}

/*
 * Determines whether any sockets have pending connect actions
 */
static BOOL socket_set_have_pending_connect(socket_info_t **sockets)
{
    for (int i = 0; i < SOCKET_COUNT; i++) {
        if (sockets[i]->state < SOCKET_STATE_CONNECTED) {
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * Initialize the sockets array
 */
static BOOL socket_set_create(socket_info_t** sockets)
{
    int address_family = program_arguments.server_address_is_in6 ? AF_INET6 : AF_INET;

    for (int i = 0; i < SOCKET_COUNT; i++) {
        socket_info_t* socket_info = malloc(sizeof(socket_info_t));

        socket_info->id = i;
        socket_info->state = SOCKET_STATE_WAIT_CONNECT;
        socket_info->socket = socket(address_family, SOCK_STREAM, IPPROTO_TCP);

        if (socket_info->socket == INVALID_SOCKET) {
            error_push("Failed to create socket #%d", socket_info->id);
            return FALSE;
        }

        sockets[i] = socket_info;
    }

    return TRUE;
}

/*
 * Thread main routine to connect sockets
 */
static DWORD WINAPI socket_set_connect(LPVOID param)
{
    socket_info_t **sockets = (socket_info_t**)param;
    FD_SET read_set;
    FD_SET write_set;
    FD_SET error_set;

    for (int i = 0; i < SOCKET_COUNT; i++) {
        if (!socket_connect(sockets[i])) {
            return FAILURE;
        }
    }

    while (socket_set_have_pending_connect(sockets)) {
        FD_ZERO(&read_set);
        FD_ZERO(&write_set);
        FD_ZERO(&error_set);

        for (int i = 0; i < SOCKET_COUNT; i++) {
            if (sockets[i]->state == SOCKET_STATE_WAIT_CONNECT) {
                FD_SET(sockets[i]->socket, &write_set);
                FD_SET(sockets[i]->socket, &error_set);
            } else if (sockets[i]->state == SOCKET_STATE_WAIT_ACK) {
                FD_SET(sockets[i]->socket, &read_set);
            }
        }

        int pending_activity_count = select(0, &read_set, &write_set, &error_set, NULL);

        if (pending_activity_count == SOCKET_ERROR) {
            system_error_push(WSAGetLastError(), "select() operation failed");
            return FAILURE;
        }

        if (pending_activity_count == 0) {
            error_push("select() unexpectedly returned zero sockets");
            return FAILURE;
        }

        for (int i = 0; pending_activity_count > 0 && i < SOCKET_COUNT; i++) {
            if (FD_ISSET(sockets[i]->socket, &read_set)) {
                if (!socket_process_connect_readable(sockets[i])) {
                    return FAILURE;
                }

                pending_activity_count--;
            } else if (FD_ISSET(sockets[i]->socket, &write_set)) {
                if (!socket_process_connect_writable(sockets[i])) {
                    return FAILURE;
                }

                pending_activity_count--;
            } else if (FD_ISSET(sockets[i]->socket, &error_set)) {
                socket_process_connect_error(sockets[i]);
                return FAILURE;
            }
        }
    }

    return SUCCESS;
}

static BOOL process_init(process_info_t *process_info)
{
    process_info->security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    process_info->security_attributes.bInheritHandle = TRUE;
    process_info->security_attributes.lpSecurityDescriptor = NULL;

    for (int i = 0; i < 3; i++) {
        if (!CreatePipe(&process_info->pipes[i].read, &process_info->pipes[i].write, &process_info->security_attributes, 0)) {
            error_push("Failed to create pipe for process I/O stream #%d", i);
            return FALSE;
        }

        if (!SetHandleInformation(i == 0 ? process_info->pipes[i].write : process_info->pipes[i].read, HANDLE_FLAG_INHERIT, 0)) {
            error_push("Failed to set handle information for process I/O stream #%d", i);
            return FALSE;
        }
    }

    process_info->start_info.cb = sizeof(STARTUPINFO);
    process_info->start_info.hStdInput = process_info->pipes[0].read;
    process_info->start_info.hStdOutput = process_info->pipes[1].write;
    process_info->start_info.hStdError = process_info->pipes[2].write;
    process_info->start_info.dwFlags |= STARTF_USESTDHANDLES;

    return TRUE;
}

static BOOL process_start(process_info_t *process_info)
{
    BOOL result = CreateProcess(
        NULL,
        program_arguments.exe_command_line,
        &process_info->security_attributes, // process security attributes 
        &process_info->security_attributes, // primary thread security attributes 
        TRUE, // handles are inherited 
        CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS,
        NULL, // use parent's environment 
        program_arguments.exe_cwd,
        &process_info->start_info,
        &process_info->process_info
    );

    if (!result) {
		system_error_push(GetLastError(), "Failed to create child process");
		return FALSE;
    }

	CloseHandle(process_info->process_info.hThread);

	return TRUE;
}

static DWORD WINAPI copy_file_to_socket(LPVOID param)
{
	DWORD bytes_read, bytes_written, flags = 0;
	WSABUF buffer;
	
	file_socket_pair_t *pair = (file_socket_pair_t*)param;

	buffer.buf = malloc(BUFFER_SIZE);
	buffer.len = BUFFER_SIZE;

	while (1) {
		int result = ReadFile(pair->file, buffer.buf, BUFFER_SIZE, &bytes_read, NULL);

		if (!result) {
			system_error_push(GetLastError(), "Failed to read from child process pipe #%d", pair->id);
			return FAILURE;
		}

		if (bytes_read == 0) {
			break;
		}

		result = WSASend(pair->socket, &buffer, 1, &bytes_written, flags, NULL, NULL);

		if (result == SOCKET_ERROR) {
			system_error_push(WSAGetLastError(), "Failed to send data to socket #%d", pair->id);
			return FAILURE;
		}

		if (bytes_written != bytes_read) {
			error_push("Failed to send data to socket #%d: sent %d of %d bytes", pair->id, bytes_written, bytes_read);
			return FALSE;
		}
    }

	CloseHandle(pair->file);
	closesocket(pair->socket);

    return SUCCESS;
}

static DWORD WINAPI copy_socket_to_file(LPVOID param)
{
	DWORD bytes_read, bytes_written, flags = 0;
	WSABUF buffer;
	file_socket_pair_t *pair = (file_socket_pair_t*)param;

	buffer.buf = malloc(BUFFER_SIZE);
	buffer.len = BUFFER_SIZE;

	while (1) {
		int result = WSARecv(pair->socket, &buffer, 1, &bytes_read, &flags, NULL, NULL);

		if (result == SOCKET_ERROR) {
			system_error_push(GetLastError(), "Failed to read from socket #%d", pair->id);
			return FAILURE;
		}

		if (bytes_read == 0) {
			break;
		}

		result = WriteFile(pair->file, buffer.buf, bytes_read, &bytes_written, NULL);

		if (!result) {
			system_error_push(GetLastError(), "Failed to send data to child process pipe #%d", pair->id);
			return FAILURE;
		}

		if (bytes_written != bytes_read) {
			error_push("Failed to send data to child process pipe #%d: sent %d of %d bytes", pair->id, bytes_written, bytes_read);
			return FALSE;
		}
	}

	CloseHandle(pair->file);
	closesocket(pair->socket);
	
	return SUCCESS;
}

int main(int argc, char** argv)
{
    DWORD exit_code;
    socket_info_t* sockets[SOCKET_COUNT];

    /* Initialize error handlers */
    errors_init();

    /* Initialize Winsock */
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);

    if (result != 0) {
        error_push("WSAStartup failed: %d", result);
    }

    /* Parse args */
    if (!parse_opts(&program_arguments, argc, argv)) {
        return errors_exit();
    }

    /* Connect to server */
    if (!socket_set_create(sockets)) {
        return errors_exit();
    }

    HANDLE connect_thread = CreateThread(NULL, 0, socket_set_connect, &sockets, 0, NULL);

    /* Initialize the data for the child process */
    process_info_t process_info;
    ZeroMemory(&process_info, sizeof(process_info_t));

    if (!process_init(&process_info)) {
        return errors_exit();
    }

    /* Wait until server is connected */
    if (WaitForSingleObject(connect_thread, INFINITE) == WAIT_FAILED) {
        system_error_push(GetLastError(), "Wait operation failed");
        return errors_exit();
    }
        
    if (!GetExitCodeThread(connect_thread, &exit_code)) {
        system_error_push(GetLastError(), "Retrieving connect thread exit code failed");
        return errors_exit();
    }

    if (exit_code != SUCCESS) {
        return errors_exit();
    }

    /* Start the process */
    if (!process_start(&process_info)) {
        return errors_exit();
    }

    /* Pass streams through */
    HANDLE copy_threads[SOCKET_COUNT + 1];

    file_socket_pair_t stdin_pair;
	stdin_pair.id = 0;
    stdin_pair.socket = sockets[0]->socket;
    stdin_pair.file = process_info.pipes[0].write;
    copy_threads[0] = CreateThread(NULL, 0, copy_socket_to_file, &stdin_pair, 0, NULL);

    file_socket_pair_t stdout_pair;
	stdout_pair.id = 1;
	stdout_pair.socket = sockets[1]->socket;
    stdout_pair.file = process_info.pipes[1].read;
    copy_threads[1] = CreateThread(NULL, 0, copy_file_to_socket, &stdout_pair, 0, NULL);

    file_socket_pair_t stderr_pair;
	stderr_pair.id = 2;
	stderr_pair.socket = sockets[2]->socket;
    stderr_pair.file = process_info.pipes[2].read;
    copy_threads[2] = CreateThread(NULL, 0, copy_file_to_socket, &stderr_pair, 0, NULL);

    copy_threads[3] = process_info.process_info.hProcess;

    /* Wait until the streams have finished and the process ends */
    if (WaitForMultipleObjects(SOCKET_COUNT + 1, copy_threads, TRUE, INFINITE) == WAIT_FAILED) {
        system_error_push(GetLastError(), "Wait operation failed");
    }

	/* Make sure all the copy threads completed without errors */
	for (int i = 0; i < SOCKET_COUNT; i++) {
		if (!GetExitCodeThread(copy_threads[i], &exit_code)) {
			system_error_push(GetLastError(), "Retrieving copy thread #%d exit code failed", i);
			return errors_exit();
		}

		if (exit_code != SUCCESS) {
			return errors_exit();
		}
	}

	/* Get the process' exit code and use it as our own */
    if (!GetExitCodeProcess(process_info.process_info.hProcess, &exit_code)) {
        system_error_push(GetLastError(), "Retrieving process exit code failed");
        return errors_exit();
    }

    return exit_code;
}
