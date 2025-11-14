/*
 * Fast Ping Module - C++ Implementation
 * High-performance ICMP ping for network automation
 */

#include <Python.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

// Calculate checksum for ICMP packet
unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Perform ICMP ping
static PyObject* fast_ping_ping(PyObject* self, PyObject* args) {
    const char* ip_address;
    int timeout = 2;

    if (!PyArg_ParseTuple(args, "s|i", &ip_address, &timeout)) {
        return NULL;
    }

    int sock;
    struct sockaddr_in addr;
    struct icmp icmp_packet;
    char recv_buffer[1024];
    struct timeval tv_timeout, start_time, end_time;
    double elapsed_ms;

    // Create raw socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        // If we can't create raw socket (no permissions), return error gracefully
        PyObject* result = PyDict_New();
        PyDict_SetItemString(result, "reachable", Py_False);
        PyDict_SetItemString(result, "time_ms", PyFloat_FromDouble(0.0));
        PyDict_SetItemString(result, "error", PyUnicode_FromString("No permission for raw socket"));
        return result;
    }

    // Set socket timeout
    tv_timeout.tv_sec = timeout;
    tv_timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));

    // Prepare destination address
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip_address);

    // Prepare ICMP packet
    memset(&icmp_packet, 0, sizeof(icmp_packet));
    icmp_packet.icmp_type = ICMP_ECHO;
    icmp_packet.icmp_code = 0;
    icmp_packet.icmp_id = getpid();
    icmp_packet.icmp_seq = 1;
    icmp_packet.icmp_cksum = checksum(&icmp_packet, sizeof(icmp_packet));

    // Record start time
    gettimeofday(&start_time, NULL);

    // Send ICMP packet
    if (sendto(sock, &icmp_packet, sizeof(icmp_packet), 0,
               (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
        close(sock);
        PyObject* result = PyDict_New();
        PyDict_SetItemString(result, "reachable", Py_False);
        PyDict_SetItemString(result, "time_ms", PyFloat_FromDouble(0.0));
        PyDict_SetItemString(result, "error", PyUnicode_FromString("Send failed"));
        return result;
    }

    // Receive response
    socklen_t addr_len = sizeof(addr);
    int bytes_received = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0,
                                   (struct sockaddr*)&addr, &addr_len);

    // Record end time
    gettimeofday(&end_time, NULL);

    // Calculate elapsed time
    elapsed_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0;
    elapsed_ms += (end_time.tv_usec - start_time.tv_usec) / 1000.0;

    close(sock);

    // Create result dictionary
    PyObject* result = PyDict_New();

    if (bytes_received > 0) {
        PyDict_SetItemString(result, "reachable", Py_True);
        PyDict_SetItemString(result, "time_ms", PyFloat_FromDouble(elapsed_ms));
    } else {
        PyDict_SetItemString(result, "reachable", Py_False);
        PyDict_SetItemString(result, "time_ms", PyFloat_FromDouble(0.0));
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            PyDict_SetItemString(result, "error", PyUnicode_FromString("Timeout"));
        } else {
            PyDict_SetItemString(result, "error", PyUnicode_FromString("Receive failed"));
        }
    }

    return result;
}

// Module method definitions
static PyMethodDef FastPingMethods[] = {
    {"ping", fast_ping_ping, METH_VARARGS,
     "Perform ICMP ping to an IP address\n\n"
     "Args:\n"
     "    ip_address (str): Target IP address\n"
     "    timeout (int): Timeout in seconds (default: 2)\n\n"
     "Returns:\n"
     "    dict: {'reachable': bool, 'time_ms': float, 'error': str}\n"},
    {NULL, NULL, 0, NULL}
};

// Module definition
static struct PyModuleDef fast_ping_module = {
    PyModuleDef_HEAD_INIT,
    "fast_ping",
    "High-performance ICMP ping module for network automation",
    -1,
    FastPingMethods
};

// Module initialization
PyMODINIT_FUNC PyInit_fast_ping(void) {
    return PyModule_Create(&fast_ping_module);
}
