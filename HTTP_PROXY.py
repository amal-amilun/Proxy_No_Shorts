import socket
import threading
import sys

def handle_client(client_socket):

    # Terima request dari client
    request = client_socket.recv(4096)

    print("\n=== REQUEST DATA ===")
    print(request.decode('utf-8', errors='ignore')[:500])

    # Parse host dan port
    first_line = request.split(b'\n')[0]
    url = first_line.split(b' ')[1]

    # Membuang http://
    http_pos = url.find(b'://')
    if http_pos == -1:
        temp = url
    else:
        temp = url[(http_pos + 3):]

    port_pos = temp.find(b':')
    host_pos = temp.find(b'/')

    if host_pos == -1:
        host_pos = len(temp)

    host = ''
    port = 80

    if port_pos == -1 or host_pos < port_pos:
        host = temp[:host_pos]
    else:
        host = temp[:port_pos]
        port = int(temp[port_pos+1:host_pos])

    # Buat koneksi ke server asli
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((host, port))
    server_socket.sendall(request)

    # Terima response
    response = b''
    while True:
        data = server_socket.recv(4096)
        if not data:
            break
        response += data
        client_socket.send(data)

    print("\n=== RESPONSE DITERIMA ===")
    print(response.decode('utf-8', errors='ignore')[:300])

    server_socket.close()
    client_socket.close()

def start_proxy(host='127.0.0.1', port=8081):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)

    print(f"[+] Proxy berjalan di {host}:{port}")
    
    while True:
        client_socket, addr = server.accept()
        print(f"[+] Connection dari {addr}")
        thread = threading.Thread(target=handle_client, args={client_socket,})
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    start_proxy()