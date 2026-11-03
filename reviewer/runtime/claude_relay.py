"""In-sandbox loopback relay of the AGENTIC claude-cli mode (claude-cli-isolated@6; reviewer.runtime.claude_agentic).

The agentic sandbox has NO network (bwrap --unshare-net: only its own loopback). This trusted helper - standard library only, run
as `/usr/bin/python3 -I -B /pullo/relay.py <port> <unix socket> -- <claude argv...>` - binds 127.0.0.1:<port> INSIDE the sandbox's
private network namespace, forks a relay process that pipes every accepted TCP connection byte-for-byte to ONE unix socket (the
host forwarder's, bind-mounted read-only at <unix socket>), and execs the CLI in its own place, so the CLI keeps the sandbox's
stdin/stdout/stderr and the inherited OAuth token fd. The relay process drops stdio and the token fd first. It connects to nothing
but that one socket path, reads no file, and dies with the sandbox's PID namespace when the CLI exits. The forwarder does all
auditing; the relay only moves bytes."""
import os
import socket
import sys
import threading

TOKEN_FD_ENV = "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"
BUF = 65536


def _pump(src, dst):
    try:
        while True:
            b = src.recv(BUF)
            if not b:
                break
            dst.sendall(b)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _handle(conn, path):
    up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        up.connect(path)
    except OSError:
        conn.close()
        up.close()
        return
    back = threading.Thread(target=_pump, args=(up, conn), daemon=True)
    back.start()
    _pump(conn, up)
    back.join()
    conn.close()
    up.close()


def _serve(lst, path):
    while True:
        try:
            conn, _ = lst.accept()
        except OSError:
            return
        threading.Thread(target=_handle, args=(conn, path), daemon=True).start()


def main(argv):
    if len(argv) < 5 or argv[3] != "--" or not argv[1].isdigit():
        sys.stderr.write("usage: relay.py <port> <unix socket> -- <argv...>\n")
        return 2
    port, path, cmd = int(argv[1]), argv[2], argv[4:]
    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(("127.0.0.1", port))
    lst.listen(16)
    pid = os.fork()
    if pid == 0:                                   # the relay: no stdio, no token fd, only the listener and the one socket path
        fd = os.environ.get(TOKEN_FD_ENV, "")
        if fd.isdigit():
            try:
                os.close(int(fd))
            except OSError:
                pass
        null = os.open(os.devnull, os.O_RDWR)
        for i in (0, 1, 2):
            os.dup2(null, i)
        try:
            _serve(lst, path)
        finally:
            os._exit(0)
    lst.close()
    os.execvp(cmd[0], cmd)                          # the CLI, in this process: stdio and the token fd stay its own
    return 127


if __name__ == "__main__":
    sys.exit(main(sys.argv))
