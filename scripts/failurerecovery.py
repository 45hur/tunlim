import sys
import os
import signal

def write_stdout(s):
    sys.stdout.write(s)
    sys.stdout.flush()

def write_stderr(s):
    sys.stderr.write(s)
    sys.stderr.flush()

def main():
    while 1:
        write_stdout('READY\n')
        line = sys.stdin.readline()
        if line.find('processname:resolver_') >= 0:
            os.kill(1, signal.SIGTERM)
        write_stdout('RESULT 2\nOK')

if __name__ == '__main__':
    main()
