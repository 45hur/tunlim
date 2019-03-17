import sys
import os

def write_stdout(s):
    # only eventlistener protocol messages may be sent to stdout
    sys.stdout.write(s)
    sys.stdout.flush()

def write_stderr(s):
    sys.stderr.write(s)
    sys.stderr.flush()

def main():
    while 1:
        # transition from ACKNOWLEDGED to READY
        write_stdout('READY\n')

        # read header line and print it to stderr
        line = sys.stdin.readline()
        write_stderr(line)

        if line.find('processname:resolver_') >= 0 and (line.find('from_state:EXITED') >= 0 or line.find('from_state:BACKOFF') >= 0) and line.find('eventname:PROCESS_STATE_BACKOFF') >= 0:
            write_stderr('Trying to delete root.keys and cache\n')
            try:
                os.remove('/etc/kres/root.keys')
                os.remove('/var/lib/kres/cache/data.mdb')
                os.remove('/var/lib/kres/cache/lock.mdb')
            except Exception as ex:
                write_stderr('Failed to delete root.keys or cache, exception:\n')
                write_stderr(ex)
                write_stderr('\n')

        # transition from READY to ACKNOWLEDGED
        write_stdout('RESULT 2\nOK')

if __name__ == '__main__':
    main()

