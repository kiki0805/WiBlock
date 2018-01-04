from subprocess import Popen, PIPE, CalledProcessError
import threading

connec

def execute():
    cmd = ' '.join(["python fake_AP_output.py"])
    proc = Popen(cmd, shell=True, stdout=PIPE, bufsize=1,universal_newlines=True)
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        handle_line(line)
        print(line, end='')
    proc.wait()
    if proc.returncode != 0:
        raise CalledProcessError(p.returncode, p.args)

t = threading.Thread(target=execute)
t.start()
