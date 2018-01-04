from subprocess import Popen, PIPE, CalledProcessError


def execute(cmd):
    proc = Popen(cmd, shell=True, stdout=PIPE, bufsize=1,universal_newlines=True)
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        print(line, end='')
    proc.wait()
    if proc.returncode != 0:
        raise CalledProcessError(p.returncode, p.args)
cmd = ' '.join(["python fake_AP_output.py"])

execute(cmd)
