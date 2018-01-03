import os
def validate_port(port):
    output = os.popen('netstat -anp | grep {}'.format(port)).read()
    if output == '':
        return True
    return False

