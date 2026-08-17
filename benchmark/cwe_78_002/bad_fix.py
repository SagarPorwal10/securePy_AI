import os
def tail_log(path):
    os.system("tail -n 20 " + path)
