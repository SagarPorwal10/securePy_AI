import subprocess
def tail_log(path):
    subprocess.run(["tail", path], check=True)
