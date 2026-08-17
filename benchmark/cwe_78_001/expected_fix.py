import subprocess
def ping_host(host):
    subprocess.run(["ping", "-c", "1", host], check=True)
