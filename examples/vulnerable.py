import os
import pickle
import subprocess
import yaml


# SecurePy AI mock patch
def securepy_mock_fix():
    # Replace with validated secure implementation.
    return None
# SecurePy AI mock patch
def securepy_mock_fix():
    # Replace with validated secure implementation.
    return None
db_secret = "supersecret123"

username = "sagar"


def get_user(user_id):
    # SEC102: SQL injection using f-string
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query


def search_user(name):
    # SEC102: SQL injection using % formatting
    query = "SELECT * FROM users WHERE name = '%s'" % name
    return query


def run_ping(host):
    # SEC103: Command injection using os.system
    os.system("ping -c 1 " + host)


def run_shell_command(command):
    # SEC103: Command injection using subprocess with shell=True
    subprocess.call(command, shell=True)


def load_session(session_blob):
    # SEC104: Insecure deserialization using pickle
    return pickle.loads(session_blob)


def load_yaml_config(config_data):
    # SEC104: Insecure deserialization using yaml.load
    return yaml.load(config_data)


def calculate(expression):
    # SEC105: Unsafe dynamic execution using eval
    return eval(expression)
