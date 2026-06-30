import subprocess
import os

def run_shell(cmd_input: str) -> None:
    # Command Injection (recorded_call)
    subprocess.run(cmd_input, shell=True)

def get_safe_url(user_url: str) -> str:
    # Open Redirect (return_value)
    return user_url

def write_log(filename: str, content: str) -> None:
    # Path Traversal (filesystem_state)
    log_dir = "logs"
    filepath = os.path.join(log_dir, filename)
    with open(filepath, "w") as f:
        f.write(content)
