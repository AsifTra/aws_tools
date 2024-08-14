import boto3
import argparse
import sys
from termcolor import cprint

def parse_args():
    parser = argparse.ArgumentParser(
        description="IAM Validator Tool",
        usage="IAM_Validator.py [-h] -f filename | [-ak IAM access key] [-sk IAM secret key]"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", metavar="filename", help="Please specify a file containing IAM keys in the following format <ACCESS_KEY>:<SECRET_KEY>")
    group.add_argument("-ak", "--access_key", metavar="IAM access key", help="Specify an IAM access key")
    parser.add_argument("-sk", "--secret_key", metavar="IAM secret key", help="Specify an IAM secret key")

    args = parser.parse_args()
    if args.access_key or args.secret_key:
        if not (args.access_key and args.secret_key):
            parser.error('Both --access_key and --secret_key must be provided together.')
    return args

def read_keys_from_file(filename):
    key_pairs = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                keys = line.strip().split(':')
                if len(keys) == 2 and validate_access_key(keys[0]) and validate_secret_key(keys[1]):
                    key_pairs.append({
                        "Access Key": keys[0],
                        "Secret Key": keys[1]
                    })
                else:
                    cprint(f" - Invalid key format or validation failed for keys: {line.strip()}", "red")
        return key_pairs
    except FileNotFoundError:
        cprint(f"Error: The file at path '{filename}' was not found.", "red")
    except Exception as e:
        cprint(f"An error occurred while reading the file: {e}", "red")
        return []

def validate_access_key(key):
    return len(key) == 20 and key.startswith("AKIA")

def validate_secret_key(key):
    return len(key) == 40

def create_session(access_key, secret_key, region):
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        sts_client = session.client('sts')
        identity = sts_client.get_caller_identity()
        cprint(f" + Successfully created a session for access key: {access_key} on Account: {identity['Account']}", "green")
        return session
    except Exception as e:
        cprint(f" - Failed to create a session: {e}", "red")
        return None

def main():
    args = parse_args()

    if args.file:
        filename = args.file
        cprint(f"File provided: {filename}\n", "green")
        key_pairs = read_keys_from_file(filename)
        for pair in key_pairs:
            create_session(pair["Access Key"], pair["Secret Key"], region="us-east-1")
    elif args.access_key and args.secret_key:
        access_key = args.access_key
        secret_key = args.secret_key
        cprint(f"Access key: {access_key}, Secret key: {secret_key}", "green")
        create_session(access_key, secret_key, region="us-east-1")
    else:
        cprint("No valid input provided.", "red")
        sys.exit(1)

if __name__ == "__main__":
    main()
