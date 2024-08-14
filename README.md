## AWS IAM Role Chaining Tool

Quickly identify and leverage role chaining opportunities by discovering roles you can assume to gain further access to your AWS environment.

```console
python3 roleChaining.py -p <profile>
```

## AWS IAM keys validator

Testing IAM key pairs at mass

```console
python3 IAM_keys_validator.py -f <filename in a <ACCESS_KEY>:<SECRET_KEY> format>
python3 IAM_keys_validator.py -ak <ACCESS_KEY> -sk <SECRET_KEY>
```
TODO:
  * Add support for sts tokens if the user already has a session

## Installation
```
git clone https://github.com/AsifTra/aws_iam_tools.git
cd aws_tools/
pip3 install -r requirements.txt
```
