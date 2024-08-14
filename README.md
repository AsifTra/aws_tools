## AWS IAM Role Chaining Tool

Quickly identify and leverage role chaining opportunities by discovering roles you can assume to gain further access in your AWS environment.

```console
python3 roleChaining.py -p <profile>
```

## AWS IAM keys validator

Testing a large number of key pairs at once

```console
python3 IAM_keys_validator.py -f <filename containing IAM keys in a <ACCESS_KEY>:<SECRET_KEY> format>
python3 IAM_keys_validator.py -ak <ACCESS_KEY> -sk <SECRET_KEY>
```
#TODO:
  * Add support for sts tokens

## Installation
```
git clone https://github.com/AsifTra/aws_iam_tools.git
cd aws_tools/
pip3 install -r requirements.txt
```
