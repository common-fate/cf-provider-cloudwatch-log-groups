import json
import boto3
import click
from mypy_boto3_iam.client import IAMClient
from mypy_boto3_sts.client import STSClient
from pathlib import Path
from os import path

role_base_name = "cf-provider-cloudwatch-log-groups"


@click.command()
@click.option("--account-id", required=True)
@click.option("--role", required=True)
def create_role(account_id, role):
    iam: IAMClient = boto3.client("iam")

    trust_relationship = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            }
        ],
    }
    trust_relationship_str = json.dumps(trust_relationship)

    policy_file = path.join("policies", role + ".json")

    role_name = role_base_name + "-" + role

    with open(policy_file) as f:
        policy_document = f.read()
        res = iam.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=trust_relationship_str
        )

        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="common-fate-inline",
            PolicyDocument=policy_document,
        )
        print(f'created: {res["Role"]["Arn"]}')


@click.command()
@click.option("--role", required=True)
def delete_role(role):
    iam: IAMClient = boto3.client("iam")

    role_name = role_base_name + "-" + role
    iam.delete_role_policy(RoleName=role_name, PolicyName="common-fate-inline")
    iam.delete_role(RoleName=role_name)
    print(f"deleted {role_name}")


@click.group()
def cli():
    pass


cli.add_command(create_role)
cli.add_command(delete_role)

if __name__ == "__main__":
    cli()
