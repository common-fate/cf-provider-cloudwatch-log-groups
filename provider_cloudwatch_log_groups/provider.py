from dataclasses import dataclass
import json
import typing
import provider
from provider import (
    target,
    access,
    resources,
    rpc,
)
import boto3
import botocore.session
from mypy_boto3_identitystore.client import IdentityStoreClient
from mypy_boto3_sso_admin.client import SSOAdminClient
from botocore.credentials import (
    AssumeRoleCredentialFetcher,
    DeferredRefreshableCredentials,
)
from pydantic import BaseModel
from retrying import retry
import structlog
from .parse_arn import parse_arn, ARN
from urllib.parse import quote_plus

log = structlog.get_logger()


class LogGroup(resources.Resource):
    creation_time: str
    account: str
    region: str


@dataclass
class SSOUser:
    UserId: str
    UserName: str


class Provider(provider.Provider):
    cloudwatch_regions = provider.String(
        description="comma-separated regions to query for CloudWatch log groups in"
    )
    cloudwatch_read_role_arn = provider.String(
        description="The ARN of the AWS IAM Role with permission to read CloudWatch log groups"
    )
    sso_instance_arn = provider.String(description="the AWS SSO instance ARN")
    sso_identity_store_id = provider.String(description="the AWS SSO identity store ID")
    sso_region = provider.String(description="the AWS SSO instance region")
    sso_role_arn = provider.String(
        description="The ARN of the AWS IAM Role with permission to create AWS SSO Permission Sets"
    )

    def setup(self):
        self.org_client = get_boto3_session(role_arn=self.sso_role_arn.get()).client(
            "organizations", region_name=self.sso_region.get()
        )
        self.sso_client: SSOAdminClient = get_boto3_session(
            role_arn=self.sso_role_arn.get()
        ).client("sso-admin", region_name=self.sso_region.get())

        self.idstore_client: IdentityStoreClient = get_boto3_session(
            role_arn=self.sso_role_arn.get()
        ).client("identitystore", region_name=self.sso_region.get())

    def get_user(self, subject) -> SSOUser:
        # try get user first by filtering username
        out = self.idstore_client.list_users(
            IdentityStoreId=self.sso_identity_store_id.get(),
            MaxResults=1,
            Filters=[{"AttributePath": "UserName", "AttributeValue": subject}],
        )

        if len(out["Users"]) != 0:
            return SSOUser(
                UserId=out["Users"][0]["UserId"], UserName=out["Users"][0]["UserName"]
            )

        # if we didnt find the user via the username
        # list all users and find a match in the subject email

        has_more = True
        next_token = ""

        while has_more:
            users = self.idstore_client.list_users(
                IdentityStoreId=self.sso_identity_store_id.get(),
                NextToken=next_token,
            )

            for user in users["Users"]:
                for email in user["Emails"]:
                    if email["Value"] == subject:
                        return SSOUser(UserId=user["UserId"], UserName=user["UserName"])

            next_token = users["NextToken"]
            has_more = next_token != ""

        raise Exception(f"user {subject} does not exist in AWS SSO directory")


@access.target(kind="LogGroup")
class LogGroupTarget:
    log_group = target.Resource(
        title="Log Group",
        resource=LogGroup,
        description="the ARN of the CloudWatch log group to grant read access to",
    )


class NotReadyError(Exception):
    pass


def retry_on_notready(exc):
    return isinstance(exc, NotReadyError)


# retry for 2 minutes
@retry(stop_max_delay=60000 * 2, retry_on_exception=retry_on_notready)
def check_account_assignment_status(p: Provider, request_id):
    acc_assignment = p.sso_client.describe_account_assignment_creation_status(
        InstanceArn=p.sso_instance_arn.get(),
        AccountAssignmentCreationRequestId=request_id,
    )

    if acc_assignment["AccountAssignmentCreationStatus"]["Status"] == "SUCCEEDED":
        return acc_assignment
    else:
        if acc_assignment["AccountAssignmentCreationStatus"]["Status"] == "FAILED":
            return acc_assignment

        # trigger a retry
        raise NotReadyError


@retry(stop_max_delay=60000 * 2, retry_on_exception=retry_on_notready)
def check_account_deletion_status(p: Provider, request_id):
    acc_assignment = p.sso_client.describe_account_assignment_deletion_status(
        InstanceArn=p.sso_instance_arn.get(),
        AccountAssignmentDeletionRequestId=request_id,
    )

    if acc_assignment["AccountAssignmentDeletionStatus"]["Status"] == "SUCCEEDED":
        return acc_assignment
    else:
        if acc_assignment["AccountAssignmentDeletionStatus"]["Status"] == "FAILED":
            return acc_assignment

        # trigger a retry
        raise NotReadyError


class State(BaseModel):
    permission_set_arn: str
    sso_user_id: str  # in future, this will be moved to a resource-based lookup


@access.grant()
def grant(
    p: Provider, subject: str, target: LogGroupTarget, request: rpc.AccessRequest
) -> access.GrantResult:
    log_group_arn = parse_arn(target.log_group)

    # find the user id from the email address subject
    user = p.get_user(subject)

    # create the permission set
    ps = p.sso_client.create_permission_set(
        Name=request.id,
        Description=f"Common Fate Access Request {request.id}",
        InstanceArn=p.sso_instance_arn.get(),
    )

    log.info("created permission set", result=ps)

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:GetLogDelivery",
                    "logs:GetLogEvents",
                    "logs:GetLogGroupFields",
                    "logs:GetLogRecord",
                    "logs:GetQueryResults",
                    "logs:StartQuery",
                    "logs:StopQuery",
                    "logs:TestMetricFilter",
                    "logs:FilterLogEvents",
                    "logs:DescribeSubscriptionFilters",
                    "logs:ListTagsLogGroup",
                    "logs:GetDataProtectionPolicy",
                ],
                "Resource": [f"{target.log_group}:*"],
            },
            # These permissions are not required to view log group data,
            # but allowing users to view metadata about logs results in
            # a far better console user experience.
            #
            # This allows for users to view metadata about log groups
            # other than the one they have requested, and to view
            # metric data. This provider does not consider these to be
            # sensitive and in fact may be of assistance to a user who
            # is using this provider to get access to logs when responding
            # to an incident.
            #
            # In future we will introduce a configuration option allowing
            # this policy statement to be disabled, so that metadata
            # about other log groups and metrics cannot be viewed.
            {
                "Effect": "Allow",
                "Action": [
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:DescribeMetricFilters",
                    "cloudwatch:GetMetricData",
                ],
                "Resource": ["*"],
            },
        ],
    }

    log.info("provisioning inline policy to role", policy=inline_policy)

    inline_policy_result = p.sso_client.put_inline_policy_to_permission_set(
        InstanceArn=p.sso_instance_arn.get(),
        PermissionSetArn=ps["PermissionSet"]["PermissionSetArn"],
        InlinePolicy=json.dumps(inline_policy),
    )

    log.info("attached inline policy to permission set", result=inline_policy_result)

    # call aws to create the account assignment to the permissions set
    acc_assignment = p.sso_client.create_account_assignment(
        InstanceArn=p.sso_instance_arn.get(),
        PermissionSetArn=ps["PermissionSet"]["PermissionSetArn"],
        PrincipalType="USER",
        PrincipalId=user.UserId,
        TargetId=log_group_arn.account,
        TargetType="AWS_ACCOUNT",
    )

    log.info("created account assignment", result=acc_assignment)

    # poll the assignment api to see if the assignment was successful
    res = check_account_assignment_status(
        p, acc_assignment["AccountAssignmentCreationStatus"]["RequestId"]
    )

    log.info("checked account assignment", result=res)

    # log the success or failure of the grant
    if res["AccountAssignmentCreationStatus"]["Status"] != "SUCCEEDED":
        raise Exception(
            f'Error creating account assigment: {res["AccountAssignmentCreationStatus"]["FailureReason"]}'
        )

    state = State(
        sso_user_id=user.UserId,
        permission_set_arn=ps["PermissionSet"]["PermissionSetArn"],
    )

    url = log_group_url(log_group_arn=log_group_arn)

    log.info(f"url: {url}")

    access_instructions = f"""First, log in to your [AWS SSO URL](https://{p.sso_identity_store_id.get()}.awsapps.com/start).

Account ID: {log_group_arn.account}

Role: {request.id}

Once logged in, use the link below to view logs for the log group:

[{target.log_group}]({url})
"""

    return access.GrantResult(state=state, access_instructions=access_instructions)


def log_group_url(log_group_arn: ARN) -> str:
    return f"https://{log_group_arn.region}.console.aws.amazon.com/cloudwatch/home?region={log_group_arn.region}#logsV2:log-groups/log-group/{quote_plus(log_group_arn.resource)}"


@access.revoke()
def revoke(p: Provider, subject: str, target: LogGroupTarget, state: State):
    log_group_arn = parse_arn(target.log_group)
    instance_arn = p.sso_instance_arn.get()
    log.info(
        "deleting account assignment",
        instance_arn=instance_arn,
        state=state,
    )
    # delete the account assignment
    acc_assignment = p.sso_client.delete_account_assignment(
        InstanceArn=instance_arn,
        PermissionSetArn=state.permission_set_arn,
        PrincipalType="USER",
        PrincipalId=state.sso_user_id,
        TargetId=log_group_arn.account,
        TargetType="AWS_ACCOUNT",
    )

    # poll the assignment api to see if the deletion was successful
    res = check_account_deletion_status(
        p, acc_assignment["AccountAssignmentDeletionStatus"]["RequestId"]
    )

    if res["AccountAssignmentDeletionStatus"]["Status"] != "SUCCEEDED":
        raise Exception(
            f'Error deleting account assigment: {res["AccountAssignmentDeletionStatus"]["FailureReason"]}'
        )

    # delete the permission set that we provisioned
    p.sso_client.delete_permission_set(
        InstanceArn=instance_arn, PermissionSetArn=state.permission_set_arn
    )


def next_token(page: typing.Optional[str]) -> dict:
    """
    returns a type-safe next token for use with boto3
    """
    if page is None:
        return {}  # type: ignore
    return {"NextToken": page}


def get_boto3_session(role_arn=None):
    """
    Returns a boto3 session which assumes the role specified with `role_arn`.
    """
    session = boto3.Session()
    if not role_arn:
        return session

    fetcher = AssumeRoleCredentialFetcher(
        client_creator=_get_client_creator(session),
        source_credentials=session.get_credentials(),
        role_arn=role_arn,
    )
    botocore_session = botocore.session.Session()
    botocore_session._credentials = DeferredRefreshableCredentials(
        method="assume-role", refresh_using=fetcher.fetch_credentials
    )

    return boto3.Session(botocore_session=botocore_session)


def _get_client_creator(session):
    def client_creator(service_name, **kwargs):
        return session.client(service_name, **kwargs)

    return client_creator
