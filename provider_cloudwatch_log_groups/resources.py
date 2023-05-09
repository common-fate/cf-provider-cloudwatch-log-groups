from dataclasses import dataclass
import typing
from provider import resources, tasks
from mypy_boto3_logs.client import CloudWatchLogsClient

from .parse_arn import parse_arn
from .provider import Provider, get_boto3_session, LogGroup


@resources.loader
def log_groups(p: Provider):
    cloudwatch_regions = p.cloudwatch_regions.get().split(",")
    for region in cloudwatch_regions:
        tasks.call(ListLogGroups(region=region))


class ListLogGroups(tasks.Task):
    region: str
    page: typing.Optional[str] = None

    def run(self, p: Provider):
        logs: CloudWatchLogsClient = get_boto3_session(
            p.cloudwatch_read_role_arn.get()
        ).client("logs", region_name=self.region)

        if self.page is None:
            res = logs.describe_log_groups()
        else:
            res = logs.describe_log_groups(nextToken=self.page)

        for log_group in res["logGroups"]:
            arn = parse_arn(log_group["arn"])
            resources.register(
                LogGroup(
                    id=log_group["arn"],
                    account=arn.account,
                    region=self.region,
                    creation_time=log_group["creationTime"],
                    name=log_group["logGroupName"],
                )
            )

        next_token = res.get("nextToken", None)
        if next_token is not None and next_token != "":
            self.page = next_token
            tasks.call(self)
