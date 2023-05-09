from dataclasses import dataclass
import typing


@dataclass
class ARN:
    arn: str
    partition: str
    service: str
    region: str
    account: str
    resource: str
    resource_type: typing.Optional[str]


def parse_arn(arn) -> ARN:
    # http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
    elements = arn.split(":", 5)
    result = ARN(
        arn=elements[0],
        partition=elements[1],
        service=elements[2],
        region=elements[3],
        account=elements[4],
        resource=elements[5],
        resource_type=None,
    )
    if ":" in result.resource:
        result.resource_type, result.resource = result.resource.split(":", 1)
    return result
