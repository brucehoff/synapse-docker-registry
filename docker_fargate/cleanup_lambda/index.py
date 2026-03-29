import boto3
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    """
    Triggered by EventBridge when the ECS service reaches SERVICE_STEADY_STATE,
    meaning the rolling deployment of new tasks (with the rotated credentials) is
    complete.  At that point it is safe to delete the old IAM access key.
    """
    ssm = boto3.client('ssm')
    try:
        old_key_id = ssm.get_parameter(Name=os.environ['SSM_PARAM_NAME'])['Parameter']['Value']
    except ssm.exceptions.ParameterNotFound:
        logger.info("No pending key deletion found, nothing to do")
        return

    iam = boto3.client('iam')
    try:
        iam.delete_access_key(UserName=os.environ['IAM_USERNAME'], AccessKeyId=old_key_id)
        logger.info(f"Deleted old IAM access key {old_key_id}")
    except iam.exceptions.NoSuchEntityException:
        logger.info(f"Key {old_key_id} was already deleted")

    ssm.delete_parameter(Name=os.environ['SSM_PARAM_NAME'])
    logger.info("Cleanup complete")
