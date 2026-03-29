import boto3
import json
import logging
import os
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    secret_arn = event['SecretId']
    # When Secrets Manager initiates a rotation, it first creates a new pending version of
    # the secret — a placeholder slot that will hold the new credential once the rotation
    # Lambda writes it. Secrets Manager generates a UUID to identify that new version,
    # and passes it to the Lambda as ClientRequestToken.
    token = event['ClientRequestToken']
    step = event['Step']

    sm = boto3.client('secretsmanager')
    metadata = sm.describe_secret(SecretId=secret_arn)

    if not metadata.get('RotationEnabled'):
        raise ValueError(f"Secret {secret_arn} is not enabled for rotation")

    versions = metadata.get('VersionIdsToStages', {})
    if token not in versions:
        raise ValueError(f"Version {token} has no stage for secret {secret_arn}")
    if 'AWSCURRENT' in versions[token]:
        logger.info(f"Version {token} is already AWSCURRENT, no rotation needed")
        return
    if 'AWSPENDING' not in versions[token]:
        raise ValueError(f"Version {token} is not AWSPENDING for secret {secret_arn}")

    if step == 'createSecret':
        create_secret(sm, secret_arn, token)
    elif step == 'setSecret':
        pass  # IAM access keys are immediately active after creation
    elif step == 'testSecret':
        test_secret(sm, secret_arn, token)
    elif step == 'finishSecret':
        finish_secret(sm, secret_arn, token)
    else:
        raise ValueError(f"Invalid step: {step}")


def create_secret(sm, secret_arn, token):
    # Idempotency: skip if AWSPENDING version already exists
    try:
        sm.get_secret_value(SecretId=secret_arn, VersionId=token, VersionStage='AWSPENDING')
        logger.info("AWSPENDING version already exists, skipping key creation")
        return
    except sm.exceptions.ResourceNotFoundException:
        pass

    iam = boto3.client('iam')
    new_key = iam.create_access_key(UserName=os.environ['IAM_USERNAME'])['AccessKey']
    logger.info(f"Created new IAM access key {new_key['AccessKeyId']}")

    sm.put_secret_value(
        SecretId=secret_arn,
        ClientRequestToken=token,
        SecretString=json.dumps({
            'access_key_id': new_key['AccessKeyId'],
            'secret_access_key': new_key['SecretAccessKey'],
        }),
        VersionStages=['AWSPENDING'],
    )


def test_secret(sm, secret_arn, token):
    secret = json.loads(
        sm.get_secret_value(SecretId=secret_arn, VersionId=token, VersionStage='AWSPENDING')['SecretString']
    )
    # IAM key propagation can take a few seconds; retry up to 5 times
    for attempt in range(5):
        try:
            boto3.client(
                'sts',
                aws_access_key_id=secret['access_key_id'],
                aws_secret_access_key=secret['secret_access_key'],
            ).get_caller_identity()
            logger.info(f"New key {secret['access_key_id']} tested successfully")
            return
        except Exception as e:
            if attempt == 4:
                raise
            logger.warning(f"Test attempt {attempt + 1} failed: {e}, retrying in 5s...")
            time.sleep(5)


def finish_secret(sm, secret_arn, token):
    metadata = sm.describe_secret(SecretId=secret_arn)
    current_version = next(
        (v for v, stages in metadata['VersionIdsToStages'].items() if 'AWSCURRENT' in stages),
        None,
    )
    if current_version == token:
        logger.info("Version is already AWSCURRENT")
        return

    # Capture old key ID before promoting the new version
    old_secret = json.loads(
        sm.get_secret_value(SecretId=secret_arn, VersionStage='AWSCURRENT')['SecretString']
    )
    old_key_id = old_secret['access_key_id']

    # Promote AWSPENDING → AWSCURRENT
    sm.update_secret_version_stage(
        SecretId=secret_arn,
        VersionStage='AWSCURRENT',
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logger.info(f"Promoted version {token} to AWSCURRENT")

    # Stash old key ID in SSM so the cleanup Lambda can delete it after ECS restarts
    boto3.client('ssm').put_parameter(
        Name=os.environ['SSM_PARAM_NAME'],
        Value=old_key_id,
        Type='String',
        Overwrite=True,
    )
    logger.info(f"Stored old key ID {old_key_id} in SSM parameter {os.environ['SSM_PARAM_NAME']}")

    # Force a rolling ECS redeployment so tasks pick up the new secret
    boto3.client('ecs').update_service(
        cluster=os.environ['ECS_CLUSTER_ARN'],
        service=os.environ['ECS_SERVICE_ARN'],
        forceNewDeployment=True,
    )
    logger.info("Triggered ECS force redeployment")
