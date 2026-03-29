from aws_cdk import (Stack,
    aws_ec2 as ec2,
    aws_s3 as s3,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_elasticloadbalancingv2 as elbv2,
    aws_route53 as r53,
    aws_apigateway as apigateway,
    aws_iam as iam,
    aws_lambda,
    aws_logs as logs,
    aws_wafv2 as wafv2,
    aws_events as events,
    aws_events_targets as targets,
    CfnOutput,
    Duration,
    SecretValue,
    Tags)

import config as config
import aws_cdk.aws_certificatemanager as cm
import aws_cdk.aws_secretsmanager as sm
from constructs import Construct
from docker_fargate.generate_ssl_cert import cert_gen
from common.vpc_stack import get_region

from aws_cdk.aws_ecr_assets import Platform

ACM_CERT_ARN_CONTEXT = "ACM_CERT_ARN"
IMAGE_PATH_AND_TAG_CONTEXT = "IMAGE_PATH_AND_TAG"
PORT_NUMBER_CONTEXT = "PORT"

# The name of the environment variable that will hold the secrets
SECRETS_MANAGER_ENV_NAME = "SECRETS_MANAGER_SECRETS"
CONTAINER_ENV_NAME = "CONTAINER_ENV"

PRIVATE_KEY_FILE_NAME = "privatekey.pem"
CERTIFICATE_FILE_NAME = "certificate.pem"

BUCKET_NAME = "BUCKET_NAME"

NOTIFICATION_AUTH_SECRET_JSON_KEY="notification_auth"
HTTP_SECRET_SECRET_JSON_KEY="http_secret"

def get_secret(scope: Construct, id: str, name: str) -> str:
    return sm.Secret.from_secret_name_v2(scope, id, name)
    # see also: https://docs.aws.amazon.com/cdk/api/v1/python/aws_cdk.aws_ecs/Secret.html
    # see also: ecs.Secret.from_ssm_parameter(ssm.IParameter(parameter_name=name))

def get_container_env(env: dict) -> dict:
    return env.get(CONTAINER_ENV_NAME, {})

def get_bucket_name(env: dict) -> dict:
    return env.get(BUCKET_NAME)

def get_certificate_arn(env: dict) -> str:
    return env.get(ACM_CERT_ARN_CONTEXT)

def get_docker_image_name(env: dict):
    return env.get(IMAGE_PATH_AND_TAG_CONTEXT)

def get_port(env: dict) -> int:
    return int(env.get(PORT_NUMBER_CONTEXT))


class DockerFargateStack(Stack):

    def __init__(self, scope: Construct, context: str, env: dict, vpc: ec2.Vpc, vpc_endpoint: ec2.InterfaceVpcEndpoint, **kwargs) -> None:
        stack_prefix = f'{env.get(config.STACK_NAME_PREFIX_CONTEXT)}'
        stack_id = f'{stack_prefix}-DockerFargateStack'
        region=get_region(env)
        super().__init__(scope, stack_id, env={"region":region}, **kwargs)

        # set up the bucket
        bucket_name=get_bucket_name(env)
        bucket_arn=f"arn:aws:s3:::{bucket_name}"
        bucket=s3.Bucket.from_bucket_attributes(self, id=bucket_name, bucket_arn=bucket_arn)

        #
        # Docker Registry cannot access the task role provided by
        # ECS.  The work-around is to define an IAM user, give the
        # user bucket access, and pass its key pair to the container
        # as environment variables.
        #

        # create a user
        user = iam.User(self, "DockerRegistryUser")
        # create a key pair, storing both the access key ID and secret in Secrets Manager
        # as a JSON object so they can be rotated together
        access_key = iam.AccessKey(self, "AccessKey", user=user)
        secret_stored_name = f'{env.get(config.STACK_NAME_PREFIX_CONTEXT)}-DockerFargateStack/{context}/access_key'
        access_key_secret = sm.Secret(self, secret_stored_name,
            secret_object_value={
                "access_key_id": SecretValue.unsafe_plain_text(access_key.access_key_id),
                "secret_access_key": access_key.secret_access_key,
            }
        )

        # give the user S3 access
        bucket.grant_read_write(user)

        # create an APIGateway that logs registry events to Cloudwatch Logs
        api_url = create_logging_apigateway(self, stack_prefix, stack_id, vpc_endpoint)

        cluster = ecs.Cluster(
            self,
            f'{stack_id}-Cluster',
            vpc=vpc,
            container_insights=True)

        secret_name = f'{env.get(config.STACK_NAME_PREFIX_CONTEXT)}-DockerFargateStack/{context}/ecs'
        sm_secret = get_secret(self, secret_name, secret_name)
        secrets = {
            NOTIFICATION_AUTH_SECRET_JSON_KEY:
                ecs.Secret.from_secrets_manager(sm_secret, NOTIFICATION_AUTH_SECRET_JSON_KEY),
            HTTP_SECRET_SECRET_JSON_KEY:
                ecs.Secret.from_secrets_manager(sm_secret, HTTP_SECRET_SECRET_JSON_KEY),
            "AWS_ACCESS_KEY_ID": ecs.Secret.from_secrets_manager(access_key_secret, "access_key_id"),
            "AWS_SECRET_ACCESS_KEY": ecs.Secret.from_secrets_manager(access_key_secret, "secret_access_key"),
        }

        env_vars = get_container_env(env)
        env_vars[BUCKET_NAME]=bucket_name
        env_vars["api_gateway_url"]=api_url

        # Build the container image for the registry
        # Need self-signed certificates to add to the image
        key_and_cert = cert_gen()
        # write the private key and self-signed-cert to disk for Docker to use
        with open(PRIVATE_KEY_FILE_NAME, "wt") as f:
          f.write(key_and_cert["private_key"])
        with open(CERTIFICATE_FILE_NAME, "wt") as f:
          f.write(key_and_cert["certificate"])
        # Now build the image, using the self-signed cert and key
        image = ecs.ContainerImage.from_asset(
            directory=".",
            platform=Platform.LINUX_AMD64, # important to include when building locally, for testing
            build_args={"stack":context} # 'dev' or 'prod'
        )

        # default ECS execution policy plus Guardduty access
        execution_role = iam.Role(
            self,
            "ExecutionRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonECSTaskExecutionRolePolicy"
                ),
            ],
        )
        execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=["*"],
                effect=iam.Effect.ALLOW,
            )
        )

        task_image_options = ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                   image=image,
                   environment=env_vars,
                   secrets = secrets,
                   container_port = get_port(env),
                   execution_role=execution_role)

        cert = cm.Certificate.from_certificate_arn(
            self,
            f'{stack_id}-Certificate',
            get_certificate_arn(env),
        )

        load_balanced_fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            f'{stack_prefix}-Service',
            cluster=cluster,            # Required
            cpu=2048,                   # Default is 256
            desired_count=2,            # Number of copies of the 'task' (i.e. the app') running behind the ALB
            circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True), # Enable rollback on deployment failure
            task_image_options=task_image_options,
            memory_limit_mib=4096,      # Default is 512
            public_load_balancer=True,  # Default is False
            redirect_http=True,
            # TLS:
            target_protocol=elbv2.ApplicationProtocol.HTTPS,
            certificate=cert,
            protocol=elbv2.ApplicationProtocol.HTTPS,
            ssl_policy=elbv2.SslPolicy.FORWARD_SECRECY_TLS12_RES # Strong forward secrecy ciphers and TLS1.2 only.
        )

        # Add access logging
        log_bucket = s3.Bucket(self,
          f'{stack_prefix}-access-logs.sagebase.org',
          block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
          encryption=s3.BucketEncryption.S3_MANAGED,
          enforce_ssl=True,
          minimum_tls_version=1.2,
          lifecycle_rules=[s3.LifecycleRule(
            expiration=Duration.days(90) # delete logs after 90 days
          )]
        )
        load_balanced_fargate_service.load_balancer.log_access_logs(log_bucket)

        # Add a WebACL
        web_acl = wafv2.CfnWebACL(
            self,
            f'{stack_prefix}-web-acl',
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            scope="REGIONAL",
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name=f'{stack_prefix}-waf',
                sampled_requests_enabled=False
                ),
            name=f'{stack_prefix}-web-acl',
            # From https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
            # The core rule set (CRS) rule group contains rules that are generally applicable
            # to web applications. This provides protection against exploitation of a wide range of
            # vulnerabilities, including some of the high risk and commonly occurring vulnerabilities
            # described in OWASP publications such as OWASP Top 10. Consider using this rule group for
            # any AWS WAF use case.
            rules=[wafv2.CfnWebACL.RuleProperty(
              name="AWS-AWSManagedRulesCommonRuleSet",
              priority=0,
              statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                  vendor_name="AWS", name="AWSManagedRulesCommonRuleSet",
                  rule_action_overrides=[
                    # The following rules need to be disabled, since they break the Docker registry
                    wafv2.CfnWebACL.RuleActionOverrideProperty(
                      # blocks request bodies > 8KB
                      name="SizeRestrictions_BODY",
                      action_to_use=wafv2.CfnWebACL.RuleActionProperty(allow={})
                    ),
                    wafv2.CfnWebACL.RuleActionOverrideProperty(
                      # Inspects for the presence of Local File Inclusion (LFI) exploits in the query arguments.
                      name="GenericLFI_QUERYARGUMENTS",
                      action_to_use=wafv2.CfnWebACL.RuleActionProperty(allow={})
                    ),
                  ]
                )
              ),
              override_action=wafv2.CfnWebACL.OverrideActionProperty(count={}),
              visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name=f'{stack_prefix}-AWSManagedRulesCommonRuleSet',
              ),
            )]
        )
        wafv2.CfnWebACLAssociation(self, f'{stack_prefix}-CfnWebACLAssociation',
         resource_arn=load_balanced_fargate_service.load_balancer.load_balancer_arn,
         web_acl_arn=web_acl.attr_arn)

        scalable_target = load_balanced_fargate_service.service.auto_scale_task_count(
           min_capacity=2, # Minimum capacity to scale to. Default: 1
           max_capacity=4 # Maximum capacity to scale to.
        )

        # Add more capacity when CPU utilization reaches 50%
        scalable_target.scale_on_cpu_utilization("CpuScaling",
            target_utilization_percent=50
        )

        # Add more capacity when memory utilization reaches 50%
        scalable_target.scale_on_memory_utilization("MemoryScaling",
            target_utilization_percent=50
        )

        # ── Credential rotation ──────────────────────────────────────────────
        # SSM parameter used to hand the old key ID from the rotation Lambda to
        # the cleanup Lambda (which runs only after ECS confirms the new tasks
        # are healthy, making it safe to delete the old key).
        ssm_param_name = f'/{stack_prefix}/pending-key-deletion'
        ssm_param_arn = f"arn:aws:ssm:{region}:{self.account}:parameter{ssm_param_name}"

        rotation_lambda = aws_lambda.Function(self, "RotationLambda",
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=aws_lambda.Code.from_asset("docker_fargate/rotation_lambda"),
            timeout=Duration.minutes(5),
            environment={
                "IAM_USERNAME": user.user_name,
                "SSM_PARAM_NAME": ssm_param_name,
                "ECS_CLUSTER_ARN": cluster.cluster_arn,
                "ECS_SERVICE_ARN": load_balanced_fargate_service.service.service_arn,
            },
        )

        # Secrets Manager needs read + write on the secret
        access_key_secret.grant_read(rotation_lambda)
        rotation_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["secretsmanager:PutSecretValue", "secretsmanager:UpdateSecretVersionStage"],
            resources=[access_key_secret.secret_arn],
        ))
        rotation_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["iam:CreateAccessKey"],
            resources=[user.user_arn],
        ))
        rotation_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["ecs:UpdateService"],
            resources=[load_balanced_fargate_service.service.service_arn],
        ))
        rotation_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["ssm:PutParameter"],
            resources=[ssm_param_arn],
        ))

        # Wire up 90-day automatic rotation; this also grants Secrets Manager
        # permission to invoke the Lambda
        access_key_secret.add_rotation_schedule(
            "AccessKeyRotationSchedule",
            rotation_lambda=rotation_lambda,
            automatically_after=Duration.days(90),
        )

        cleanup_lambda = aws_lambda.Function(self, "CleanupLambda",
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=aws_lambda.Code.from_asset("docker_fargate/cleanup_lambda"),
            timeout=Duration.minutes(1),
            environment={
                "IAM_USERNAME": user.user_name,
                "SSM_PARAM_NAME": ssm_param_name,
            },
        )
        cleanup_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["iam:DeleteAccessKey"],
            resources=[user.user_arn],
        ))
        cleanup_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["ssm:GetParameter", "ssm:DeleteParameter"],
            resources=[ssm_param_arn],
        ))

        # Trigger the cleanup Lambda once ECS reports the service is at steady
        # state (all new tasks healthy), meaning the old credentials are no
        # longer in use and it is safe to delete the old IAM key
        events.Rule(self, "ECSDeploymentCompleteRule",
            event_pattern=events.EventPattern(
                source=["aws.ecs"],
                detail_type=["ECS Service Action"],
                resources=[load_balanced_fargate_service.service.service_arn],
                detail={"eventName": ["SERVICE_STEADY_STATE"]},
            ),
            targets=[targets.LambdaFunction(cleanup_lambda)],
        )
        # ── End credential rotation ──────────────────────────────────────────

        # Tag all resources in this Stack's scope with context tags
        for key, value in env.get(config.TAGS_CONTEXT).items():
            Tags.of(scope).add(key, value)

        # Export load balancer name
        lb_dns_name = load_balanced_fargate_service.load_balancer.load_balancer_dns_name
        lb_dns_export_name = f'{stack_id}-LoadBalancerDNS'
        CfnOutput(self, 'LoadBalancerDNS', value=lb_dns_name, export_name=lb_dns_export_name)

#
# Create an API Gateway that the registry can call by its URL
# to log events to CloudWatch Logs
#
def create_logging_apigateway(self, stack_prefix, stack_id, vpc_endpoint):
    # Create a policy to allow invoking the API Gateway
    # Note that the Gateway is only accessible within the VPC
    gateway_resource_policy=iam.PolicyDocument(
        statements=[
        iam.PolicyStatement(
            actions =['execute-api:Invoke'],
            principals = [iam.StarPrincipal()],
            resources = ['*']
        )]
    )

    # Create the log group & stream to receive the event logs
    log_group_name = f"{stack_id}-execution-logs"
    log_group = logs.LogGroup(self, log_group_name, retention=logs.RetentionDays.SIX_MONTHS)
    log_stream = logs.LogStream(self, f"{stack_id}-log-stream", log_group=log_group)
    CfnOutput(self, 'LogGroup', value=log_group.log_group_name, export_name=log_group_name)

    # Define the code for the lambda, in-line
    # We simply log the event to Cloudwatch Logs
    lambda_code = f"""
import boto3, json, time
client = boto3.client('logs')
def handler(event, context):
    headers = event.get('multiValueHeaders',{{}})
    body = json.loads(event.get('body',{{}}))
    content_to_log={{'headers':headers,'body':body}}
    message = json.dumps(content_to_log)
    milliseconds = int(round(time.time() * 1000))
    client.put_log_events(
        logGroupName='{log_group.log_group_name}',
        logStreamName='{log_stream.log_stream_name}',
        logEvents=[{{'timestamp':milliseconds,'message':message}}])
    return {{'statusCode': 204}}
"""

    # Define the lambda function that runs the code
    lambda_function = aws_lambda.Function(self, "Function",
        runtime=aws_lambda.Runtime.PYTHON_3_13,
        handler="index.handler",
        code=aws_lambda.InlineCode(lambda_code)
    )

    # Create a policy to allow the lambda to put logs to Cloudwatch Logs
    lambda_function.add_to_role_policy(
        iam.PolicyStatement(
            actions=["logs:*"],
            resources=[log_group.log_group_arn]
        )
    )

    # Create the Lambda-integrated API Gateway
    api = apigateway.LambdaRestApi(self,
        f'{stack_prefix}-events-collector',
        handler=lambda_function,
        endpoint_configuration=apigateway.EndpointConfiguration(
            types=[apigateway.EndpointType.PRIVATE],
            vpc_endpoints=[vpc_endpoint]),
        policy=gateway_resource_policy,
        deploy_options=apigateway.StageOptions(
            logging_level=apigateway.MethodLoggingLevel.ERROR
        )
    )
    # the URL for this gateway is api.url

    return api.url
