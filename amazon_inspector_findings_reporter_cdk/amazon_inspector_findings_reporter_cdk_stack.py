import json

# Core constructs
from aws_cdk import Stack
from constructs import Construct

# AWS services
from aws_cdk import (
    aws_s3 as s3,
    aws_sns as sns,
    aws_lambda as _lambda,
    aws_iam as iam,
    aws_s3_notifications as s3n,
    aws_kms as kms,
    aws_events as events,
    aws_events_targets as targets,
    aws_sns_subscriptions as subscriptions,
    aws_glue as glue,
)


class InspectorFindingsReportStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        bucket_name = self.node.try_get_context("bucketName")
        if not bucket_name:
            bucket_name = "inspector-report-bucket"
        # Create S3 bucket to store the report
        inspector_report_bucket = s3.Bucket(
            self,
            bucket_name,
            bucket_name=f"{bucket_name}.{self.region}.{self.account}",
            # encryption=s3.BucketEncryption.S3_MANAGED, # Gives Access Denied error because of Control Tower - GuradRail policy for the Audit account
            # enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        )
        FINANCE_PROD = self.node.try_get_context("financeProdAccount")
        FINANCE_NONPROD = self.node.try_get_context("financeNonProdAccount")
        # Add Finance accounts to the bucket policy
        inspector_report_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:GetObject*", "s3:ListBucket*"],
                resources=[
                    inspector_report_bucket.arn_for_objects("*"),
                    inspector_report_bucket.bucket_arn,
                ],
                principals=[
                    iam.AccountPrincipal(FINANCE_PROD),
                    iam.AccountPrincipal(FINANCE_NONPROD),
                ],
            ),
        )

        # Define the service principal for Amazon Inspector2
        inspector_principal = iam.ServicePrincipal("inspector2.amazonaws.com")

        # Create a policy statement that allows 's3:PutObject' action from Inspector v2
        bucket_policy_statement = iam.PolicyStatement(
            actions=[
                "s3:PutObject",
                "s3:PutObjectAcl",
                "s3:AbortMultipartUpload",
            ],
            resources=[
                inspector_report_bucket.bucket_arn + "/*"
            ],  # Grant access to the objects in the bucket
            principals=[
                inspector_principal
            ],  # Grant access to the Amazon Inspector service
        )

        # Attach the policy statement to the bucket
        inspector_report_bucket.add_to_resource_policy(bucket_policy_statement)

        # Get the account ID of the current account
        account_root_principal = iam.AccountRootPrincipal()

        # Create a KMS key used for Inspector report encryption
        inspector_report_cmk = kms.Key(
            self,
            "InspectorReportCmk",
            policy=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=["kms:*"],
                        principals=[iam.AccountRootPrincipal()],
                        resources=["*"],
                    )
                ]
            ),
        )

        # Define the Amazon Inspector service principal
        inspector_principal = iam.ServicePrincipal("inspector2.amazonaws.com")

        # Grant Amazon Inspector permissions to use the key
        inspector_report_cmk.grant_encrypt_decrypt(inspector_principal)

        # Create an IAM role for Lambda
        lambda_role = iam.Role(
            self,
            "InspectorLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonInspector2FullAccess"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSNSFullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSESFullAccess"),
            ],
        )

        inspector_report_cmk.grant_encrypt_decrypt(lambda_role)

        # Environment Variables initializations:
        TOPIC_ARN = ""
        SES_SENDER = ""
        SES_RECIPIENTS = ""

        notification_system = self.node.try_get_context("notificationSystem")
        if notification_system == "SES":
            SES_SENDER = self.node.try_get_context("ses_sender")
            print(SES_SENDER)
            SES_RECIPIENTS = self.node.try_get_context("ses_receivers")
            print(SES_RECIPIENTS)
        elif notification_system == "SNS":
            subscribed_emails = self.node.try_get_context("sns_subscribed_emails")
            # Create SNS topic to send the report
            inspector_report_topic = sns.Topic(self, "InspectorReportTopic")
            TOPIC_ARN = inspector_report_topic.topic_arn
            # Create SNS subscriptions to send the report
            for subscribed_email in subscribed_emails:
                inspector_report_topic.add_subscription(
                    subscriptions.EmailSubscription(subscribed_email)
                )
        else:
            print("please specify proper notification_system in cdk.json")

        # Create Lambda function to send the report
        OUTPUT_FORMAT = self.node.try_get_context("outputFormat")
        if not OUTPUT_FORMAT:
            OUTPUT_FORMAT = "CSV"
        inspector_report_generator_lambda = _lambda.Function(
            self,
            "InspectorReportFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="report_generator.lambda_handler",
            code=_lambda.Code.from_asset("./lambda/report_generator/"),
            environment={
                "BUCKET_NAME": inspector_report_bucket.bucket_name,
                "KMS_KEY": inspector_report_cmk.key_arn,
                "OUTPUT_FORMAT": OUTPUT_FORMAT,
            },
            role=lambda_role,
        )

        report_sender_lambda = _lambda.Function(
            self,
            "ReportSenderFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="report_sender.lambda_handler",
            code=_lambda.Code.from_asset("./lambda/report_sender/"),
            environment={
                "TOPIC_ARN": TOPIC_ARN,
                "SES_SENDER": SES_SENDER,
                "SES_RECIPIENTS": json.dumps(SES_RECIPIENTS),
            },
            role=lambda_role,
        )

        # Grant the Lambda function permissions to the bucket and the topic
        inspector_report_bucket.grant_read_write(inspector_report_generator_lambda)
        inspector_report_bucket.grant_put(inspector_report_generator_lambda)

        # Add an S3 event notification to trigger the Lambda function
        inspector_report_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED, s3n.LambdaDestination(report_sender_lambda)
        )
        report_frequency = self.node.try_get_context("reportFrequency")
        if not report_frequency:
            report_frequency = "DAILY"

        schedule_cron = "cron(05 0 * * ? *)"  # default value = daily
        if report_frequency == "WEEKLY":
            schedule_cron = "cron(05 0 ? * MON *)"
        elif report_frequency == "MONTHLY":
            schedule_cron = "cron(05 0 1 * ? *)"
        # create an event bridge rule to trigger the lambda every 24 hours
        rule = events.Rule(
            self, "Rules", schedule=events.Schedule.expression(schedule_cron)
        )

        # Add the Lambda function as a target
        rule.add_target(targets.LambdaFunction(inspector_report_generator_lambda))

        # Create Glue Database
        glue_db = glue.CfnDatabase(
            self,
            "InspectorFindingsDatabase",
            catalog_id=self.account,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                name="inspector_findings",
                description="Database to store Amazon Inspector findings",
            ),
        )

        # Create Glue Table
        # Response from the Inspector API is in CSV format and found here https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/inspector2/client/list_findings.html
        # Data is partitioned by year, month, and day and stored in the S3 bucket
        # With these columns
        # AWS Account Id,Severity,Fix Available,Finding Type,Title,Description,Finding ARN,First Seen,Last Seen,Last Updated,Resource ID,Container Image Tags,Region,Platform,Resource Tags,Affected Packages,Package Installed Version,Fixed in Version,Package Remediation,File Path,Network Paths,Age (Days),Remediation,Inspector Score,Inspector Score Vector,Status,Vulnerability Id,Vendor,Vendor Severity,Vendor Advisory,Vendor Advisory Published,NVD CVSS3 Score,NVD CVSS3 Vector,NVD CVSS2 Score,NVD CVSS2 Vector,Vendor CVSS3 Score,Vendor CVSS3 Vector,Vendor CVSS2 Score,Vendor CVSS2 Vector,Resource Type,Ami,Resource Public Ipv4,Resource Private Ipv4,Resource Ipv6,Resource Vpc,Port Range,Epss Score,Exploit Available,Last Exploited At,Lambda Layers,Lambda Package Type,Lambda Last Updated At,Reference Urls,Detector Name,Package Manager
        # aws_account_id string,severity string,fix_available string,finding_type string,title string,description string,finding_arn string,first_seen date,last_seen date,last_updated date,resource_id string,container_image_tags string,region string,platform string,resource_tags string,affected_packages string,package_installed_version string,fixed_in_version string,package_remediation string,file_path string,network_paths string,age_days string,remediation string,inspector_score string,inspector_score_vector string,status string,vulnerability_id string,vendor string,vendor_severity string,vendor_advisory string,vendor_advisory_published string,nvd_cvss3_score string,nvd_cvss3_vector string,nvd_cvss2_score string,nvd_cvss2_vector string,vendor_cvss3_score string,vendor_cvss3_vector string,vendor_cvss2_score string,vendor_cvss2_vector string,resource_type string,ami string,resource_public_ipv4 string,resource_private_ipv4 string,resource_ipv6 string,resource_vpc string,port_range string,epss_score string,exploit_available string,last_exploited_at string,lambda_layers string,lambda_package_type string,lambda_last_updated_at string,reference_urls string,detector_name string,package_manager string
        columns = [
            glue.CfnTable.ColumnProperty(name="aws_account_id", type="string"),
            glue.CfnTable.ColumnProperty(name="severity", type="string"),
            glue.CfnTable.ColumnProperty(name="fix_available", type="string"),
            glue.CfnTable.ColumnProperty(name="finding_type", type="string"),
            glue.CfnTable.ColumnProperty(name="title", type="string"),
            glue.CfnTable.ColumnProperty(name="description", type="string"),
            glue.CfnTable.ColumnProperty(name="finding_arn", type="string"),
            glue.CfnTable.ColumnProperty(name="first_seen", type="string"),
            glue.CfnTable.ColumnProperty(name="last_seen", type="string"),
            glue.CfnTable.ColumnProperty(name="last_updated", type="string"),
            glue.CfnTable.ColumnProperty(name="resource_id", type="string"),
            glue.CfnTable.ColumnProperty(name="container_image_tags", type="string"),
            glue.CfnTable.ColumnProperty(name="region", type="string"),
            glue.CfnTable.ColumnProperty(name="platform", type="string"),
            glue.CfnTable.ColumnProperty(name="resource_tags", type="string"),
            glue.CfnTable.ColumnProperty(name="affected_packages", type="string"),
            glue.CfnTable.ColumnProperty(name="package_installed_version", type="string"),
            glue.CfnTable.ColumnProperty(name="fixed_in_version", type="string"),
            glue.CfnTable.ColumnProperty(name="package_remediation", type="string"),
            glue.CfnTable.ColumnProperty(name="file_path", type="string"),
            glue.CfnTable.ColumnProperty(name="network_paths", type="string"),
            glue.CfnTable.ColumnProperty(name="age_days", type="string"),
            glue.CfnTable.ColumnProperty(name="remediation", type="string"),
            glue.CfnTable.ColumnProperty(name="inspector_score", type="string"),
            glue.CfnTable.ColumnProperty(name="inspector_score_vector", type="string"),
            glue.CfnTable.ColumnProperty(name="status", type="string"),
            glue.CfnTable.ColumnProperty(name="vulnerability_id", type="string"),
            glue.CfnTable.ColumnProperty(name="vendor", type="string"),
            glue.CfnTable.ColumnProperty(name="vendor_severity", type="string"),
            glue.CfnTable.ColumnProperty(name="vendor_advisory", type="string"),
            glue.CfnTable.ColumnProperty(name="vendor_advisory_published", type="string"),
            glue.CfnTable.ColumnProperty(name="nvd_cvss3_score", type="string"),
            glue.CfnTable.ColumnProperty(name="nvd_cvss3_vector", type="string"),
            glue.CfnTable.ColumnProperty(name="nvd_cvss2_score", type="string"),
            glue.CfnTable.ColumnProperty(name="nvd_cvss2_vector", type="string"),
            glue.CfnTable.ColumnProperty(name="vendor_cvss3_score", type="string"),
            glue.CfnTable.ColumnProperty(name="vendor_cvss3_vector", type="string"),
            glue.CfnTable.ColumnProperty(name="vendor_cvss2_score", type="string"),
            glue.CfnTable.ColumnProperty(name="vendor_cvss2_vector", type="string"),
            glue.CfnTable.ColumnProperty(name="resource_type", type="string"),
            glue.CfnTable.ColumnProperty(name="ami", type="string"),
            glue.CfnTable.ColumnProperty(name="resource_public_ipv4", type="string"),
            glue.CfnTable.ColumnProperty(name="resource_private_ipv4", type="string"),
            glue.CfnTable.ColumnProperty(name="resource_ipv6", type="string"),
            glue.CfnTable.ColumnProperty(name="resource_vpc", type="string"),
            glue.CfnTable.ColumnProperty(name="port_range", type="string"),
            glue.CfnTable.ColumnProperty(name="epss_score", type="string"),
            glue.CfnTable.ColumnProperty(name="exploit_available", type="string"),
            glue.CfnTable.ColumnProperty(name="last_exploited_at", type="string"),
            glue.CfnTable.ColumnProperty(name="lambda_layers", type="string"),
            glue.CfnTable.ColumnProperty(name="lambda_package_type", type="string"),
            glue.CfnTable.ColumnProperty(name="lambda_last_updated_at", type="string"),
            glue.CfnTable.ColumnProperty(name="reference_urls", type="string"),
            glue.CfnTable.ColumnProperty(name="detector_name", type="string"),
            glue.CfnTable.ColumnProperty(name="package_manager", type="string"),
        ]
        # add the table to the database using the glue.CfnTable construct
        # add with theses properties
        # PARTITIONED BY (`year` int, `month` int, `day` int)
        # ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.OpenCSVSerde' STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat' OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat' LOCATION 's3://inspector-findings.eu-west-1.620992746856/' TBLPROPERTIES (
        # 'classification' = 'csv',
        # 'escapeChar' = '\\',
        # 'has_encrypted_data' = 'true',
        # 'quoteChar' = '\"',
        # 'separatorChar' = ',',
        # 'skip.header.line.count' = '1',
        # 'transient_lastDdlTime' = '1724165428'

        glue_table = glue.CfnTable(
            self,
            "InspectorFindingsTable",
            catalog_id=self.account,
            database_name=glue_db.ref,
            table_input=glue.CfnTable.TableInputProperty(
                name="inspector_findings",
                description="Table to store Amazon Inspector findings",
                table_type="EXTERNAL_TABLE",
                parameters={
                    "classification": "csv",
                    "has_encrypted_data": "true",
                    "separatorChar": ",",
                    "quoteChar": '"',
                    "escapeChar": "\\",
                    "skip.header.line.count": "1",
                },
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    columns=columns,
                    location=f"s3://{inspector_report_bucket.bucket_name}/",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.apache.hadoop.hive.serde2.OpenCSVSerde"
                    ),
                ),
                partition_keys=[
                    glue.CfnTable.ColumnProperty(name="year", type="int"),
                    glue.CfnTable.ColumnProperty(name="month", type="int"),
                    glue.CfnTable.ColumnProperty(name="day", type="int"),
                ],
            ),
        )
        # load partitions MSCK REPAIR TABLE `findings`;

        