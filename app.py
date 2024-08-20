#!/usr/bin/env python3
import os

import aws_cdk as cdk
from constructs import Construct
from aws_cdk import App, Stack                    # core constructs

from amazon_inspector_findings_reporter_cdk.amazon_inspector_findings_reporter_cdk_stack import InspectorFindingsReportStack


app = cdk.App()
stack = InspectorFindingsReportStack(app, "AmazonInspectorFindingsReporterCdkStack")
# add tags to stack Owner, Component
cdk.Tags.of(stack).add("Owner", "CloudEngineering")
cdk.Tags.of(stack).add("Component", "InspectorFindingsReporter")
app.synth()
