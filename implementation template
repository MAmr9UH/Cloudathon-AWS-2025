// CougarLab Full Architecture CDK App (TypeScript, CDK v2)
// -----------------------------------------------------------
// This single file CDK app implements the two‑AZ architecture you shared:
//  - VPC (public / app private / db private subnets) with NAT GWs
//  - Internet‑facing ALB → Fargate service running your container image
//  - EFS for shared files, RDS MySQL 8 with RDS Proxy
//  - Cognito user & identity pools, CloudFront + WAF + Route 53 for www.anycompany.net
//  - S3 → Kinesis Data Firehose → QuickSight data‑source pipeline
//  - Pinpoint project, CloudTrail, GuardDuty, KMS key, SNS alerts
//
// Prerequisites before deploy:
//  1. Route 53 public hosted zone for "anycompany.net" already exists in this account/region.
//  2. `cdk bootstrap` has been run in the target account / region.
//  3. Replace "<ACCOUNT_ID>" and "<REGION>" (in cdk.json or via CLI) as needed.
//  4. Push your container image to ECR (or another repo) and set IMAGE_URI env var or context key.
//
// Deploy:
//    cdk deploy CougarLabStack --profile myprofile
// -----------------------------------------------------------

#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as efs from 'aws-cdk-lib/aws-efs';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53Targets from 'aws-cdk-lib/aws-route53-targets';
import * as certificatemanager from 'aws-cdk-lib/aws-certificatemanager';
import * as firehose from 'aws-cdk-lib/aws-kinesisfirehose';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as quicksight from 'aws-cdk-lib/aws-quicksight';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as guardduty from 'aws-cdk-lib/aws-guardduty';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sns_subs from 'aws-cdk-lib/aws-sns-subscriptions';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';

// -----------------------------------------------------------
// Helper: look up context or env vars with fallback
// -----------------------------------------------------------
function getContext(app: cdk.App, key: string, fallback?: string): string {
  return (app.node.tryGetContext(key) ?? process.env[key.toUpperCase()] ?? fallback ?? '').toString();
}

// -----------------------------------------------------------
// Stack Definition
// -----------------------------------------------------------
export class CougarLabStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ---------- Parameters / context ----------
    const domainName = 'anycompany.net';
    const siteSubDomain = 'www';
    const fullDomain = `${siteSubDomain}.${domainName}`;

    // Container image URI (ECR or DockerHub). Change by passing `-c imageUri=...` or env IMAGE_URI
    const imageUri = getContext(this.node.root as cdk.App, 'imageUri', 'public.ecr.aws/nginx/nginx:latest');

    // ---------- Networking ----------
    const vpc = new ec2.Vpc(this, 'Vpc', {
      cidr: '10.0.0.0/16',
      maxAzs: 2,
      natGateways: 2,
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: 'public',
          subnetType: ec2.SubnetType.PUBLIC,
        },
        {
          cidrMask: 24,
          name: 'app',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
        },
        {
          cidrMask: 24,
          name: 'db',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
        },
      ],
    });

    // ---------- Security Groups ----------
    const albSg = new ec2.SecurityGroup(this, 'AlbSg', {
      vpc,
      description: 'ALB security group',
      allowAllOutbound: true,
    });
    albSg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'HTTP');

    const ecsSg = new ec2.SecurityGroup(this, 'EcsSg', {
      vpc,
      description: 'ECS service SG',
      allowAllOutbound: true,
    });
    ecsSg.addIngressRule(albSg, ec2.Port.tcp(8080), 'From ALB');

    const rdsSg = new ec2.SecurityGroup(this, 'RdsSg', {
      vpc,
      description: 'RDS security group',
      allowAllOutbound: true,
    });
    rdsSg.addIngressRule(ecsSg, ec2.Port.tcp(3306), 'MySQL from ECS');

    // ---------- Application Load Balancer ----------
    const alb = new elbv2.ApplicationLoadBalancer(this, 'Alb', {
      vpc,
      internetFacing: true,
      securityGroup: albSg,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
    });

    const listener = alb.addListener('Http', {
      port: 80,
      open: true,
    });

    // ---------- ECS Cluster & Service ----------
    const cluster = new ecs.Cluster(this, 'Cluster', {
      vpc,
      containerInsights: true,
    });

    const taskRole = new iam.Role(this, 'TaskRole', {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
    });

    // Allow tasks to query parameter store / secrets manager if needed
    taskRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMReadOnlyAccess'));

    const taskDefinition = new ecs.FargateTaskDefinition(this, 'TaskDef', {
      memoryLimitMiB: 1024,
      cpu: 512,
      taskRole,
    });

    const container = taskDefinition.addContainer('AppContainer', {
      image: ecs.ContainerImage.fromRegistry(imageUri),
      logging: ecs.LogDriver.awsLogs({ streamPrefix: 'app' }),
      environment: {
        DB_ENDPOINT: 'placeholder', // will be patched after RDS creation
      },
    });
    container.addPortMappings({ containerPort: 8080 });

    const service = new ecs.FargateService(this, 'Service', {
      cluster,
      taskDefinition,
      desiredCount: 2,
      securityGroups: [ecsSg],
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    listener.addTargets('EcsTargets', {
      port: 80,
      targets: [service],
      healthCheck: {
        path: '/',
        timeout: cdk.Duration.seconds(5),
      },
    });

    // ---------- EFS ----------
    const fileSystem = new efs.FileSystem(this, 'Efs', {
      vpc,
      securityGroup: ecsSg,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ---------- RDS (MySQL 8) ----------
    const dbSubnetGroup = new rds.SubnetGroup(this, 'DbSubnetGroup', {
      description: 'DB Subnet Group',
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      subnetGroupName: 'db-subnets',
    });

    const db = new rds.DatabaseInstance(this, 'Database', {
      engine: rds.DatabaseInstanceEngine.mysql({ version: rds.MysqlEngineVersion.VER_8_0_36 }),
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      subnetGroup: dbSubnetGroup,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
      multiAz: true,
      port: 3306,
      securityGroups: [rdsSg],
      credentials: rds.Credentials.fromGeneratedSecret('admin'),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // RDS Proxy
    const proxy = new rds.DatabaseProxy(this, 'RdsProxy', {
      proxyTarget: rds.ProxyTarget.fromInstance(db),
      secrets: [db.secret!],
      vpc,
      requireTLS: true,
      securityGroups: [rdsSg],
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // Wire DB endpoint into task env
    container.addEnvironment('DB_ENDPOINT', proxy.endpoint);

    // ---------- Cognito ----------
    const userPool = new cognito.UserPool(this, 'UserPool', {
      selfSignUpEnabled: true,
      passwordPolicy: {
        minLength: 8,
        requireSymbols: false,
      },
      mfa: cognito.Mfa.OPTIONAL,
    });

    const userPoolClient = new cognito.UserPoolClient(this, 'UserPoolClient', {
      userPool,
    });

    const identityPool = new cognito.CfnIdentityPool(this, 'IdentityPool', {
      allowUnauthenticatedIdentities: false,
      cognitoIdentityProviders: [
        {
          clientId: userPoolClient.userPoolClientId,
          providerName: userPool.userPoolProviderName,
        },
      ],
    });

    // ---------- Route 53 & ACM cert (in us‑east‑1) ----------
    const hostedZone = route53.HostedZone.fromLookup(this, 'HostedZone', { domainName });

    const certificate = new certificatemanager.DnsValidatedCertificate(this, 'SiteCert', {
      domainName: fullDomain,
      hostedZone,
      region: 'us-east-1', // must be us-east-1 for CloudFront
    });

    // ---------- CloudFront & WAF ----------
    const webAcl = new wafv2.CfnWebACL(this, 'WebACL', {
      defaultAction: { allow: {} },
      scope: 'CLOUDFRONT',
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: 'webAcl',
      },
      name: 'CougarLabWebAcl',
      rules: [],
    });

    const distribution = new cloudfront.Distribution(this, 'SiteDistribution', {
      defaultBehavior: {
        origin: new origins.LoadBalancerV2Origin(alb, {
          protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      domainNames: [fullDomain],
      certificate,
      webAclId: webAcl.attrId,
    });

    new route53.ARecord(this, 'AliasRecord', {
      zone: hostedZone,
      recordName: siteSubDomain,
      target: route53.RecordTarget.fromAlias(new route53Targets.CloudFrontTarget(distribution)),
    });

    // ---------- Analytics Pipeline (S3 → Firehose → QuickSight) ----------
    const analyticsBucket = new s3.Bucket(this, 'AnalyticsBucket', {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      versioned: true,
      lifecycleRules: [{ expiration: cdk.Duration.days(365) }],
    });

    const firehoseLogGroup = new logs.LogGroup(this, 'FirehoseLogGroup', {
      retention: logs.RetentionDays.ONE_MONTH,
    });

    const firehoseRole = new iam.Role(this, 'FirehoseRole', {
      assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com'),
    });
    analyticsBucket.grantReadWrite(firehoseRole);
    firehoseLogGroup.grantWrite(firehoseRole);

    new firehose.CfnDeliveryStream(this, 'DeliveryStream', {
      deliveryStreamType: 'DirectPut',
      s3DestinationConfiguration: {
        bucketArn: analyticsBucket.bucketArn,
        roleArn: firehoseRole.roleArn,
        bufferingHints: {
          intervalInSeconds: 300,
          sizeInMBs: 5,
        },
        cloudWatchLoggingOptions: {
          enabled: true,
          logGroupName: firehoseLogGroup.logGroupName,
          logStreamName: 'S3Delivery',
        },
      },
    });

    // QuickSight – limited CDK coverage, create a placeholder data source
    new quicksight.CfnDataSource(this, 'QsDataSource', {
      awsAccountId: this.account,
      dataSourceId: 's3-analytics-ds',
      name: 'S3AnalyticsSource',
      type: 'S3',
      dataSourceParameters: {
        s3Parameters: {
          manifestFileLocation: {
            bucket: analyticsBucket.bucketName,
            key: 'manifest.json', // must be uploaded separately
          },
        },
      },
    });

    // ---------- Pinpoint ----------
    new pinpoint.CfnApp(this, 'PinpointApp', {
      name: 'CougarLabPinpoint',
    });

    // ---------- Observability & Security ----------
    const kmsKey = new kms.Key(this, 'KmsKey', {
      enableKeyRotation: true,
      alias: 'alias/cougarlab/general',
    });

    new cloudtrail.Trail(this, 'Trail', {
      sendToCloudWatchLogs: true,
      encryptionKey: kmsKey,
      includeGlobalServiceEvents: true,
    });

    new guardduty.CfnDetector(this, 'GuardDuty', {
      enable: true,
    });

    const alertTopic = new sns.Topic(this, 'AlertsTopic');
    alertTopic.addSubscription(new sns_subs.EmailSubscription('ops@anycompany.net'));

    // Example CloudWatch alarm on ALB 5XX error rate → SNS
    const alb5xxAlarm = new cloudwatch.Alarm(this, 'Alb5xxAlarm', {
      metric: alb.metricHttpCodeTarget(elbv2.HttpCodeTarget.PER_5XX_COUNT),
      evaluationPeriods: 1,
      threshold: 5,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
    });
    alb5xxAlarm.addAlarmAction(new actions.SnsAction(alertTopic));

    // ---------- Outputs ----------
    new cdk.CfnOutput(this, 'LoadBalancerDNS', { value: alb.loadBalancerDnsName });
    new cdk.CfnOutput(this, 'CloudFrontURL', { value: `https://${fullDomain}` });
    new cdk.CfnOutput(this, 'UserPoolId', { value: userPool.userPoolId });
    new cdk.CfnOutput(this, 'IdentityPoolId', { value: identityPool.ref });
    new cdk.CfnOutput(this, 'RdsEndpoint', { value: db.dbInstanceEndpointAddress });
  }
}

// -----------------------------------------------------------
// CDK App entrypoint
// -----------------------------------------------------------
const app = new cdk.App();
new CougarLabStack(app, 'CougarLabStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});

