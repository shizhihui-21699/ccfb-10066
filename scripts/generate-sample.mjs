#!/usr/bin/env node
/**
 * Generates src/data/sample-dataset.json.
 *
 * The dataset is synthetic and safe to publish: account IDs, user names and
 * resources are fictional. It models an AWS organization with production,
 * development and shared-services accounts, each with SCPs, permissions
 * boundaries, resource policies and a realistic spread of managed/inline
 * policies.
 *
 * Several statements are deliberately written to look safe while granting more
 * than they appear to. Each is listed in README.md under "样例中的陷阱".
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(here, '../src/data/sample-dataset.json');

const ORG = 'o-examplecorp';
const PROD = '111122223333';
const DEV = '444455556666';
const SHARED = '777788889999';
const ACCOUNTS = [PROD, DEV, SHARED];
const GEN_AT = '2026-11-15T00:00:00.000Z';

const policies = [];
const users = [];
const groups = [];
const roles = [];
const resources = [];
const resourcePolicies = [];

const put = (record) => {
  policies.push(record);
  return record.id;
};

/* ------------------------------------------------------------------ */
/* SCPs                                                                */
/* ------------------------------------------------------------------ */

const fullAwsAccess = {
  Version: '2012-10-17',
  Statement: [{ Sid: 'AllowAllServices', Effect: 'Allow', Action: '*', Resource: '*' }],
};

put({
  id: 'scp-root-full-access',
  name: 'FullAWSAccess (组织根)',
  kind: 'scp',
  description: 'AWS Organizations 默认附加到根的全允许 SCP。',
  document: fullAwsAccess,
});

put({
  id: 'scp-account-full-access',
  name: 'FullAWSAccess (账号层)',
  kind: 'scp',
  description: '每个账号默认附加的全允许 SCP；移除它会让该账号失去所有权限。',
  document: fullAwsAccess,
});

put({
  id: 'scp-prod-guardrails',
  name: 'Prod-Guardrails',
  kind: 'scp',
  description:
    '生产 OU 护栏：限制组织管理与 IAM 提权，并阻止改写生产桶的桶策略。注意 ProtectProdBucketPolicies 的前缀写法。',
  document: {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DenyOrgManagement',
        Effect: 'Deny',
        Action: ['organizations:*'],
        Resource: '*',
      },
      {
        Sid: 'BlockIamPrivilegeEscalation',
        Effect: 'Deny',
        Action: [
          'iam:CreatePolicyVersion',
          'iam:SetDefaultPolicyVersion',
          'iam:AttachUserPolicy',
          'iam:AttachRolePolicy',
        ],
        Resource: '*',
      },
      {
        // 陷阱 1：只匹配 prod-*，而真正的生产桶叫 production-payments-archive。
        Sid: 'ProtectProdBucketPolicies',
        Effect: 'Deny',
        Action: ['s3:PutBucketPolicy', 's3:DeleteBucketPolicy', 's3:PutBucketAcl'],
        Resource: 'arn:aws:s3:::prod-*',
      },
      {
        Sid: 'DenyPublicObjectAcl',
        Effect: 'Deny',
        Action: 's3:PutObjectAcl',
        Resource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::prod-*/*', 'arn:aws:s3:::production-*', 'arn:aws:s3:::production-*/*'],
      },
    ],
  },
});

put({
  id: 'scp-prod-full-access',
  name: 'FullAWSAccess (生产 OU)',
  kind: 'scp',
  document: fullAwsAccess,
  description: '生产 OU 的默认放行 SCP。',
});

put({
  id: 'scp-dev-open',
  name: 'Dev-Open',
  kind: 'scp',
  description: '开发 OU：只阻止退出组织，其余全部放行，便于实验。',
  document: {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'DenyLeaveOrg', Effect: 'Deny', Action: 'organizations:LeaveOrganization', Resource: '*' },
      {
        Sid: 'DenyProdBucketDeletionFromDev',
        Effect: 'Deny',
        Action: ['s3:DeleteObject', 's3:DeleteBucket'],
        Resource: ['arn:aws:s3:::prod-*', 'arn:aws:s3:::prod-*/*'],
      },
    ],
  },
});

put({
  id: 'scp-dev-full-access',
  name: 'FullAWSAccess (开发 OU)',
  kind: 'scp',
  document: fullAwsAccess,
  description: '开发 OU 的默认放行 SCP。',
});

put({
  id: 'scp-shared-guardrails',
  name: 'SharedServices-Guardrails',
  kind: 'scp',
  description: '共享服务 OU：禁止删除 KMS 密钥与机密。',
  document: {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DenyKeyDeletion',
        Effect: 'Deny',
        Action: ['kms:ScheduleKeyDeletion', 'kms:DisableKey'],
        Resource: 'arn:aws:kms:*:*:key/*',
      },
      {
        Sid: 'DenySecretDeletion',
        Effect: 'Deny',
        Action: ['secretsmanager:DeleteSecret'],
        Resource: 'arn:aws:secretsmanager:*:*:secret:*',
      },
    ],
  },
});

put({
  id: 'scp-shared-full-access',
  name: 'FullAWSAccess (共享服务 OU)',
  kind: 'scp',
  document: fullAwsAccess,
  description: '共享服务 OU 的默认放行 SCP。',
});

/* ------------------------------------------------------------------ */
/* Curated policies                                                    */
/* ------------------------------------------------------------------ */

const policy = (id, name, kind, description, document, labels = []) =>
  put({ id, name, kind, description, labels, document });

/* --- identity policies: production ------------------------------- */

policy(
  'pol-prod-platform-admin',
  'Platform-Admin-Prod',
  'managed',
  '平台管理员的生产权限：读写生产桶，但显式禁止删除支付归档对象。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ListProdBuckets',
        Effect: 'Allow',
        Action: ['s3:ListBucket', 's3:GetBucketLocation'],
        Resource: [
          'arn:aws:s3:::prod-artifacts-build',
          'arn:aws:s3:::prod-customer-exports',
          'arn:aws:s3:::production-payments-archive',
        ],
      },
      {
        Sid: 'ReadWriteProdObjects',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:PutObject'],
        Resource: [
          'arn:aws:s3:::prod-artifacts-build/*',
          'arn:aws:s3:::prod-customer-exports/*',
          'arn:aws:s3:::production-payments-archive/*',
        ],
      },
      {
        Sid: 'DeleteBuildArtifactsOnly',
        Effect: 'Allow',
        Action: 's3:DeleteObject',
        Resource: 'arn:aws:s3:::prod-artifacts-build/*',
      },
      {
        Sid: 'NeverDeletePayments',
        Effect: 'Deny',
        Action: 's3:DeleteObject',
        Resource: 'arn:aws:s3:::production-payments-archive/*',
      },
    ],
  },
  ['baseline', 'prod'],
);

policy(
  'pol-prod-storage-team',
  'Storage-Team-Prod',
  'managed',
  '存储团队：对生产存储桶的完整读写删权限（由权限边界进一步收缩）。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'StorageBucketAdmin',
        Effect: 'Allow',
        Action: 's3:*',
        Resource: [
          'arn:aws:s3:::prod-*',
          'arn:aws:s3:::prod-*/*',
          'arn:aws:s3:::production-*',
          'arn:aws:s3:::production-*/*',
        ],
      },
      {
        Sid: 'StorageKms',
        Effect: 'Allow',
        Action: ['kms:Decrypt', 'kms:Encrypt', 'kms:GenerateDataKey', 'kms:DescribeKey'],
        Resource: 'arn:aws:kms:*:*:key/*',
      },
    ],
  },
  ['prod', 'storage'],
);

policy(
  'pol-prod-auditor',
  'Auditor-Prod-ReadOnly',
  'managed',
  '审计员：生产数据只读 + 云审计日志查询。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AuditReadObjects',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:GetObjectVersion'],
        Resource: 'arn:aws:s3:::production-*/*',
      },
      {
        Sid: 'AuditListBuckets',
        Effect: 'Allow',
        Action: 's3:ListBucket',
        Resource: 'arn:aws:s3:::production-*',
      },
      {
        Sid: 'AuditLogs',
        Effect: 'Allow',
        Action: ['logs:FilterLogEvents', 'logs:GetLogEvents', 'cloudtrail:LookupEvents'],
        Resource: ['arn:aws:logs:*:*:log-group:*', 'arn:aws:cloudtrail:*:*:trail/*'],
      },
    ],
  },
  ['audit', 'prod'],
);

policy(
  'pol-prod-deployer',
  'Deployer-Prod',
  'managed',
  '发布机器人/发布人员的部署权限。AssumeRole 的资源 ARN 使用了账号通配（陷阱 4）。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'UploadArtifacts',
        Effect: 'Allow',
        Action: ['s3:PutObject', 's3:GetObject', 's3:ListBucket', 's3:DeleteObject'],
        Resource: ['arn:aws:s3:::prod-artifacts-build', 'arn:aws:s3:::prod-artifacts-build/*'],
      },
      {
        Sid: 'ReadDeployConfig',
        Effect: 'Allow',
        Action: ['ssm:GetParameter', 'ssm:GetParameters'],
        Resource: 'arn:aws:ssm:*:*:parameter/deploy/*',
      },
      {
        // 陷阱 4：账号字段是通配，跨账号也可扮演同名角色。
        Sid: 'AssumeDeployRoles',
        Effect: 'Allow',
        Action: 'sts:AssumeRole',
        Resource: ['arn:aws:iam::*:role/ProdDeployer', 'arn:aws:iam::*:role/CICDRunner'],
      },
    ],
  },
  ['deploy', 'prod'],
);

policy(
  'pol-prod-tagged-upload',
  'Tagged-Upload-Policy',
  'managed',
  '数据工程上传：本意是"只在携带指定标签时允许上传"，实际缺少 Null 检查（陷阱 2）。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'UploadPaymentsWithTags',
        Effect: 'Allow',
        Action: 's3:PutObject',
        Resource: 'arn:aws:s3:::production-payments-archive/*',
        Condition: {
          'ForAllValues:StringEquals': {
            'aws:TagKeys': ['classification', 'owner'],
          },
        },
      },
    ],
  },
  ['data-eng', 'prod', 'trap'],
);

policy(
  'pol-prod-intern',
  'Intern-Baseline',
  'managed',
  '实习生：只读开发环境对象与列举全部桶。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ListAllBuckets',
        Effect: 'Allow',
        Action: 's3:ListAllMyBuckets',
        Resource: '*',
      },
      {
        Sid: 'ReadDevObjects',
        Effect: 'Allow',
        Action: 's3:GetObject',
        Resource: 'arn:aws:s3:::dev-*/*',
      },
    ],
  },
  ['intern'],
);

policy(
  'pol-prod-dataeng',
  'DataEngineering-Prod',
  'managed',
  '数据工程团队：生产桶读写、Athena 查询、Glue 任务管理。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ReadWriteAnalyticsBuckets',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:PutObject', 's3:ListBucket', 's3:GetBucketLocation'],
        Resource: [
          'arn:aws:s3:::prod-customer-exports',
          'arn:aws:s3:::prod-customer-exports/*',
          'arn:aws:s3:::production-payments-archive/*',
        ],
      },
      {
        Sid: 'AthenaQueries',
        Effect: 'Allow',
        Action: ['athena:StartQueryExecution', 'athena:GetQueryResults', 'athena:ListWorkGroups'],
        Resource: 'arn:aws:athena:*:*:workgroup/*',
      },
      {
        Sid: 'GlueJobs',
        Effect: 'Allow',
        Action: ['glue:StartJobRun', 'glue:GetJobRun'],
        Resource: 'arn:aws:glue:*:*:job/*',
      },
    ],
  },
  ['data-eng', 'prod'],
);

policy(
  'pol-prod-finops',
  'FinOps-Prod',
  'managed',
  '财务运营：读取成本报告，禁止触碰支付归档。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ReadCostReports',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:ListBucket'],
        Resource: ['arn:aws:s3:::prod-customer-exports', 'arn:aws:s3:::prod-customer-exports/*'],
      },
      {
        Sid: 'ReadCostExplorer',
        Effect: 'Allow',
        Action: ['ce:GetCostAndUsage', 'ce:GetDimensionValues'],
        Resource: 'arn:aws:ce:*:*:/',
      },
      {
        Sid: 'NoPaymentsAccess',
        Effect: 'Deny',
        Action: 's3:*',
        Resource: ['arn:aws:s3:::production-payments-archive', 'arn:aws:s3:::production-payments-archive/*'],
      },
    ],
  },
  ['finops', 'prod'],
);

policy(
  'pol-prod-breakglass',
  'BreakGlass-Prod',
  'managed',
  '紧急通道角色策略：广泛运维权限，但不得删除支付归档。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'BreakGlassS3',
        Effect: 'Allow',
        Action: 's3:*',
        Resource: [
          'arn:aws:s3:::prod-*',
          'arn:aws:s3:::prod-*/*',
          'arn:aws:s3:::production-*',
          'arn:aws:s3:::production-*/*',
        ],
      },
      {
        Sid: 'BreakGlassEc2',
        Effect: 'Allow',
        Action: ['ec2:DescribeInstances', 'ec2:RebootInstances', 'ec2:StartInstances', 'ec2:StopInstances'],
        Resource: 'arn:aws:ec2:*:*:instance/*',
      },
      {
        Sid: 'BreakGlassIamRead',
        Effect: 'Allow',
        Action: ['iam:GetRole', 'iam:ListRoles', 'iam:GetPolicy', 'iam:ListPolicies'],
        Resource: 'arn:aws:iam::*:role/*',
      },
      {
        Sid: 'BreakGlassNoPaymentsWrites',
        Effect: 'Deny',
        Action: ['s3:DeleteObject', 's3:PutObject'],
        Resource: 'arn:aws:s3:::production-payments-archive/*',
      },
    ],
  },
  ['breakglass', 'prod'],
);

policy(
  'pol-prod-cicd',
  'CI-CD-Prod',
  'managed',
  '流水线角色：只能写构建产物并推送日志。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'CicdArtifacts',
        Effect: 'Allow',
        Action: ['s3:PutObject', 's3:GetObject', 's3:DeleteObject', 's3:ListBucket'],
        Resource: ['arn:aws:s3:::prod-artifacts-build', 'arn:aws:s3:::prod-artifacts-build/*'],
      },
      {
        Sid: 'CicdLogs',
        Effect: 'Allow',
        Action: ['logs:CreateLogStream', 'logs:PutLogEvents', 'logs:CreateLogGroup'],
        Resource: 'arn:aws:logs:*:*:log-group:/aws/cicd/*',
      },
    ],
  },
  ['cicd', 'prod'],
);

policy(
  'pol-prod-ip-restricted',
  'Corp-Network-Prod-Access',
  'managed',
  '本意是"仅允许公司网段访问生产桶"，但 CIDR 列表里混入了 0.0.0.0/0（陷阱 5）。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ProdFromCorpNetwork',
        Effect: 'Allow',
        Action: 's3:*',
        Resource: ['arn:aws:s3:::production-*', 'arn:aws:s3:::production-*/*'],
        Condition: {
          IpAddress: {
            'aws:SourceIp': ['10.0.0.0/8', '203.0.113.0/24', '0.0.0.0/0'],
          },
        },
      },
    ],
  },
  ['network', 'prod', 'trap'],
);

policy(
  'pol-prod-secrets-read',
  'Secrets-Reader-Prod',
  'managed',
  '按团队标签限制的生产机密读取。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ReadSecretsForPlatformTeam',
        Effect: 'Allow',
        Action: 'secretsmanager:GetSecretValue',
        Resource: 'arn:aws:secretsmanager:*:*:secret:prod/*',
        Condition: {
          StringEquals: { 'aws:PrincipalTag/team': 'platform-ops' },
        },
      },
      {
        Sid: 'ReadSecretsForDataTeam',
        Effect: 'Allow',
        Action: 'secretsmanager:GetSecretValue',
        Resource: 'arn:aws:secretsmanager:*:*:secret:prod/data/*',
        Condition: {
          StringEquals: { 'aws:PrincipalTag/team': ['data-eng', 'finops'] },
        },
      },
    ],
  },
  ['secrets', 'prod'],
);

/* --- identity policies: development ------------------------------ */

policy(
  'pol-dev-standard',
  'Developer-Dev',
  'managed',
  '开发人员：开发环境完整 S3/EC2 权限与日志读取。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DevS3',
        Effect: 'Allow',
        Action: 's3:*',
        Resource: ['arn:aws:s3:::dev-*', 'arn:aws:s3:::dev-*/*'],
      },
      {
        Sid: 'DevEc2',
        Effect: 'Allow',
        Action: ['ec2:RunInstances', 'ec2:TerminateInstances', 'ec2:DescribeInstances', 'ec2:CreateTags'],
        Resource: ['arn:aws:ec2:*:*:instance/*', 'arn:aws:ec2:*:*:volume/*'],
      },
      {
        Sid: 'DevLogs',
        Effect: 'Allow',
        Action: ['logs:FilterLogEvents', 'logs:GetLogEvents', 'logs:DescribeLogGroups'],
        Resource: 'arn:aws:logs:*:*:log-group:*',
      },
      {
        Sid: 'DevDynamo',
        Effect: 'Allow',
        Action: 'dynamodb:*',
        Resource: 'arn:aws:dynamodb:*:*:table/*',
      },
    ],
  },
  ['dev'],
);

policy(
  'pol-dev-devops',
  'DevOps-Dev',
  'managed',
  '开发运维：可在开发账号扮演发布角色，并读取共享审计日志。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DevopsAssumeDeployer',
        Effect: 'Allow',
        Action: 'sts:AssumeRole',
        Resource: [
          'arn:aws:iam::444455556666:role/DevDeployer',
          'arn:aws:iam::111122223333:role/ProdDeployer',
        ],
      },
      {
        Sid: 'DevopsReadSharedLogs',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:ListBucket'],
        Resource: ['arn:aws:s3:::shared-audit-logs', 'arn:aws:s3:::shared-audit-logs/*'],
      },
      {
        Sid: 'DevopsCicdAdmin',
        Effect: 'Allow',
        Action: ['codebuild:StartBuild', 'codebuild:RetryBuild', 'codebuild:BatchGetBuilds'],
        Resource: 'arn:aws:codebuild:*:*:project/*',
      },
    ],
  },
  ['devops', 'dev'],
);

policy(
  'pol-dev-contractor',
  'Contractor-Baseline',
  'managed',
  '外包人员基线：只读所有桶的对象，用于排查问题。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ContractorReadObjects',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:GetObjectVersion'],
        Resource: 'arn:aws:s3:::*/*',
      },
      {
        Sid: 'ContractorListBuckets',
        Effect: 'Allow',
        Action: 's3:ListAllMyBuckets',
        Resource: '*',
      },
      {
        Sid: 'ContractorTicketTools',
        Effect: 'Allow',
        Action: ['support:DescribeCases', 'support:DescribeTrustedPrincipals'],
        Resource: '*',
      },
    ],
  },
  ['contractor', 'dev'],
);

/* --- identity policies: shared services -------------------------- */

policy(
  'pol-shared-support',
  'Shared-Support-Ops',
  'managed',
  '共享服务支持：审计日志读写、工单系统。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'SharedLogs',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:PutObject', 's3:ListBucket'],
        Resource: ['arn:aws:s3:::shared-audit-logs', 'arn:aws:s3:::shared-audit-logs/*'],
      },
      {
        Sid: 'SharedSecrets',
        Effect: 'Allow',
        Action: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        Resource: 'arn:aws:secretsmanager:*:*:secret:shared/*',
      },
    ],
  },
  ['shared'],
);

policy(
  'pol-shared-readonly-notaction',
  'Shared-ReadOnly-Objects',
  'managed',
  '本意是"共享桶只读"，用 NotAction 排除写入动作，却漏掉了桶级管理动作（陷阱 3）。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ReadOnlyExceptWrites',
        Effect: 'Allow',
        NotAction: ['s3:PutObject', 's3:DeleteObject'],
        Resource: ['arn:aws:s3:::shared-*', 'arn:aws:s3:::shared-*/*'],
      },
    ],
  },
  ['shared', 'trap'],
);

/* --- boundaries --------------------------------------------------- */

policy(
  'pol-boundary-standard',
  'Standard-User-Boundary',
  'boundary',
  '普通用户边界：允许常见服务，但禁止删除桶与改动 IAM 权限边界自身。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ServiceBoundaries',
        Effect: 'Allow',
        Action: ['s3:*', 'ec2:*', 'logs:*', 'dynamodb:*', 'athena:*', 'glue:*', 'codebuild:*', 'support:*'],
        Resource: '*',
      },
      {
        Sid: 'AllowSelfServiceIam',
        Effect: 'Allow',
        Action: [
          'iam:ChangePassword',
          'iam:GetUser',
          'iam:*AccessKey*',
          'iam:*SigningCertificate*',
          'iam:*ServiceSpecificCredential*',
        ],
        Resource: 'arn:aws:iam::*:user/${aws:username}',
      },
      {
        Sid: 'DenyBucketDeletion',
        Effect: 'Deny',
        Action: ['s3:DeleteBucket', 's3:DeleteBucketPolicy'],
        Resource: 'arn:aws:s3:::*',
      },
      {
        Sid: 'DenyBoundaryTampering',
        Effect: 'Deny',
        Action: ['iam:DeleteUserPermissionsBoundary', 'iam:PutUserPermissionsBoundary'],
        Resource: '*',
      },
    ],
  },
  ['boundary'],
);

policy(
  'pol-boundary-admin',
  'Admin-Boundary',
  'boundary',
  '管理员边界：放宽服务范围，但仍禁止在生产前缀上删除对象。注意资源前缀写成了 prod-*（陷阱 1）。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AdminServices',
        Effect: 'Allow',
        Action: ['s3:*', 'ec2:*', 'logs:*', 'dynamodb:*', 'athena:*', 'glue:*', 'kms:*', 'ssm:*', 'iam:Get*', 'iam:List*', 'sts:AssumeRole', 'sts:GetCallerIdentity'],
        Resource: '*',
      },
      {
        Sid: 'AdminNoProdDeletes',
        Effect: 'Deny',
        Action: ['s3:DeleteObject', 's3:DeleteBucket'],
        Resource: ['arn:aws:s3:::prod-*/*', 'arn:aws:s3:::prod-*'],
      },
      {
        Sid: 'AdminNoBoundaryPolicyEdits',
        Effect: 'Deny',
        Action: ['iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion', 'iam:DeletePolicy'],
        Resource: [
          'arn:aws:iam::*:policy/Admin-Boundary',
          'arn:aws:iam::*:policy/Standard-User-Boundary',
        ],
      },
    ],
  },
  ['boundary', 'admin'],
);

policy(
  'pol-boundary-readonly',
  'ReadOnly-Boundary',
  'boundary',
  '审计类身份边界：只允许读取类动作。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'ReadOnlyServices',
        Effect: 'Allow',
        Action: [
          's3:GetObject',
          's3:GetObjectVersion',
          's3:ListBucket',
          's3:ListAllMyBuckets',
          's3:GetBucketLocation',
          'logs:FilterLogEvents',
          'logs:GetLogEvents',
          'logs:DescribeLogGroups',
          'cloudtrail:LookupEvents',
          'sts:GetCallerIdentity',
        ],
        Resource: '*',
      },
    ],
  },
  ['boundary', 'readonly'],
);

policy(
  'pol-boundary-cicd',
  'CICD-Boundary',
  'boundary',
  '流水线身份边界：只允许构建产物与日志。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'CicdBoundary',
        Effect: 'Allow',
        Action: ['s3:PutObject', 's3:GetObject', 's3:DeleteObject', 's3:ListBucket', 'logs:*', 'ecr:*', 'codebuild:*'],
        Resource: '*',
      },
      {
        Sid: 'CicdNoDeleteProd',
        Effect: 'Deny',
        Action: 's3:DeleteObject',
        Resource: 'arn:aws:s3:::production-*/*',
      },
    ],
  },
  ['boundary', 'cicd'],
);

/* --- resource policies -------------------------------------------- */

const resourcePolicy = (id, name, description, arns, document) => {
  const policyId = put({
    id: `${id}-doc`,
    name,
    kind: 'resource',
    description,
    document,
    labels: ['resource'],
  });
  resourcePolicies.push({ id, name, resourceArns: arns, policyId, description });
};

resourcePolicy(
  'rp-prod-payments-bucket',
  'BucketPolicy-production-payments-archive',
  '公共读取的支付归档桶策略：只要求 TLS，实际对全互联网开放读（陷阱 6）。',
  ['arn:aws:s3:::production-payments-archive'],
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'PublicReadOverTls',
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: 'arn:aws:s3:::production-payments-archive/*',
        Condition: { Bool: { 'aws:SecureTransport': 'true' } },
      },
      {
        Sid: 'AllowProdAccountList',
        Effect: 'Allow',
        Principal: { AWS: `arn:aws:iam::${PROD}:root` },
        Action: 's3:ListBucket',
        Resource: 'arn:aws:s3:::production-payments-archive',
      },
    ],
  },
);

resourcePolicy(
  'rp-prod-artifacts-bucket',
  'BucketPolicy-prod-artifacts-build',
  '允许开发账号的流水线角色读取构建产物，用于联调。',
  ['arn:aws:s3:::prod-artifacts-build'],
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AllowDevAccountRead',
        Effect: 'Allow',
        Principal: { AWS: `arn:aws:iam::${DEV}:root` },
        Action: ['s3:GetObject', 's3:ListBucket'],
        Resource: ['arn:aws:s3:::prod-artifacts-build', 'arn:aws:s3:::prod-artifacts-build/*'],
      },
      {
        Sid: 'DenyDeleteFromOtherAccounts',
        Effect: 'Deny',
        Principal: { AWS: '*' },
        Action: 's3:DeleteObject',
        Resource: 'arn:aws:s3:::prod-artifacts-build/*',
        Condition: { StringNotEquals: { 'aws:PrincipalAccount': PROD } },
      },
    ],
  },
);

resourcePolicy(
  'rp-shared-audit-bucket',
  'BucketPolicy-shared-audit-logs',
  '审计日志桶：向指定外部审计账号开放只读。',
  ['arn:aws:s3:::shared-audit-logs'],
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AllowExternalAuditorRead',
        Effect: 'Allow',
        Principal: { AWS: ['arn:aws:iam::999900001111:root'] },
        Action: ['s3:GetObject', 's3:ListBucket'],
        Resource: ['arn:aws:s3:::shared-audit-logs', 'arn:aws:s3:::shared-audit-logs/*'],
      },
      {
        Sid: 'RequireTls',
        Effect: 'Deny',
        Principal: { AWS: '*' },
        Action: 's3:*',
        Resource: 'arn:aws:s3:::shared-audit-logs/*',
        Condition: { Bool: { 'aws:SecureTransport': 'false' } },
      },
    ],
  },
);

/* --- trust policies ----------------------------------------------- */

const trustPolicy = (id, name, description, document) =>
  put({ id, name, kind: 'trust', description, labels: ['trust'], document });

trustPolicy(
  'trust-prod-deployer',
  'Trust-ProdDeployer',
  '生产发布角色：信任生产平台管理员、开发账号根与 CI 服务。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'TrustPlatformAdmins',
        Effect: 'Allow',
        Principal: { AWS: `arn:aws:iam::${PROD}:root` },
        Action: 'sts:AssumeRole',
      },
      {
        Sid: 'TrustDevAccount',
        Effect: 'Allow',
        Principal: { AWS: `arn:aws:iam::${DEV}:root` },
        Action: 'sts:AssumeRole',
        Condition: {
          StringEquals: { 'aws:PrincipalTag/team': 'devops' },
        },
      },
      {
        Sid: 'TrustCicdService',
        Effect: 'Allow',
        Principal: { Service: 'codebuild.amazonaws.com' },
        Action: 'sts:AssumeRole',
      },
    ],
  },
);

trustPolicy(
  'trust-dev-proddeployer-name-collision',
  'Trust-Dev-ProdDeployer',
  '开发账号里一个同名角色 ProdDeployer。它信任生产账号根，于是生产账号那条账号通配的 AssumeRole 授权可以跨账号落到它身上。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'TrustProdAccountForNameCollisionDemo',
        Effect: 'Allow',
        Principal: { AWS: `arn:aws:iam::${PROD}:root` },
        Action: 'sts:AssumeRole',
      },
    ],
  },
);

trustPolicy(
  'trust-prod-breakglass',
  'Trust-ProdBreakGlass',
  '紧急通道角色：只信任安全值班人，并要求 MFA 会话标签。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'TrustOnCall',
        Effect: 'Allow',
        Principal: { AWS: `arn:aws:iam::${PROD}:user/security-oncall` },
        Action: 'sts:AssumeRole',
        Condition: {
          StringEquals: { 'aws:PrincipalTag/oncall': 'true' },
        },
      },
    ],
  },
);

trustPolicy(
  'trust-dev-deployer',
  'Trust-DevDeployer',
  '开发发布角色：信任开发账号全体。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'TrustDevAccount',
        Effect: 'Allow',
        Principal: { AWS: `arn:aws:iam::${DEV}:root` },
        Action: 'sts:AssumeRole',
      },
    ],
  },
);

trustPolicy(
  'trust-shared-ops',
  'Trust-SharedOps',
  '共享服务运维角色：信任共享服务账号与生产平台管理员。',
  {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'TrustSharedAccount',
        Effect: 'Allow',
        Principal: { AWS: `arn:aws:iam::${SHARED}:root` },
        Action: 'sts:AssumeRole',
      },
      {
        Sid: 'TrustPlatformAdmins',
        Effect: 'Allow',
        Principal: { AWS: `arn:aws:iam::${PROD}:root` },
        Action: 'sts:AssumeRole',
        Condition: {
          StringEquals: { 'aws:PrincipalTag/team': 'platform-ops' },
        },
      },
    ],
  },
);

/* ------------------------------------------------------------------ */
/* Bulk corpus                                                         */
/* ------------------------------------------------------------------ */

const BUCKETS = [
  'prod-artifacts-build',
  'prod-customer-exports',
  'production-payments-archive',
  'prod-analytics-raw',
  'prod-media-originals',
  'dev-app-data',
  'dev-integration-fixtures',
  'dev-sandbox-scratch',
  'shared-audit-logs',
  'shared-tooling-cache',
  'shared-backup-vault',
];

const BULK = [];

function pushBulk(record) {
  if (policies.some((existing) => existing.id === record.id)) {
    throw new Error(`duplicate policy id ${record.id}`);
  }
  const withLabels = { ...record, labels: ['bulk', ...(record.labels ?? [])] };
  put(withLabels);
  BULK.push(withLabels);
}

const TEAMS = [
  { key: 'platform', name: 'Platform', tag: 'platform-ops' },
  { key: 'storage', name: 'Storage', tag: 'storage' },
  { key: 'data', name: 'DataEngineering', tag: 'data-eng' },
  { key: 'analytics', name: 'Analytics', tag: 'analytics' },
  { key: 'media', name: 'MediaPipeline', tag: 'media' },
  { key: 'finops', name: 'FinOps', tag: 'finops' },
  { key: 'support', name: 'Support', tag: 'support' },
  { key: 'security', name: 'Security', tag: 'security' },
  { key: 'network', name: 'Network', tag: 'network' },
  { key: 'backend', name: 'Backend', tag: 'backend' },
];

/* --- per-team S3 policies ---------------------------------------- */

for (const team of TEAMS) {
  const bucket = BUCKETS[TEAMS.indexOf(team) % BUCKETS.length];
  const isProd = bucket.startsWith('prod');
  pushBulk({
    id: `pol-${team.key}-s3-rw`,
    name: `${team.name}-S3-ReadWrite`,
    kind: 'managed',
    description: `${team.name} 团队对 ${bucket} 的读写权限。`,
    document: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: `${team.name}S3List`,
          Effect: 'Allow',
          Action: ['s3:ListBucket', 's3:GetBucketLocation'],
          Resource: `arn:aws:s3:::${bucket}`,
        },
        {
          Sid: `${team.name}S3Objects`,
          Effect: 'Allow',
          Action: ['s3:GetObject', 's3:PutObject'],
          Resource: `arn:aws:s3:::${bucket}/*`,
          Condition: isProd ? { Bool: { 'aws:SecureTransport': 'true' } } : undefined,
        },
      ],
    },
    labels: [team.key],
  });

  pushBulk({
    id: `pol-${team.key}-s3-ro`,
    name: `${team.name}-S3-ReadOnly`,
    kind: 'managed',
    description: `${team.name} 团队只读 ${bucket}，带版本读取与分页限制。`,
    document: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: `${team.name}ReadOnlyObjects`,
          Effect: 'Allow',
          Action: ['s3:GetObject', 's3:GetObjectVersion'],
          Resource: `arn:aws:s3:::${bucket}/*`,
        },
        {
          Sid: `${team.name}ListBucketLimited`,
          Effect: 'Allow',
          Action: 's3:ListBucket',
          Resource: `arn:aws:s3:::${bucket}`,
          Condition: { NumericLessThanEquals: { 's3:max-keys': '1000' } },
        },
      ],
    },
    labels: [team.key],
  });

  pushBulk({
    id: `pol-${team.key}-kms`,
    name: `${team.name}-KMS-Usage`,
    kind: 'managed',
    description: `${team.name} 团队使用 SSE-KMS 加解密对象。`,
    document: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: `${team.name}KmsDataKeys`,
          Effect: 'Allow',
          Action: ['kms:GenerateDataKey', 'kms:Decrypt'],
          Resource: 'arn:aws:kms:*:*:key/*',
          Condition: {
            StringEquals: { 'aws:ResourceTag/team': team.tag },
          },
        },
      ],
    },
    labels: [team.key],
  });
}

/* --- compute policies --------------------------------------------- */

const INSTANCE_TABLES = {
  platform: 'ProdApp-*',
  backend: 'ProdApi-*',
  data: 'DataWorker-*',
  analytics: 'Analytics-*',
  media: 'MediaEncoder-*',
  security: 'Scanner-*',
  network: 'Bastion-*',
  support: 'SupportTool-*',
};

for (const [teamKey, namePattern] of Object.entries(INSTANCE_TABLES)) {
  const team = TEAMS.find((t) => t.key === teamKey);
  for (const op of ['describe', 'start-stop', 'reboot']) {
    const actions =
      op === 'describe'
        ? ['ec2:DescribeInstances', 'ec2:DescribeInstanceStatus', 'ec2:DescribeTags']
        : op === 'reboot'
          ? ['ec2:RebootInstances']
          : ['ec2:StartInstances', 'ec2:StopInstances'];
    pushBulk({
      id: `pol-ec2-${teamKey}-${op}`,
      name: `${team.name}-EC2-${op}`,
      kind: 'managed',
      description: `${team.name} 团队对 ${namePattern} 实例的 ${op} 权限。`,
      document: {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: `${team.name}Ec2${op.replace(/[^a-zA-Z]/g, '')}`,
            Effect: 'Allow',
            Action: actions,
            Resource: op === 'describe' ? '*' : `arn:aws:ec2:*:*:instance/${namePattern}`,
          },
        ],
      },
      labels: [teamKey],
    });
  }
}

/* --- condition variety -------------------------------------------- */

const CONDITION_VARIANTS = [
  {
    key: 'source-ip',
    name: 'Corp-IP-Restricted',
    description: '仅公司网段可用。',
    condition: { IpAddress: { 'aws:SourceIp': ['10.0.0.0/8', '172.16.0.0/12', '203.0.113.0/24'] } },
  },
  {
    key: 'require-mfa',
    name: 'Require-MFA',
    description: '要求多因素认证会话。',
    condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } },
  },
  {
    key: 'session-age',
    name: 'Fresh-Credentials',
    description: '要求登录时间足够新。',
    condition: { NumericLessThan: { 'aws:MultiFactorAuthAge': '3600' } },
  },
  {
    key: 'tls-only',
    name: 'TLS-Only',
    description: '只允许 TLS 通道。',
    condition: { Bool: { 'aws:SecureTransport': 'true' } },
  },
  {
    key: 'requested-region',
    name: 'Region-Pinned',
    description: '限制到指定区域。',
    condition: { StringEquals: { 'aws:RequestedRegion': ['cn-north-1', 'cn-northwest-1'] } },
  },
  {
    key: 'vpc-endpoint',
    name: 'VPCE-Only',
    description: '限制来源 VPC 终端节点。',
    condition: { StringEquals: { 'aws:SourceVpce': 'vpce-0example1111' } },
  },
];

const SERVICES = [
  { key: 'dynamodb', actions: ['dynamodb:GetItem', 'dynamodb:Query', 'dynamodb:PutItem', 'dynamodb:UpdateItem'], arn: 'arn:aws:dynamodb:*:*:table/*' },
  { key: 'sqs', actions: ['sqs:SendMessage', 'sqs:ReceiveMessage', 'sqs:DeleteMessage'], arn: 'arn:aws:sqs:*:*:*' },
  { key: 'sns', actions: ['sns:Publish', 'sns:Subscribe'], arn: 'arn:aws:sns:*:*:*' },
  { key: 'lambda', actions: ['lambda:InvokeFunction', 'lambda:GetFunction'], arn: 'arn:aws:lambda:*:*:function:*' },
  { key: 'ecs', actions: ['ecs:RunTask', 'ecs:DescribeTasks', 'ecs:UpdateService'], arn: 'arn:aws:ecs:*:*:*' },
  { key: 'eks', actions: ['eks:DescribeCluster', 'eks:ListNodegroups'], arn: 'arn:aws:eks:*:*:cluster/*' },
  { key: 'rds', actions: ['rds:DescribeDBInstances', 'rds:CreateDBSnapshot'], arn: 'arn:aws:rds:*:*:db:*' },
  { key: 'cloudwatch', actions: ['cloudwatch:GetMetricData', 'cloudwatch:PutMetricData', 'cloudwatch:ListMetrics'], arn: '*' },
  { key: 'logs', actions: ['logs:FilterLogEvents', 'logs:GetLogEvents', 'logs:DescribeLogGroups'], arn: 'arn:aws:logs:*:*:log-group:*' },
  { key: 'athena', actions: ['athena:StartQueryExecution', 'athena:GetQueryResults'], arn: 'arn:aws:athena:*:*:workgroup/*' },
  { key: 'glue', actions: ['glue:StartJobRun', 'glue:GetJobRun', 'glue:GetTable'], arn: 'arn:aws:glue:*:*:*' },
  { key: 'codebuild', actions: ['codebuild:StartBuild', 'codebuild:BatchGetBuilds'], arn: 'arn:aws:codebuild:*:*:project/*' },
  { key: 'secretsmanager', actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'], arn: 'arn:aws:secretsmanager:*:*:secret:*' },
  { key: 'ssm', actions: ['ssm:GetParameter', 'ssm:GetParameters'], arn: 'arn:aws:ssm:*:*:parameter/*' },
  { key: 'iam-read', actions: ['iam:GetUser', 'iam:ListUsers', 'iam:GetRole', 'iam:ListRoles'], arn: 'arn:aws:iam::*:*' },
];

for (const service of SERVICES) {
  for (const team of TEAMS) {
    const variant = CONDITION_VARIANTS[(TEAMS.indexOf(team) + SERVICES.indexOf(service)) % CONDITION_VARIANTS.length];
    pushBulk({
      id: `pol-${service.key}-${team.key}`,
      name: `${team.name}-${service.key}-With-${variant.name}`,
      kind: 'managed',
      description: `${team.name} 团队访问 ${service.key}，并附加条件：${variant.description}`,
      document: {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: `${team.name}${service.key.replace(/[^a-zA-Z]/g, '')}`,
            Effect: 'Allow',
            Action: service.actions,
            Resource: service.arn,
            Condition: variant.condition,
          },
        ],
      },
      labels: [team.key, service.key, 'conditional'],
    });
  }
}

/* --- NotAction / NotResource variety ------------------------------ */

pushBulk({
  id: 'pol-bulk-notaction-media',
  name: 'Media-Pipeline-NotAction',
  kind: 'managed',
  description: '媒体流水线读取所有媒体桶对象，排除写入与删除。',
  document: {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'MediaReadEverythingElse',
        Effect: 'Allow',
        NotAction: ['s3:PutObject', 's3:DeleteObject'],
        Resource: ['arn:aws:s3:::prod-media-originals', 'arn:aws:s3:::prod-media-originals/*'],
      },
    ],
  },
  labels: ['media', 'notaction'],
});

pushBulk({
  id: 'pol-bulk-notresource-support',
  name: 'Support-NotResource-Backups',
  kind: 'managed',
  description: '支持团队可读共享桶，但排除备份金库。',
  document: {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'SharedExceptBackupVault',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:ListBucket'],
        NotResource: ['arn:aws:s3:::shared-backup-vault', 'arn:aws:s3:::shared-backup-vault/*'],
      },
    ],
  },
  labels: ['support', 'notresource'],
});

/* --- intentionally over-broad "convenience" policies ------------ */

pushBulk({
  id: 'pol-bulk-admin-convenience',
  name: 'Ops-Convenience-AllBuckets',
  kind: 'managed',
  description: '运维便利策略：全部桶全部对象操作（未加任何条件）。',
  document: {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AllBucketsAllObjects',
        Effect: 'Allow',
        Action: 's3:*',
        Resource: ['arn:aws:s3:::*', 'arn:aws:s3:::*/*'],
      },
    ],
  },
  labels: ['ops', 'over-broad'],
});

pushBulk({
  id: 'pol-bulk-assume-any-role',
  name: 'Assume-Any-Role',
  kind: 'managed',
  description: '本意是"允许进入运维角色"，资源却写成同账号任意角色（陷阱 4 的变体）。',
  document: {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AssumeOpsRoles',
        Effect: 'Allow',
        Action: 'sts:AssumeRole',
        Resource: 'arn:aws:iam::111122223333:role/*',
      },
    ],
  },
  labels: ['ops', 'trap'],
});

pushBulk({
  id: 'pol-bulk-mfa-exists',
  name: 'MFA-IfExists',
  kind: 'managed',
  description: '要求 MFA，但用了 BoolIfExists：键缺失时条件为真，等于没要求（陷阱 7）。',
  document: {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DeleteObjectsWithMfa',
        Effect: 'Allow',
        Action: 's3:DeleteObject',
        Resource: 'arn:aws:s3:::prod-customer-exports/*',
        Condition: { BoolIfExists: { 'aws:MultiFactorAuthPresent': 'true' } },
      },
    ],
  },
  labels: ['trap'],
});

pushBulk({
  id: 'pol-bulk-stringlike-prefix',
  name: 'Prefix-StringLike',
  kind: 'managed',
  description: '用 StringLike 匹配键名前缀，但缺少结尾通配的约束，任意包含该子串的值都命中。',
  document: {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AdminTagLike',
        Effect: 'Allow',
        Action: 'iam:*',
        Resource: 'arn:aws:iam::*:user/*',
        Condition: { StringLike: { 'aws:PrincipalTag/role': 'admin*' } },
      },
    ],
  },
  labels: ['trap', 'conditional'],
});

pushBulk({
  id: 'pol-bulk-deny-notresource',
  name: 'Deny-Except-Home',
  kind: 'managed',
  description: '拒绝所有用户的 IAM 写操作，仅保留自己账号下的自助操作；NotResource 里同时有变量与通配。',
  document: {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'DenyOtherUsersIam',
        Effect: 'Deny',
        Action: ['iam:CreateAccessKey', 'iam:UpdateAccessKey', 'iam:DeleteAccessKey'],
        NotResource: 'arn:aws:iam::111122223333:user/${aws:username}',
      },
    ],
  },
  labels: ['guardrail'],
});

/* --- bulk guardrail denies ---------------------------------------- */

for (let i = 0; i < 24; i += 1) {
  const bucket = BUCKETS[i % BUCKETS.length];
  pushBulk({
    id: `pol-bulk-deny-public-acl-${i}`,
    name: `Guardrail-NoPublicAcl-${bucket}`,
    kind: 'managed',
    description: `禁止在 ${bucket} 上写入公开 ACL。`,
    document: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: `NoPublicAcl${i}`,
          Effect: 'Deny',
          Action: ['s3:PutBucketAcl', 's3:PutObjectAcl'],
          Resource: [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`],
          Condition: { StringEquals: { 's3:x-amz-acl': 'public-read' } },
        },
      ],
    },
    labels: ['guardrail'],
  });
}

/* --- bulk read-only reporting policies ---------------------------- */

for (let i = 0; i < 30; i += 1) {
  const service = SERVICES[i % SERVICES.length];
  const team = TEAMS[(i * 3) % TEAMS.length];
  pushBulk({
    id: `pol-bulk-report-${i}`,
    name: `${team.name}-Report-${service.key}-${i}`,
    kind: 'managed',
    description: `报表只读：${service.key} 的只读动作，带会话新鲜度条件。`,
    document: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: `Report${i}`,
          Effect: 'Allow',
          Action: service.actions.slice(0, 2),
          Resource: service.arn,
          Condition: {
            NumericLessThan: { 'aws:MultiFactorAuthAge': String(1800 + i * 60) },
          },
        },
      ],
    },
    labels: [team.key, 'reporting'],
  });
}

/* ------------------------------------------------------------------ */
/* Organization structure                                              */
/* ------------------------------------------------------------------ */

const orgUnits = [
  { id: 'ou-root', name: 'ExampleCorp (根)', parentId: null, scpPolicyIds: ['scp-root-full-access'] },
  {
    id: 'ou-prod',
    name: 'Production',
    parentId: 'ou-root',
    scpPolicyIds: ['scp-prod-full-access', 'scp-prod-guardrails'],
  },
  {
    id: 'ou-dev',
    name: 'Development',
    parentId: 'ou-root',
    scpPolicyIds: ['scp-dev-full-access', 'scp-dev-open'],
  },
  {
    id: 'ou-shared',
    name: 'SharedServices',
    parentId: 'ou-root',
    scpPolicyIds: ['scp-shared-full-access', 'scp-shared-guardrails'],
  },
];

const accounts = [
  {
    id: PROD,
    name: 'prod-workloads',
    orgUnitId: 'ou-prod',
    scpPolicyIds: ['scp-account-full-access'],
    description: '生产工作负载账号，承载支付归档与客户数据导出。',
  },
  {
    id: DEV,
    name: 'dev-workloads',
    orgUnitId: 'ou-dev',
    scpPolicyIds: ['scp-account-full-access'],
    description: '开发与集成账号，允许较宽松的实验权限。',
  },
  {
    id: SHARED,
    name: 'shared-services',
    orgUnitId: 'ou-shared',
    scpPolicyIds: ['scp-account-full-access'],
    description: '共享服务账号：审计日志、工具链与备份。',
  },
  {
    id: '999900001111',
    name: 'external-auditor',
    orgUnitId: 'ou-root',
    scpPolicyIds: ['scp-account-full-access'],
    description: '外部审计方账号，仅通过审计日志桶的资源策略获得只读权限。',
  },
];

/* ------------------------------------------------------------------ */
/* Groups                                                             */
/* ------------------------------------------------------------------ */

const group = (id, name, accountId, managedPolicyIds, tags = {}) => {
  const record = {
    id,
    name,
    arn: `arn:aws:iam::${accountId}:group/${name}`,
    managedPolicyIds,
    inlinePolicyIds: [],
    description: `${name} 组`,
    tags,
  };
  groups.push(record);
  return record.id;
};

const gPlatform = group('grp-platform-ops', 'PlatformOps', PROD, [
  'pol-prod-platform-admin',
  'pol-platform-s3-rw',
  'pol-ec2-platform-describe',
  'pol-ec2-platform-reboot',
  'pol-ec2-platform-start-stop',
], { team: 'platform-ops' });
const gStorage = group('grp-storage', 'StorageTeam', PROD, [
  'pol-prod-storage-team',
  'pol-storage-s3-rw',
  'pol-storage-kms',
], { team: 'storage' });
const gAudit = group('grp-audit', 'AuditTeam', PROD, [
  'pol-prod-auditor',
  'pol-security-s3-ro',
], { team: 'security' });
const gDeploy = group('grp-deploy', 'DeployTeam', PROD, [
  'pol-prod-deployer',
  'pol-prod-cicd',
  'pol-support-s3-ro',
], { team: 'cicd' });
const gData = group('grp-dataeng', 'DataEngineering', PROD, [
  'pol-prod-dataeng',
  'pol-data-s3-rw',
  'pol-data-kms',
  'pol-prod-tagged-upload',
], { team: 'data-eng' });
const gFinops = group('grp-finops', 'FinOps', PROD, ['pol-prod-finops'], { team: 'finops' });
const gDevelopers = group('grp-developers', 'Developers', DEV, [
  'pol-dev-standard',
  'pol-dev-devops',
  'pol-backend-s3-rw',
  'pol-dev-contractor',
], { team: 'devops' });
const gContractors = group('grp-contractors', 'Contractors', DEV, ['pol-dev-contractor'], { team: 'external' });
const gShared = group('grp-shared-ops', 'SharedOps', SHARED, [
  'pol-shared-support',
  'pol-shared-readonly-notaction',
  'pol-support-s3-ro',
], { team: 'support' });
const gNetwork = group('grp-network', 'NetworkTeam', PROD, [
  'pol-network-s3-ro',
  'pol-prod-ip-restricted',
  'pol-ec2-network-start-stop',
], { team: 'network' });
const gBackend = group('grp-backend', 'Backend', DEV, [
  'pol-backend-s3-rw',
  'pol-backend-kms',
  'pol-ec2-backend-start-stop',
], { team: 'backend' });
const gAnalytics = group('grp-analytics', 'Analytics', PROD, [
  'pol-analytics-s3-rw',
  'pol-analytics-kms',
  'pol-ec2-analytics-reboot',
], { team: 'analytics' });
const gMedia = group('grp-media', 'MediaPipeline', PROD, [
  'pol-media-s3-rw',
  'pol-media-kms',
  'pol-bulk-notaction-media',
], { team: 'media' });

/* ------------------------------------------------------------------ */
/* Users                                                              */
/* ------------------------------------------------------------------ */

const user = (id, name, accountId, groupIds, extras = {}) => {
  users.push({
    id,
    name,
    arn: `arn:aws:iam::${accountId}:user/${name}`,
    accountId,
    groupIds,
    managedPolicyIds: extras.managedPolicyIds ?? [],
    inlinePolicyIds: extras.inlinePolicyIds ?? [],
    boundaryPolicyId: extras.boundaryPolicyId ?? null,
    tags: extras.tags ?? {},
    description: extras.description,
  });
};

user('usr-platform-lead', 'platform-lead', PROD, [gPlatform], {
  boundaryPolicyId: 'pol-boundary-admin',
  tags: { team: 'platform-ops', role: 'admin' },
  description: '平台组负责人，生产环境广域权限但受管理员边界约束。',
});
user('usr-platform-oncall', 'platform-oncall', PROD, [gPlatform], {
  boundaryPolicyId: 'pol-boundary-admin',
  tags: { team: 'platform-ops', oncall: 'true' },
  description: '平台值班人；同时是紧急通道角色的信任主体。',
});
user('usr-platform-engineer', 'platform-engineer', PROD, [gPlatform], {
  boundaryPolicyId: 'pol-boundary-standard',
  tags: { team: 'platform-ops' },
});
user('usr-storage-lead', 'storage-lead', PROD, [gStorage], {
  boundaryPolicyId: 'pol-boundary-admin',
  tags: { team: 'storage' },
  description: '存储团队负责人，策略看似可删桶，但被标准边界拦住。',
});
user('usr-storage-engineer', 'storage-engineer', PROD, [gStorage], {
  boundaryPolicyId: 'pol-boundary-readonly',
  tags: { team: 'storage' },
  description: '存储工程师：身份策略给了 s3:*，边界却只允许读。',
});
user('usr-auditor', 'external-auditor', PROD, [gAudit], {
  boundaryPolicyId: 'pol-boundary-readonly',
  tags: { team: 'security' },
});
user('usr-deployer', 'deployer-bot', PROD, [gDeploy], {
  boundaryPolicyId: 'pol-boundary-admin',
  tags: { team: 'cicd' },
  description:
    '发布机器人（长期用户，实际生产中应用角色，此处用于对比）。它带有账号通配的 AssumeRole 授权，演示跨账号扮演风险。',
});
user('usr-dataeng', 'dataeng-lead', PROD, [gData], {
  boundaryPolicyId: 'pol-boundary-admin',
  tags: { team: 'data-eng' },
});
user('usr-finops', 'finops-analyst', PROD, [gFinops], {
  boundaryPolicyId: 'pol-boundary-readonly',
  tags: { team: 'finops' },
});
user('usr-dev', 'dev-engineer', DEV, [gDevelopers], {
  tags: { team: 'devops' },
  description: '无边界约束，开发账号权限全开。',
});
user('usr-contractor', 'contractor-1', DEV, [gContractors], {
  boundaryPolicyId: 'pol-boundary-readonly',
  tags: { team: 'external' },
});
user('usr-shared-ops', 'shared-ops', SHARED, [gShared], {
  boundaryPolicyId: 'pol-boundary-standard',
  tags: { team: 'support' },
});
user('usr-network', 'network-engineer', PROD, [gNetwork], {
  boundaryPolicyId: 'pol-boundary-standard',
  tags: { team: 'network' },
});
user('usr-backend', 'backend-engineer', DEV, [gBackend], {
  tags: { team: 'backend' },
});
user('usr-analytics', 'analytics-eng', PROD, [gAnalytics], {
  boundaryPolicyId: 'pol-boundary-admin',
  tags: { team: 'analytics' },
});
user('usr-media', 'media-eng', PROD, [gMedia], {
  boundaryPolicyId: 'pol-boundary-standard',
  tags: { team: 'media' },
});
user('usr-security-oncall', 'security-oncall', PROD, [], {
  managedPolicyIds: ['pol-inline-security-readonly'],
  inlinePolicyIds: ['pol-inline-security-readonly'],
  boundaryPolicyId: 'pol-boundary-readonly',
  tags: { team: 'security', oncall: 'true', role: 'admin' },
  description: '安全值班人，紧急通道的信任主体。',
});
user('usr-intern', 'dev-intern', PROD, [], {
  managedPolicyIds: ['pol-prod-intern', 'pol-bulk-assume-any-role'],
  boundaryPolicyId: 'pol-boundary-readonly',
  tags: { team: 'intern' },
  description: '实习生：只读权限，但顺手被加了一条 assume-any-role（陷阱演示）。',
});

put({
  id: 'pol-inline-security-readonly',
  name: 'Security-Oncall-Inline',
  kind: 'inline',
  description: '安全值班人的内联策略：审计日志与 CloudTrail 查询。',
  document: {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'SecurityOncallRead',
        Effect: 'Allow',
        Action: ['logs:FilterLogEvents', 'logs:GetLogEvents', 'cloudtrail:LookupEvents', 's3:GetObject', 's3:ListBucket'],
        Resource: ['arn:aws:logs:*:*:log-group:*', 'arn:aws:cloudtrail:*:*:trail/*', 'arn:aws:s3:::shared-audit-logs', 'arn:aws:s3:::shared-audit-logs/*'],
      },
      {
        Sid: 'SecurityOncallSecrets',
        Effect: 'Allow',
        Action: 'secretsmanager:GetSecretValue',
        Resource: 'arn:aws:secretsmanager:*:*:secret:*',
        Condition: { StringEquals: { 'aws:PrincipalTag/oncall': 'true' } },
      },
    ],
  },
});

/* ------------------------------------------------------------------ */
/* Roles                                                              */
/* ------------------------------------------------------------------ */

const role = (id, name, accountId, trustPolicyId, managedPolicyIds, extras = {}) => {
  roles.push({
    id,
    name,
    arn: `arn:aws:iam::${accountId}:role/${name}`,
    accountId,
    trustPolicyId,
    managedPolicyIds,
    inlinePolicyIds: extras.inlinePolicyIds ?? [],
    boundaryPolicyId: extras.boundaryPolicyId ?? null,
    tags: extras.tags ?? {},
    description: extras.description,
  });
};

role('role-prod-deployer', 'ProdDeployer', PROD, 'trust-prod-deployer', ['pol-prod-deployer', 'pol-prod-cicd'], {
  boundaryPolicyId: 'pol-boundary-cicd',
  tags: { team: 'cicd' },
  description: '生产发布角色；信任策略里对开发账号挂了一条很难满足的 PrincipalTag 条件。',
});
role('role-prod-breakglass', 'ProdBreakGlass', PROD, 'trust-prod-breakglass', ['pol-prod-breakglass'], {
  boundaryPolicyId: 'pol-boundary-admin',
  tags: { team: 'platform-ops', breakglass: 'true' },
  description: '紧急通道：广域 S3/EC2 权限，禁止写支付归档。',
});
role('role-prod-storage-admin', 'StorageAdmin', PROD, 'trust-prod-deployer', [
  'pol-prod-storage-team',
  'pol-storage-s3-rw',
  'pol-bulk-admin-convenience',
], {
  boundaryPolicyId: 'pol-boundary-admin',
  tags: { team: 'storage' },
  description: '存储管理员角色：附带了一条"便利"全桶策略，边界却不拦 production-*。',
});
role('role-dev-proddeployer', 'ProdDeployer', DEV, 'trust-dev-proddeployer-name-collision', [], {
  tags: { team: 'devops' },
  description:
    '与生产账号同名的角色，用于演示账号字段通配带来的跨账号扮演风险（陷阱 4 的落点）。',
});
role('role-prod-cicd-runner', 'CICDRunner', PROD, 'trust-prod-deployer', ['pol-prod-cicd', 'pol-bulk-assume-any-role'], {
  boundaryPolicyId: 'pol-boundary-cicd',
  tags: { team: 'cicd' },
});
role('role-dev-deployer', 'DevDeployer', DEV, 'trust-dev-deployer', ['pol-dev-standard'], {
  tags: { team: 'devops' },
  description: '开发发布角色，无权限边界。',
});
role('role-shared-ops', 'SharedOpsRole', SHARED, 'trust-shared-ops', ['pol-shared-support', 'pol-shared-readonly-notaction'], {
  boundaryPolicyId: 'pol-boundary-standard',
  tags: { team: 'support' },
});
role('role-prod-dataeng', 'DataEngWorker', PROD, 'trust-prod-deployer', ['pol-prod-dataeng', 'pol-bulk-assume-any-role'], {
  boundaryPolicyId: 'pol-boundary-admin',
  tags: { team: 'data-eng' },
});
role('role-prod-audit', 'ExternalAuditReader', PROD, 'trust-shared-ops', ['pol-prod-auditor'], {
  boundaryPolicyId: 'pol-boundary-readonly',
  tags: { team: 'security' },
});
role('role-prod-mfa-delete', 'DeletionWorker', PROD, 'trust-prod-deployer', ['pol-bulk-mfa-exists', 'pol-prod-storage-team'], {
  boundaryPolicyId: 'pol-boundary-standard',
  tags: { team: 'storage' },
  description: '删除机器人：策略写着"要求 MFA"，实际用的是 BoolIfExists。',
});
role('role-shared-tooling', 'ToolingMaintainer', SHARED, 'trust-shared-ops', ['pol-shared-support', 'pol-bulk-stringlike-prefix'], {
  boundaryPolicyId: 'pol-boundary-standard',
  tags: { team: 'support', role: 'admin' },
});
role('role-prod-network', 'NetworkAutomation', PROD, 'trust-prod-deployer', ['pol-network-s3-ro', 'pol-ec2-network-describe'], {
  boundaryPolicyId: 'pol-boundary-readonly',
  tags: { team: 'network' },
});
role('role-prod-media', 'MediaTranscoder', PROD, 'trust-prod-deployer', ['pol-media-s3-rw', 'pol-bulk-notaction-media'], {
  boundaryPolicyId: 'pol-boundary-admin',
  tags: { team: 'media' },
});
role('role-prod-finops', 'CostReporter', PROD, 'trust-prod-deployer', ['pol-prod-finops', 'pol-bulk-report-2'], {
  boundaryPolicyId: 'pol-boundary-readonly',
  tags: { team: 'finops' },
});

/* ------------------------------------------------------------------ */
/* Attach the bulk corpus to team groups                               */
/* ------------------------------------------------------------------ */

// Each team key maps to the group(s) that should carry its generated policies.
const TEAM_GROUP_MAP = {
  platform: [gPlatform],
  storage: [gStorage],
  data: [gData],
  analytics: [gAnalytics],
  media: [gMedia],
  finops: [gFinops],
  support: [gShared],
  security: [gAudit],
  network: [gNetwork],
  backend: [gBackend],
  cicd: [gDeploy],
};

for (const policyRecord of BULK) {
  const teamKeys = (policyRecord.labels ?? []).filter((label) => label in TEAM_GROUP_MAP);
  for (const key of teamKeys) {
    for (const groupId of TEAM_GROUP_MAP[key]) {
      const target = groups.find((candidate) => candidate.id === groupId);
      if (target && !target.managedPolicyIds.includes(policyRecord.id)) {
        target.managedPolicyIds.push(policyRecord.id);
      }
    }
  }
}

// Guardrail policies are attached broadly to every human group.
for (const policyRecord of BULK) {
  if (!(policyRecord.labels ?? []).includes('guardrail')) continue;
  for (const target of groups) {
    if (!target.managedPolicyIds.includes(policyRecord.id)) {
      target.managedPolicyIds.push(policyRecord.id);
    }
  }
}

// Secrets policies go to the platform and data teams.
for (const groupId of [gPlatform, gData]) {
  groups.find((g) => g.id === groupId)?.managedPolicyIds.push('pol-prod-secrets-read');
}

// Reporting policies carry a team label too; make sure they land somewhere even
// when the label maps to a team without a dedicated group.
for (const policyRecord of BULK) {
  if (!(policyRecord.labels ?? []).includes('reporting')) continue;
  const alreadyAttached = groups.some((candidate) => candidate.managedPolicyIds.includes(policyRecord.id));
  if (!alreadyAttached) gFinops && groups.find((g) => g.id === gFinops)?.managedPolicyIds.push(policyRecord.id);
}

/* ------------------------------------------------------------------ */
/* Resources                                                          */
/* ------------------------------------------------------------------ */

const resource = (arn, name, accountId, type, tags, description) => {
  resources.push({ arn, name, accountId, type, tags, description });
};

for (const bucket of BUCKETS) {
  const accountId =
    bucket.startsWith('dev-') ? DEV : bucket.startsWith('shared-') ? SHARED : PROD;
  const classification = bucket.includes('payments')
    ? 'restricted'
    : bucket.includes('audit')
      ? 'confidential'
      : bucket.includes('customer')
        ? 'confidential'
        : bucket.includes('backup')
          ? 'restricted'
          : 'internal';
  resource(`arn:aws:s3:::${bucket}`, bucket, accountId, 'bucket', {
    team: TEAMS[BUCKETS.indexOf(bucket) % TEAMS.length].tag,
    classification,
    environment: accountId === PROD ? 'prod' : accountId === DEV ? 'dev' : 'shared',
  }, `S3 存储桶 ${bucket}`);
}

resource(
  'arn:aws:s3:::production-payments-archive/2026/11/settlement-batch-0042.parquet',
  'settlement-batch-0042.parquet',
  PROD,
  'object',
  { classification: 'restricted', team: 'data-eng', environment: 'prod' },
  '支付归档中的一个结算批次对象——安全团队最关心的资源。',
);
resource(
  'arn:aws:s3:::prod-artifacts-build/releases/api-1.24.0.tar.gz',
  'api-1.24.0.tar.gz',
  PROD,
  'object',
  { classification: 'internal', team: 'cicd', environment: 'prod' },
  '一次发布产物。',
);
resource(
  'arn:aws:secretsmanager:cn-north-1:111122223333:secret:prod/payments/db-password',
  'prod/payments/db-password',
  PROD,
  'secret',
  { team: 'platform-ops', classification: 'restricted' },
  '生产支付库口令。',
);
resource(
  'arn:aws:kms:cn-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
  'payments-cmk',
  PROD,
  'kms-key',
  { team: 'storage', classification: 'restricted' },
  '支付归档使用的客户主密钥。',
);

/* ------------------------------------------------------------------ */
/* Dataset                                                            */
/* ------------------------------------------------------------------ */

const dataset = {
  meta: {
    name: '示例云账号策略集（中等规模）',
    generatedAt: GEN_AT,
    description:
      '一个包含 4 个账号、3 个 OU、约 100 条策略、20 个身份与若干资源策略的合成数据集，用于演示 IAM 策略求值。账号与资源均为虚构。',
  },
  org: { id: ORG, name: 'ExampleCorp' },
  accounts,
  orgUnits,
  policies,
  users,
  groups,
  roles,
  resourcePolicies,
  resources,
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(dataset, null, 2)}\n`, 'utf8');

const statementCount = policies.reduce((sum, p) => {
  const list = Array.isArray(p.document.Statement) ? p.document.Statement : [p.document.Statement];
  return sum + list.length;
}, 0);
console.log(
  `wrote ${outPath}\n  policies=${policies.length} statements=${statementCount} users=${users.length} roles=${roles.length} resources=${resources.length} resourcePolicies=${resourcePolicies.length}`,
);
