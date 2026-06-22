export const releasePrerequisiteCiRuns = [
  {
    name: 'devops-integration',
    repository: 'deep-devops',
    workflow: 'integration.yml',
    artifacts: ['integration-artifacts']
  },
  {
    name: 'devops-nightly-full-e2e',
    repository: 'deep-devops',
    workflow: 'nightly-full-e2e.yml',
    artifacts: ['nightly-e2e-artifacts']
  },
  {
    name: 'devops-security-gate',
    repository: 'deep-devops',
    workflow: 'unit.yml',
    artifacts: ['security-gate-artifacts']
  },
  {
    name: 'devops-release-gate-contracts',
    repository: 'deep-devops',
    workflow: 'unit.yml',
    artifacts: ['release-gate-contract-artifacts']
  },
  {
    name: 'devops-release-secret-preflight',
    repository: 'deep-devops',
    workflow: 'release-secret-preflight.yml',
    artifacts: ['release-secret-preflight-artifacts']
  },
  {
    name: 'xnode-c3',
    repository: 'xnode',
    workflow: 'ci.yml',
    artifacts: ['c3-test-results']
  },
  {
    name: 'client-maui-platform-matrix',
    repository: 'deep-client-maui',
    workflow: 'ci.yml',
    artifacts: ['deep-client-maui-platform-matrix']
  }
];

export const productionReadinessCiRun = {
  name: 'devops-production-readiness',
  repository: 'deep-devops',
  workflow: 'production-readiness.yml',
  artifacts: ['production-readiness-artifacts']
};

export const postReadinessCiRuns = [
  ...releasePrerequisiteCiRuns,
  productionReadinessCiRun
];

export const requiredCiRuns = releasePrerequisiteCiRuns;
