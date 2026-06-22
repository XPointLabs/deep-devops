import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const devopsRoot = path.resolve(__dirname, '..');
const workspaceRoot = path.resolve(devopsRoot, '..');
const artifactRoot = process.env.DEEP_RELEASE_ARTIFACT_ROOT
  ? path.resolve(process.env.DEEP_RELEASE_ARTIFACT_ROOT)
  : path.join(devopsRoot, 'artifacts');
const outputDir = path.join(artifactRoot, 'observability');
const outputPath = path.join(outputDir, 'observability-gate-summary.json');
const sloPath = process.env.DEEP_OBSERVABILITY_SLO_CONFIG
  ? path.resolve(process.env.DEEP_OBSERVABILITY_SLO_CONFIG)
  : path.join(devopsRoot, 'observability', 'deep-messenger-slos.json');
const dashboardPath = process.env.DEEP_OBSERVABILITY_DASHBOARD
  ? path.resolve(process.env.DEEP_OBSERVABILITY_DASHBOARD)
  : path.join(devopsRoot, 'observability', 'deep-messenger-dashboard.json');
const alertRoutesPath = process.env.DEEP_OBSERVABILITY_ALERT_ROUTES
  ? path.resolve(process.env.DEEP_OBSERVABILITY_ALERT_ROUTES)
  : path.join(devopsRoot, 'observability', 'deep-alert-routes.json');

const checks = [];

function addCheck(name, passed, details = {}) {
  checks.push({ name, passed: Boolean(passed), ...details });
}

function get(value, pathExpression) {
  return pathExpression.split('.').reduce((current, key) => current?.[key], value);
}

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJson(label, filePath) {
  const absolutePath = path.resolve(filePath);
  if (!await fileExists(absolutePath)) {
    addCheck(`${label}:exists`, false, { path: absolutePath });
    return null;
  }

  try {
    const raw = await readFile(absolutePath, 'utf8');
    const parsed = JSON.parse(raw.replace(/^\uFEFF/, ''));
    addCheck(`${label}:exists`, true, { path: absolutePath });
    return parsed;
  } catch (error) {
    addCheck(`${label}:parse`, false, { path: absolutePath, error: error.message });
    return null;
  }
}

function checkErrorCounter(label, stats, budget) {
  const errors = stats?.stats?.errors;
  addCheck(label, typeof errors === 'number' && errors <= budget, {
    observed: errors,
    target: `<= ${budget}`
  });
}

function findSnapshot(runtimeSnapshot, name) {
  return runtimeSnapshot?.snapshots?.find?.(snapshot => snapshot.name === name);
}

function checkRuntimeSnapshot(runtimeSnapshot) {
  if (!runtimeSnapshot) {
    return;
  }

  const snapshots = Array.isArray(runtimeSnapshot.snapshots) ? runtimeSnapshot.snapshots : [];
  addCheck('runtime-snapshot:has-snapshots', snapshots.length > 0, { observed: snapshots.length });
  addCheck('runtime-snapshot:all-ok', snapshots.length > 0 && snapshots.every(snapshot => snapshot.ok === true), {
    failed: snapshots.filter(snapshot => snapshot.ok !== true).map(snapshot => snapshot.name)
  });

  const router = findSnapshot(runtimeSnapshot, 'router-health-ready');
  addCheck('runtime-snapshot:router-ready', router?.ok === true && (router.body?.ready === true || router.body?.status === 'Healthy'), {
    observed: router?.body ?? null
  });
  addCheck('runtime-snapshot:router-not-mocked', router?.body?.transportMode !== 'mocked', {
    observed: router?.body?.transportMode ?? null
  });

  for (const name of ['storage-external-stats', 'file-external-stats', 'push-external-stats']) {
    const snapshot = findSnapshot(runtimeSnapshot, name);
    addCheck(`runtime-snapshot:${name}:present`, snapshot?.ok === true, {
      observed: snapshot?.ok ?? null
    });
  }
}

function checkTimingBudgets(loadSmoke, timingBudgets) {
  if (!loadSmoke || !timingBudgets) {
    return;
  }

  for (const [metric, budget] of Object.entries(timingBudgets)) {
    const p95 = loadSmoke.timings?.[metric]?.p95Ms;
    addCheck(`timing:${metric}:p95-budget`, typeof p95 === 'number' && p95 <= budget, {
      observed: p95,
      target: `<= ${budget} ms`
    });
  }
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function checkDashboard(dashboard) {
  if (!dashboard) {
    return;
  }

  const panels = Array.isArray(dashboard.panels) ? dashboard.panels : [];
  addCheck('dashboard:title-present', hasText(dashboard.title), { observed: dashboard.title ?? null });
  addCheck('dashboard:uid-present', hasText(dashboard.uid), { observed: dashboard.uid ?? null });
  addCheck('dashboard:panels-minimum', panels.length >= 5, { observed: panels.length, target: '>= 5' });

  const requiredTitles = [
    'Service Error Counters',
    'Messenger Operation P95 Latency',
    'Push Provider Delivery Health',
    'Router Runtime Transport',
    'Release Rollback MTTR'
  ];
  for (const title of requiredTitles) {
    const panel = panels.find(entry => entry.title === title);
    addCheck(`dashboard:panel:${title}`, Boolean(panel), { observed: Boolean(panel) });
    if (panel) {
      const targets = Array.isArray(panel.targets) ? panel.targets : [];
      addCheck(`dashboard:panel:${title}:targets`, targets.length > 0 && targets.every(target => hasText(target.expr)), {
        observed: targets.length,
        target: '> 0 expressions'
      });
    }
  }
}

function checkAlertRoutes(alertRoutes, sloConfig) {
  if (!alertRoutes) {
    return;
  }

  const routes = Array.isArray(alertRoutes.routes) ? alertRoutes.routes : [];
  const routeSeverities = new Set(routes.map(route => route.severity));
  const routedAlerts = new Set(routes.flatMap(route => Array.isArray(route.alerts) ? route.alerts : []));
  const requiredAlerts = Array.isArray(sloConfig?.alertRules) ? sloConfig.alertRules.map(rule => rule.name) : [];

  addCheck('alert-routes:version', alertRoutes.version === 1, { observed: alertRoutes.version });
  addCheck('alert-routes:default-receiver', hasText(alertRoutes.defaultReceiver), {
    observed: alertRoutes.defaultReceiver ?? null
  });
  addCheck('alert-routes:critical-route', routeSeverities.has('critical'), { observed: [...routeSeverities] });
  addCheck('alert-routes:warning-route', routeSeverities.has('warning'), { observed: [...routeSeverities] });
  for (const alertName of requiredAlerts) {
    addCheck(`alert-routes:covers:${alertName}`, routedAlerts.has(alertName), {
      observed: routedAlerts.has(alertName)
    });
  }
}

const sloConfig = await readJson('slo-config', sloPath);
if (sloConfig) {
  addCheck('slo-config:version', sloConfig.version === 1, { observed: sloConfig.version });
  addCheck('slo-config:alert-rules-present', Array.isArray(sloConfig.alertRules) && sloConfig.alertRules.length >= 4, {
    observed: sloConfig.alertRules?.length ?? null,
    target: '>= 4'
  });
}

const dashboard = await readJson('dashboard', dashboardPath);
checkDashboard(dashboard);

const alertRoutes = await readJson('alert-routes', alertRoutesPath);
checkAlertRoutes(alertRoutes, sloConfig);

const runtimeSnapshot = await readJson('runtime-snapshot', path.join(artifactRoot, 'runtime.snapshot.json'));
checkRuntimeSnapshot(runtimeSnapshot);

const loadSmoke = await readJson('backend-load-smoke', path.join(artifactRoot, 'test-results', 'backend-load-smoke.json'));
if (loadSmoke) {
  checkTimingBudgets(loadSmoke, sloConfig?.budgets?.timingP95Ms);
  const errorBudget = sloConfig?.budgets?.errorCounters ?? 0;
  checkErrorCounter('load:storage-errors-budget', loadSmoke.statsAfter?.storage, errorBudget);
  checkErrorCounter('load:file-errors-budget', loadSmoke.statsAfter?.file, errorBudget);
  checkErrorCounter('load:push-errors-budget', loadSmoke.statsAfter?.push, errorBudget);
}

const restartSmoke = await readJson('backend-restart-smoke', path.join(artifactRoot, 'test-results', 'backend-restart-smoke.json'));
if (restartSmoke) {
  const errorBudget = sloConfig?.budgets?.errorCounters ?? 0;
  addCheck('restart:status-ok', restartSmoke.status === 'ok', { observed: restartSmoke.status });
  checkErrorCounter('restart:storage-errors-budget', restartSmoke.statsAfterRehearsal?.storage, errorBudget);
  checkErrorCounter('restart:file-errors-budget', restartSmoke.statsAfterRehearsal?.file, errorBudget);
  checkErrorCounter('restart:push-errors-budget', restartSmoke.statsAfterRehearsal?.push, errorBudget);
}

const pushCanary = await readJson('push-provider-canary', path.join(artifactRoot, 'test-results', 'push-provider-canary.json'));
if (pushCanary) {
  addCheck('push-canary:provider-delivered', pushCanary.provider?.status === 'delivered', {
    observed: pushCanary.provider?.status
  });
  addCheck('push-canary:provider-failures-budget', (pushCanary.statsAfterDelivery?.inventory?.pushProviderFailed ?? 0) === 0, {
    observed: pushCanary.statsAfterDelivery?.inventory?.pushProviderFailed ?? null,
    target: 0
  });
}

const routerC3Path = process.env.XNODE_C3_ARTIFACT
  ? path.resolve(process.env.XNODE_C3_ARTIFACT)
  : path.join(workspaceRoot, 'xnode', 'artifacts', 'test-results', 'c3', 'latest.json');
const routerC3 = await readJson('router-c3', routerC3Path);
if (routerC3) {
  const routerBudgets = sloConfig?.budgets?.router ?? {};
  addCheck('router-c3:slo-baseline-passed', routerC3.sloBaseline?.passed === true, { observed: routerC3.sloBaseline?.passed });
  addCheck('router-c3:soak-success-rate-budget', routerC3.soak?.successRate >= (routerBudgets.soakSuccessRate ?? 0.99), {
    observed: routerC3.soak?.successRate,
    target: `>= ${routerBudgets.soakSuccessRate ?? 0.99}`
  });
  addCheck('router-c3:chaos-success-rate-budget', routerC3.chaos?.successRate >= (routerBudgets.chaosSuccessRate ?? 0.55), {
    observed: routerC3.chaos?.successRate,
    target: `>= ${routerBudgets.chaosSuccessRate ?? 0.55}`
  });
  addCheck('router-c3:load-success-rate-budget', routerC3.load?.successRate >= (routerBudgets.loadSuccessRate ?? 0.99), {
    observed: routerC3.load?.successRate,
    target: `>= ${routerBudgets.loadSuccessRate ?? 0.99}`
  });
  addCheck('router-c3:path-select-p95-budget', routerC3.load?.latencyP95Ms <= (routerBudgets.pathSelectP95Ms ?? 15), {
    observed: routerC3.load?.latencyP95Ms,
    target: `<= ${routerBudgets.pathSelectP95Ms ?? 15} ms`
  });
}

const rollback = await readJson('rollback-drill', path.join(artifactRoot, 'test-results', 'rollback-drill.json'));
if (rollback) {
  const mttrBudget = sloConfig?.budgets?.rollbackMttrSeconds ?? 3600;
  addCheck('rollback:status-ok', rollback.status === 'ok', { observed: rollback.status });
  addCheck('rollback:mttr-budget', typeof rollback.mttrSeconds === 'number' && rollback.mttrSeconds <= mttrBudget, {
    observed: rollback.mttrSeconds,
    target: `<= ${mttrBudget} seconds`
  });
  addCheck('rollback:post-smoke-green', rollback.postRollbackSmoke?.status === 'ok' || rollback.postRollbackSmoke?.passed === true, {
    observed: rollback.postRollbackSmoke?.status ?? rollback.postRollbackSmoke?.passed
  });
}

const failed = checks.filter(check => !check.passed);
const summary = {
  status: failed.length === 0 ? 'ok' : 'failed',
  generatedAt: new Date().toISOString(),
  workspaceRoot,
  artifactRoot,
  sloConfig: sloPath,
  checks,
  failedChecks: failed.map(check => check.name),
  alertRules: sloConfig?.alertRules ?? [],
  residualObservabilitySignoff: {
    dashboardsDeployedRequired: true,
    alertRoutesTestedRequired: true,
    stagingBurnInRequired: true
  }
};

await mkdir(outputDir, { recursive: true });
await writeFile(outputPath, JSON.stringify(summary, null, 2));

if (failed.length > 0) {
  console.error(`Observability gate failed (${failed.length} checks). Summary: ${outputPath}`);
  for (const check of failed) {
    console.error(`- ${check.name}`);
  }
  process.exit(1);
}

console.log(`Observability gate passed (${checks.length} checks). Summary: ${outputPath}`);
