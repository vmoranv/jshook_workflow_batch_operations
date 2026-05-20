/**
 * Batch Operations Workflow - Parallel execution for security testing
 */

import {
  defineWorkflow,
  parallelStep,
  type WorkflowExecutionContext,
} from '@jshookmcp/extension-sdk/workflow';

const DEFAULT_XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '<body onload=alert(1)>',
  '{{constructor.constructor("alert(1)")()}}',
];

export const batchXssTestWorkflow = defineWorkflow(
  'workflow.batch-xss-test.v1',
  'Batch XSS Test',
  (workflow) =>
    workflow
      .description('Test multiple XSS payloads in parallel against a target URL')
      .buildGraph((ctx: WorkflowExecutionContext) => {
        const baseUrl = ctx.getConfig<string>('baseUrl', '');
        const parameter = ctx.getConfig<string>('parameter', 'q');
        const payloads = ctx.getConfig<string[]>('payloads', DEFAULT_XSS_PAYLOADS);
        const maxConcurrency = ctx.getConfig<number>('maxConcurrency', 5);

        return parallelStep('batch-xss', (parallel) => {
          parallel.maxConcurrency(maxConcurrency);

          for (const [i, payload] of payloads.entries()) {
            parallel.sequence(`xss-${i}`, (sequence) => {
              sequence.tool('navigate', 'page_navigate', {
                input: { url: `${baseUrl}?${parameter}=${encodeURIComponent(payload)}` },
              });
              sequence.tool('check-alert', 'page_evaluate', {
                input: {
                  expression: 'window.alertTriggered || document.body.innerHTML.includes("<script>")',
                },
              });
              sequence.tool('screenshot', 'page_screenshot', {
                input: { path: `artifacts/xss-${i}.png` },
              });
            });
          }
        });
      })
      .onFinish((ctx: WorkflowExecutionContext, result: unknown) => {
        const results = Array.isArray(result) ? result : [];
        const success = results.filter((r) => (r as { success?: boolean } | null)?.success).length;
        ctx.emitMetric('xss.detected', success, 'counter');
      }),
);

export const batchRequestWorkflow = defineWorkflow(
  'workflow.batch-request.v1',
  'Batch Request',
  (workflow) =>
    workflow
      .description('Send multiple HTTP requests in parallel')
      .buildGraph((ctx: WorkflowExecutionContext) => {
        const urls = ctx.getConfig<string[]>('urls', []);
        const method = ctx.getConfig<string>('method', 'GET');
        const maxConcurrency = ctx.getConfig<number>('maxConcurrency', 10);

        return parallelStep('batch-request', (parallel) => {
          parallel.maxConcurrency(maxConcurrency);

          for (const [i, url] of urls.entries()) {
            parallel.sequence(`request-${i}`, (sequence) => {
              sequence.tool('fetch', 'network_replay_request', {
                input: { url, methodOverride: method },
              });
            });
          }
        });
      }),
);

export default [batchXssTestWorkflow, batchRequestWorkflow];
