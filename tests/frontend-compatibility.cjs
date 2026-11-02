const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const filename = process.argv[2] || path.join(__dirname, '../web/workflowcipher-v2.js');
const source = fs.readFileSync(filename === '-' ? 0 : filename, 'utf8').replace(/^import .*;\r?\n/gm, '');

function loadExtension(canvasType) {
  let extension;
  const context = vm.createContext({
    app: { registerExtension(value) { extension = value; } },
    api: { fetchApi: async () => ({ ok: true, json: async () => ({}) }) },
    GroupNodeHandler: class {},
    LiteGraph: canvasType ? { LGraphCanvas: canvasType } : {},
    document: { addEventListener() {} },
    window: { location: { origin: 'http://localhost:8188' } },
    console: { info() {}, warn() {} },
    fetch: async () => ({ ok: true, json: async () => ({}) }),
    requestAnimationFrame() {},
    URL,
  });
  vm.runInContext(`"use strict";\n${source}`, context, { filename });
  assert.equal(extension.name, 'ComfyUI.XLJworkflowCipher');
  return { extension, context };
}

test('strict module initialization registers the extension', () => {
  loadExtension();
});

test('setup tolerates an unavailable legacy canvas global', () => {
  loadExtension().extension.setup();
});

test('canvas menu can use the LiteGraph namespace', () => {
  class Canvas {
    getCanvasMenuOptions() { return []; }
  }
  loadExtension(Canvas).extension.setup();
  const options = new Canvas().getCanvasMenuOptions();
  assert.ok(options.some(option => typeof option?.callback === 'function'));
});

test('saved zero ports remove default shell sockets', () => {
  const { context } = loadExtension();
  context.node = {
    properties: { workflowcipher_input_count: 0, workflowcipher_output_count: 0 },
    inputs: Array(32).fill({}), outputs: Array(32).fill({}),
  };
  vm.runInContext('trimVaultPorts(node)', context);
  assert.equal(context.node.inputs.length, 0);
  assert.equal(context.node.outputs.length, 0);
});

test('each saved port count is applied independently', () => {
  const { context } = loadExtension();
  context.node = {
    properties: { workflowcipher_output_count: 2 },
    inputs: Array(32).fill({}), outputs: Array(32).fill({}),
  };
  vm.runInContext('trimVaultPorts(node)', context);
  assert.equal(context.node.inputs.length, 32);
  assert.equal(context.node.outputs.length, 2);
});
