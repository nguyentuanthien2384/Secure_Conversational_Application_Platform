"""Regression for the real Gradio sibling-row copy button layout."""

import shutil
import subprocess
from pathlib import Path

import pytest


def test_chat_copy_uses_its_own_sibling_row_and_keeps_links_without_html():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable; browser QA covers the static bridge.")
    bridge = Path(__file__).parents[1] / "src/app/ui_assets/session_bridge.js"
    script = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
let click, copied = [], mutations = [];
class Element {}
const source = {getAttribute: () => 'https://example.com/source'};
const userContent = {innerText: 'A user question', querySelectorAll: () => []};
const botContent = {innerText: 'A formatted answer', querySelectorAll: () => [source]};
function makeRow(content, user) {
  return {matches: selector => selector === '.message-row',
    classList: {contains: () => user}, querySelectorAll: () => [content]};
}
const userRow = makeRow(userContent, true), botRow = makeRow(botContent, false);
const chat = {contains: button => button.inChat, querySelectorAll: () => [userRow, botRow]};
class Button extends Element {
  constructor(label, row, inChat = true) { super(); this.label = label; this.row = row; this.inChat = inChat; }
  getAttribute(name) { return name === 'aria-label' ? this.label : null; }
  setAttribute() {} removeAttribute() {}
  closest(selector) {
    if (selector === 'button[aria-label]') return this;
    if (selector === '.message-buttons') return {previousElementSibling: this.row};
    if (selector === '.message-wrap') return {querySelector: () => userRow};
    return null;
  }
}
const document = {readyState:'complete', body:{},
  getElementById: id => id === 'chat-history' ? chat : null,
  querySelectorAll: () => [], addEventListener: (name, fn) => { if(name === 'click') click=fn; }};
const context = {document, Element, URL, Promise, Set, WeakMap, performance:{now:()=>0},
  MutationObserver: class {constructor(fn) {mutations.push(fn);} observe() {}},
  setInterval:()=>0, setTimeout:()=>0,
  navigator:{clipboard:{writeText:async text=>copied.push(text)}}};
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);
mutations.forEach(fn=>fn());
async function invoke(button) {
  let stopped = false;
  click({target:button, preventDefault(){}, stopImmediatePropagation(){stopped=true;}});
  await Promise.resolve(); await Promise.resolve();
  return stopped;
}
(async () => {
  assert.equal(await invoke(new Button('Copy message', botRow)), true);
  assert.equal(copied.at(-1), 'A formatted answer\n\nLiên kết:\nhttps://example.com/source');
  assert.equal(await invoke(new Button('Copy message', userRow)), true);
  assert.equal(copied.at(-1), 'A user question');
  assert.equal(await invoke(new Button('Copy conversation', null)), true);
  assert.match(copied.at(-1), /Bạn:\nA user question\n\nTrợ lý:\nA formatted answer/);
  assert.equal(await invoke(new Button('Clear', null)), false);
  assert.equal(await invoke(new Button('Copy message', botRow, false)), false);
  assert.equal(copied.length, 3);
})().catch(err => {console.error(err); process.exitCode=1;});
"""
    result = subprocess.run([node, "-e", script, str(bridge)], capture_output=True,
                            text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr
