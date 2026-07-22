const expected = [
  '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29',
  '7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674',
  'f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b'
].sort();

async function rpc(port, method) {
  const response = await fetch(`http://127.0.0.1:${port}/api/session/rpc`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: `survival-${method}`, method, params: {} })
  });
  if (!response.ok) throw new Error(`${method} failed on ${port} with ${response.status}`);
  const body = await response.json();
  if (body.success !== true) throw new Error(`${method} was rejected on ${port}`);
  return body.result;
}

for (const port of [41801, 41802, 41803]) {
  const registered = await rpc(port, 'fetch_rids');
  const contacts = await rpc(port, 'fetch_rcs');
  if (!Array.isArray(registered) || JSON.stringify([...registered].sort()) !== JSON.stringify(expected)) {
    throw new Error(`xnode on ${port} does not have exactly three registered relay IDs`);
  }
  const contactIds = Array.isArray(contacts) ? contacts.map(value => value.routerId).sort() : [];
  if (JSON.stringify(contactIds) !== JSON.stringify(expected)) {
    throw new Error(`xnode on ${port} does not have exactly three signed relay contacts`);
  }
}
process.stdout.write('All XNodes have the exact three registered signed relay contacts.\n');
