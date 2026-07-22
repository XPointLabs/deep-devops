import { isIP } from 'node:net';

const hostArgument = process.argv.indexOf('--host');
const host = hostArgument >= 0 ? process.argv[hostArgument + 1] : '127.0.0.1';
if (isIP(host) !== 4) throw new Error('seed host must be an IPv4 address');

const expected = new Set([
  '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29',
  '7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674',
  'f381626e41e7027ea431bfe3009e94bdd25a746beec468948d6c3c7c5dc9a54b',
  'fd50b8e3b144ea244fbf7737f550bc8dd0c2650bbc1aada833ca17ff8dbf329b',
  'fde4fba030ad002f7c2f7d4c331f49d13fb0ec747eceebec634f1ff4cbca9def',
  'b4c92afb3ba57f3ab959ffe6d319c98484a2155a0f4c65b2c37011ffd197b075'
]);

const contacts = await Promise.all([41801, 41802, 41803, 41804, 41805, 41806].map(async port => {
  const response = await fetch(`http://${host}:${port}/api/network/contact`);
  if (!response.ok) throw new Error(`xnode contact request failed on ${port}`);
  return response.json();
}));
if (contacts.length !== expected.size || contacts.some(contact => !expected.has(contact.routerId))) {
  throw new Error('xnode contacts do not match the exact development router identities');
}

const response = await fetch('http://127.0.0.1:41999/seed', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(contacts)
});
if (!response.ok) throw new Error(`relay-bootstrap seed failed with ${response.status}`);
const result = await response.json();
if (result.seeded !== 6) throw new Error('relay-bootstrap did not accept exactly six contacts');
process.stdout.write('Seeded six signed relay contacts.\n');
