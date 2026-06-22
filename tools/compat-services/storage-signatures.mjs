import { generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

const ed25519SpkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
const curve25519Prime = (1n << 255n) - 19n;
const subaccountTokenLength = 36;
const subaccountSignatureLength = 64;
const subaccountPublicKeyOffset = 4;

export const storageSubaccountAccess = Object.freeze({
  NONE: 0x00,
  READ: 0x01,
  WRITE: 0x02,
  DELETE: 0x04,
  ANY_PREFIX: 0x08
});

function isHexWithLength(value, length) {
  return typeof value === 'string' && value.length === length && /^[0-9a-f]+$/i.test(value);
}

function mod(value) {
  const result = value % curve25519Prime;
  return result >= 0n ? result : result + curve25519Prime;
}

function modPow(base, exponent) {
  let result = 1n;
  let factor = mod(base);
  let power = exponent;

  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = mod(result * factor);
    }
    factor = mod(factor * factor);
    power >>= 1n;
  }

  return result;
}

function modInverse(value) {
  return modPow(value, curve25519Prime - 2n);
}

function littleEndianBytesToBigInt(bytes) {
  let result = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    result = (result << 8n) + BigInt(bytes[index]);
  }
  return result;
}

function bigIntToLittleEndianBytes(value, length) {
  const bytes = Buffer.alloc(length);
  let remaining = mod(value);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function createEd25519PublicKeyDer(publicKeyBytes) {
  return Buffer.concat([ed25519SpkiPrefix, Buffer.from(publicKeyBytes)]);
}

function resolveSubaccountTokenInputs(values) {
  const normalizedValues = Array.isArray(values)
    ? values
    : values === undefined || values === null || values === ''
      ? []
      : [values];

  const tokenBytes = [];
  for (const value of normalizedValues) {
    const rawValue = typeof value === 'object' && value !== null && 'subaccount' in value
      ? value.subaccount
      : value;
    const decoded = decodeHexOrBase64Bytes(rawValue, subaccountTokenLength);
    if (!decoded) {
      return null;
    }

    tokenBytes.push(decoded);
  }

  return tokenBytes;
}

function parsePubkeyPrefix(pubkey) {
  return isHexWithLength(pubkey, 66) ? Number.parseInt(pubkey.slice(0, 2), 16) : null;
}

function verifyEd25519Signature(publicKeyBytes, message, signatureBytes) {
  try {
    return cryptoVerify(
      null,
      message,
      {
        key: createEd25519PublicKeyDer(publicKeyBytes),
        format: 'der',
        type: 'spki'
      },
      signatureBytes
    );
  } catch {
    return false;
  }
}

function resolveStorageVerificationKey(pubkey, pubkeyEd25519) {
  const normalizedPubkey = String(pubkey ?? '');

  if (isHexWithLength(normalizedPubkey, 66) && !normalizedPubkey.startsWith('05')) {
    return {
      checked: true,
      publicKeyBytes: Buffer.from(normalizedPubkey.slice(2), 'hex'),
      prefix: parsePubkeyPrefix(normalizedPubkey)
    };
  }

  if (normalizedPubkey.startsWith('05') && isHexWithLength(normalizedPubkey.slice(2), 64)) {
    const companionBytes = decodeHexOrBase64Bytes(pubkeyEd25519, 32);
    if (!pubkeyEd25519) {
      return {
        checked: false,
        publicKeyBytes: null,
        prefix: parsePubkeyPrefix(normalizedPubkey)
      };
    }

    if (!companionBytes) {
      return {
        checked: true,
        publicKeyBytes: null,
        prefix: parsePubkeyPrefix(normalizedPubkey)
      };
    }

    const expectedX25519 = Buffer.from(normalizedPubkey.slice(2), 'hex');
    return ed25519PublicKeyToX25519(companionBytes).equals(expectedX25519)
      ? {
          checked: true,
          publicKeyBytes: companionBytes,
          prefix: parsePubkeyPrefix(normalizedPubkey)
        }
      : {
          checked: true,
          publicKeyBytes: null,
          prefix: parsePubkeyPrefix(normalizedPubkey)
        };
  }

  return {
    checked: false,
    publicKeyBytes: null,
    prefix: null
  };
}

function verifyStorageSubaccount({
  ownerPrefix,
  ownerPublicKeyBytes,
  requiredAccess = storageSubaccountAccess.NONE,
  subaccount,
  subaccountSig
}) {
  const hasSubaccount = typeof subaccount === 'string' && subaccount.length > 0;
  const hasSubaccountSig = typeof subaccountSig === 'string' && subaccountSig.length > 0;

  if (!hasSubaccount && !hasSubaccountSig) {
    return {
      present: false,
      checked: false,
      verified: true,
      publicKeyBytes: null,
      subaccount: null,
      reason: null
    };
  }

  const subaccountBytes = decodeHexOrBase64Bytes(subaccount, subaccountTokenLength);
  const subaccountSigBytes = decodeHexOrBase64Bytes(subaccountSig, subaccountSignatureLength);
  if (!subaccountBytes || !subaccountSigBytes || !ownerPublicKeyBytes || ownerPrefix == null) {
    return {
      present: true,
      checked: true,
      verified: false,
      publicKeyBytes: null,
      subaccount: null,
      reason: 'Subaccount auth signature verification failed'
    };
  }

  const flags = subaccountBytes[1];
  const hasDelete = (flags & storageSubaccountAccess.DELETE) === storageSubaccountAccess.DELETE;
  const normalizedSubaccount = {
    flags,
    hasDelete,
    tokenHex: subaccountBytes.toString('hex')
  };

  const prefixAllowed = subaccountBytes[0] === ownerPrefix ||
    (flags & storageSubaccountAccess.ANY_PREFIX) === storageSubaccountAccess.ANY_PREFIX;
  if (!prefixAllowed) {
    return {
      present: true,
      checked: true,
      verified: false,
      publicKeyBytes: null,
      subaccount: normalizedSubaccount,
      reason: 'Invalid subaccount: subaccount and main account have mismatched network prefix'
    };
  }

  if ((flags & requiredAccess) !== requiredAccess) {
    const missingRead = (requiredAccess & storageSubaccountAccess.READ) === storageSubaccountAccess.READ &&
      (flags & storageSubaccountAccess.READ) !== storageSubaccountAccess.READ;
    return {
      present: true,
      checked: true,
      verified: false,
      publicKeyBytes: null,
      subaccount: normalizedSubaccount,
      reason: missingRead
        ? 'Invalid subaccount: this subaccount does not have read permission'
        : 'Subaccount auth signature verification failed'
    };
  }

  const verified = verifyEd25519Signature(ownerPublicKeyBytes, subaccountBytes, subaccountSigBytes);

  return {
    present: true,
    checked: true,
    verified,
    publicKeyBytes: Buffer.from(subaccountBytes.subarray(subaccountPublicKeyOffset)),
    subaccount: normalizedSubaccount,
    reason: verified ? null : 'Subaccount auth signature verification failed'
  };
}

export function decodeHexOrBase64Bytes(value, byteLength) {
  if (isHexWithLength(value, byteLength * 2)) {
    return Buffer.from(value, 'hex');
  }

  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9+/=_-]+$/.test(value)) {
    return null;
  }

  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = Buffer.from(normalized, 'base64');
    return decoded.length === byteLength ? decoded : null;
  } catch {
    return null;
  }
}

export function storageNamespaceSignatureValue(namespace) {
  if (namespace === undefined || namespace === null || namespace === '') {
    return '';
  }

  if (typeof namespace === 'string' && namespace.toLowerCase() === 'all') {
    return 'all';
  }

  const parsed = Number(namespace);
  return Number.isFinite(parsed) && parsed === 0 ? '' : String(parsed);
}

function concatenateSignatureValues(values) {
  let result = '';
  for (const value of values) {
    if (Array.isArray(value)) {
      result += concatenateSignatureValues(value);
      continue;
    }

    result += String(value ?? '');
  }
  return result;
}

export function createStorageStoreSignatureMessage(namespace, signatureTimestamp) {
  return Buffer.from(`store${storageNamespaceSignatureValue(namespace)}${Number(signatureTimestamp)}`);
}

export function createStorageRetrieveSignatureMessage(namespace, timestamp) {
  return Buffer.from(`retrieve${storageNamespaceSignatureValue(namespace)}${Number(timestamp)}`);
}

export function createStorageGetExpiriesSignatureMessage(timestamp, messages) {
  return Buffer.from(concatenateSignatureValues(['get_expiries', Number(timestamp), messages]));
}

export function createStorageExpireAllSignatureMessage(namespace, expiry) {
  return Buffer.from(concatenateSignatureValues(['expire_all', storageNamespaceSignatureValue(namespace), Number(expiry)]));
}

export function createStorageExpireSignatureMessage(mode, expiry, messages) {
  const normalizedMode = mode === 'shorten' || mode === 'extend' ? mode : '';
  const expiryValues = Array.isArray(expiry) ? expiry.map(value => Number(value)) : [Number(expiry)];
  return Buffer.from(concatenateSignatureValues(['expire', normalizedMode, expiryValues, messages]));
}

export function createStorageDeleteSignatureMessage(messages) {
  return Buffer.from(concatenateSignatureValues(['delete', messages]));
}

export function createStorageDeleteAllSignatureMessage(namespace, timestamp) {
  return Buffer.from(concatenateSignatureValues(['delete_all', storageNamespaceSignatureValue(namespace), Number(timestamp)]));
}

export function createStorageDeleteBeforeSignatureMessage(namespace, before) {
  return Buffer.from(concatenateSignatureValues(['delete_before', storageNamespaceSignatureValue(namespace), Number(before)]));
}

export function createStorageRevokeSubaccountSignatureMessage(timestamp, subaccounts) {
  const tokenBytes = resolveSubaccountTokenInputs(subaccounts);
  if (!tokenBytes) {
    return null;
  }

  return Buffer.concat([Buffer.from(`revoke_subaccount${Number(timestamp)}`), ...tokenBytes]);
}

export function createStorageUnrevokeSubaccountSignatureMessage(timestamp, subaccounts) {
  const tokenBytes = resolveSubaccountTokenInputs(subaccounts);
  if (!tokenBytes) {
    return null;
  }

  return Buffer.concat([Buffer.from(`unrevoke_subaccount${Number(timestamp)}`), ...tokenBytes]);
}

export function createStorageRevokedSubaccountsSignatureMessage(timestamp) {
  return Buffer.from(`revoked_subaccounts${Number(timestamp)}`);
}

export function createPushSubscribeSignatureMessage(pubkey, timestamp, wantData, namespaces) {
  const normalizedPubkey = String(pubkey ?? '').toLowerCase();
  const normalizedNamespaces = Array.isArray(namespaces)
    ? namespaces.map(value => Number(value))
    : [];
  return Buffer.from(`MONITOR${normalizedPubkey}${Number(timestamp)}${wantData ? '1' : '0'}${normalizedNamespaces.join(',')}`);
}

export function createPushUnsubscribeSignatureMessage(pubkey, timestamp) {
  return Buffer.from(`UNSUBSCRIBE${String(pubkey ?? '').toLowerCase()}${Number(timestamp)}`);
}

export function ed25519PublicKeyToX25519(publicKeyBytes) {
  if (!Buffer.isBuffer(publicKeyBytes) || publicKeyBytes.length !== 32) {
    throw new TypeError('ed25519 public key must be a 32-byte Buffer');
  }

  const yBytes = Buffer.from(publicKeyBytes);
  yBytes[31] &= 0x7f;
  const y = littleEndianBytesToBigInt(yBytes);
  const u = mod((1n + y) * modInverse(1n - y));
  return bigIntToLittleEndianBytes(u, 32);
}

export function verifyStorageSignature({
  operation,
  pubkey,
  pubkeyEd25519,
  signature,
  subaccount,
  subaccountSig,
  requiredSubaccountAccess = storageSubaccountAccess.NONE,
  subaccounts,
  namespace,
  timestamp,
  messages,
  expiry,
  mode,
  before,
  wantData
}) {
  const resolvedKey = resolveStorageVerificationKey(pubkey, pubkeyEd25519);
  if (!resolvedKey.checked) {
    return {
      checked: false,
      verified: true,
      reason: null
    };
  }

  const subaccountVerification = verifyStorageSubaccount({
    ownerPrefix: resolvedKey.prefix,
    ownerPublicKeyBytes: resolvedKey.publicKeyBytes,
    requiredAccess: requiredSubaccountAccess,
    subaccount,
    subaccountSig
  });
  if (subaccountVerification.present && !subaccountVerification.verified) {
    return {
      checked: true,
      verified: false,
      usingSubaccount: true,
      subaccount: subaccountVerification.subaccount,
      reason: subaccountVerification.reason
    };
  }

  const signatureBytes = decodeHexOrBase64Bytes(signature, 64);
  const verificationPublicKeyBytes = subaccountVerification.present
    ? subaccountVerification.publicKeyBytes
    : resolvedKey.publicKeyBytes;
  if (!signatureBytes || !verificationPublicKeyBytes) {
    return {
      checked: true,
      verified: false,
      usingSubaccount: subaccountVerification.present,
      subaccount: subaccountVerification.subaccount,
      reason: subaccountVerification.present
        ? 'Subaccount main signature verification failed'
        : 'Signature verification failed'
    };
  }

  let message;
  switch (operation) {
    case 'store':
      message = createStorageStoreSignatureMessage(namespace, timestamp);
      break;
    case 'retrieve':
      message = createStorageRetrieveSignatureMessage(namespace, timestamp);
      break;
    case 'get_expiries':
      message = createStorageGetExpiriesSignatureMessage(timestamp, messages);
      break;
    case 'expire_all':
      message = createStorageExpireAllSignatureMessage(namespace, expiry);
      break;
    case 'expire':
      message = createStorageExpireSignatureMessage(mode, expiry, messages);
      break;
    case 'delete':
      message = createStorageDeleteSignatureMessage(messages);
      break;
    case 'delete_all':
      message = createStorageDeleteAllSignatureMessage(namespace, timestamp);
      break;
    case 'delete_before':
      message = createStorageDeleteBeforeSignatureMessage(namespace, before);
      break;
    case 'revoke_subaccount':
      message = createStorageRevokeSubaccountSignatureMessage(timestamp, subaccounts);
      break;
    case 'unrevoke_subaccount':
      message = createStorageUnrevokeSubaccountSignatureMessage(timestamp, subaccounts);
      break;
    case 'revoked_subaccounts':
      message = createStorageRevokedSubaccountsSignatureMessage(timestamp);
      break;
    case 'push_subscribe':
      message = createPushSubscribeSignatureMessage(pubkey, timestamp, wantData, messages);
      break;
    case 'push_unsubscribe':
      message = createPushUnsubscribeSignatureMessage(pubkey, timestamp);
      break;
    default:
      return {
        checked: false,
        verified: true,
        reason: null
      };
  }

  if (!message) {
    return {
      checked: true,
      verified: false,
      usingSubaccount: subaccountVerification.present,
      subaccount: subaccountVerification.subaccount,
      reason: subaccountVerification.present
        ? 'Subaccount main signature verification failed'
        : 'Signature verification failed'
    };
  }

  const verified = verifyEd25519Signature(verificationPublicKeyBytes, message, signatureBytes);
  return {
    checked: true,
    verified,
    usingSubaccount: subaccountVerification.present,
    subaccount: subaccountVerification.subaccount,
    reason: verified
      ? null
      : subaccountVerification.present
        ? 'Subaccount main signature verification failed'
        : 'Signature verification failed'
  };
}

function createStorageSigner(privateKey) {
  return {
    signStore(namespace, signatureTimestamp) {
      return cryptoSign(null, createStorageStoreSignatureMessage(namespace, signatureTimestamp), privateKey).toString('base64');
    },
    signRetrieve(namespace, timestamp) {
      return cryptoSign(null, createStorageRetrieveSignatureMessage(namespace, timestamp), privateKey).toString('base64');
    },
    signGetExpiries(timestamp, messages) {
      return cryptoSign(null, createStorageGetExpiriesSignatureMessage(timestamp, messages), privateKey).toString('base64');
    },
    signExpireAll(namespace, expiry) {
      return cryptoSign(null, createStorageExpireAllSignatureMessage(namespace, expiry), privateKey).toString('base64');
    },
    signExpire(mode, expiry, messages) {
      return cryptoSign(null, createStorageExpireSignatureMessage(mode, expiry, messages), privateKey).toString('base64');
    },
    signDelete(messages) {
      return cryptoSign(null, createStorageDeleteSignatureMessage(messages), privateKey).toString('base64');
    },
    signDeleteAll(namespace, timestamp) {
      return cryptoSign(null, createStorageDeleteAllSignatureMessage(namespace, timestamp), privateKey).toString('base64');
    },
    signDeleteBefore(namespace, before) {
      return cryptoSign(null, createStorageDeleteBeforeSignatureMessage(namespace, before), privateKey).toString('base64');
    },
    signRevokeSubaccount(timestamp, subaccounts) {
      const message = createStorageRevokeSubaccountSignatureMessage(timestamp, subaccounts);
      if (!message) {
        throw new TypeError('revoke_subaccount requires valid subaccount tokens');
      }

      return cryptoSign(null, message, privateKey).toString('base64');
    },
    signUnrevokeSubaccount(timestamp, subaccounts) {
      const message = createStorageUnrevokeSubaccountSignatureMessage(timestamp, subaccounts);
      if (!message) {
        throw new TypeError('unrevoke_subaccount requires valid subaccount tokens');
      }

      return cryptoSign(null, message, privateKey).toString('base64');
    },
    signRevokedSubaccounts(timestamp) {
      return cryptoSign(null, createStorageRevokedSubaccountsSignatureMessage(timestamp), privateKey).toString('base64');
    },
    signPushSubscribe(pubkey, timestamp, wantData, namespaces) {
      return cryptoSign(null, createPushSubscribeSignatureMessage(pubkey, timestamp, wantData, namespaces), privateKey).toString('base64');
    },
    signPushUnsubscribe(pubkey, timestamp) {
      return cryptoSign(null, createPushUnsubscribeSignatureMessage(pubkey, timestamp), privateKey).toString('base64');
    }
  };
}

export function createTestStorageSigningIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const ed25519PublicKey = Buffer.from(publicKeyDer.subarray(-32));
  const x25519PublicKey = ed25519PublicKeyToX25519(ed25519PublicKey);
  const pubkeyEd25519 = ed25519PublicKey.toString('hex');
  const directPubkey = `03${pubkeyEd25519}`;
  const signer = createStorageSigner(privateKey);

  return {
    directPubkey,
    sessionPubkey: `05${x25519PublicKey.toString('hex')}`,
    pubkeyEd25519,
    ...signer,
    createSubaccount(options = {}) {
      const { publicKey: subaccountPublicKey, privateKey: subaccountPrivateKey } = generateKeyPairSync('ed25519');
      const subaccountPublicKeyDer = subaccountPublicKey.export({ type: 'spki', format: 'der' });
      const subaccountPublicKeyBytes = Buffer.from(subaccountPublicKeyDer.subarray(-32));
      const ownerPubkey = typeof options.ownerPubkey === 'string' ? options.ownerPubkey : directPubkey;
      const prefix = parsePubkeyPrefix(ownerPubkey) ?? 0x03;
      const flags = (options.read === false ? 0 : storageSubaccountAccess.READ) |
        (options.write === false ? 0 : storageSubaccountAccess.WRITE) |
        (options.delete === true ? storageSubaccountAccess.DELETE : 0) |
        (options.anyPrefix === true ? storageSubaccountAccess.ANY_PREFIX : 0);
      const tokenBytes = Buffer.concat([Buffer.from([prefix, flags, 0x00, 0x00]), subaccountPublicKeyBytes]);
      const subaccountSig = cryptoSign(null, tokenBytes, privateKey).toString('base64');

      return {
        ownerPubkey,
        flags,
        subaccount: tokenBytes.toString('base64'),
        subaccountSig,
        tokenHex: tokenBytes.toString('hex'),
        tokenBytes,
        hasDelete: (flags & storageSubaccountAccess.DELETE) === storageSubaccountAccess.DELETE,
        ...createStorageSigner(subaccountPrivateKey)
      };
    }
  };
}