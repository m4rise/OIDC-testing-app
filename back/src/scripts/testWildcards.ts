#!/usr/bin/env node

/**
 * Test script for improved matchesPermission function behavior with bidirectional wildcards
 */

// Import the simplified matchesPermission function
const matchesPermission = (userPermission: string, requiredPermission: string): boolean => {
  const userParts = userPermission.split(':');
  const reqParts = requiredPermission.split(':');

  // On compare sur la longueur la plus courte
  const minLength = Math.min(userParts.length, reqParts.length);

  for (let i = 0; i < minLength; i++) {
    if (userParts[i] !== reqParts[i] && userParts[i] !== '*' && reqParts[i] !== '*') {
      return false;
    }
  }

  // Si user est plus court ou égal, c'est OK (principe hiérarchique)
  if (userParts.length <= reqParts.length) {
    return true;
  }

  // Si user est plus long ET que required se termine par un wildcard,
  // alors user peut être plus spécifique
  if (reqParts[reqParts.length - 1] === '*') {
    return true;
  }

  return false;
};

console.log('🧪 Testing improved matchesPermission with bidirectional wildcards');
console.log('=' .repeat(70));

const testCases = [
  {
    title: 'CASE 1: Hierarchical permissions (user shorter)',
    required: "api:user:read:self",
    tests: [
      { perm: 'api:user:read:self', expected: true, reason: 'exact match' },
      { perm: 'api:user:read', expected: true, reason: 'hierarchical (shorter covers longer)' },
      { perm: 'api:user', expected: true, reason: 'hierarchical (shorter covers longer)' },
      { perm: 'api', expected: true, reason: 'hierarchical (shorter covers longer)' },
      { perm: 'api:*', expected: true, reason: 'wildcard + hierarchical' },
      { perm: 'api:*:read', expected: true, reason: 'wildcard + hierarchical' },
      { perm: 'api:*:read:*', expected: true, reason: 'user wildcards match specific values' },
      { perm: 'api:*:read:self', expected: true, reason: 'wildcard exact match' },
      { perm: 'api:admin', expected: false, reason: 'different path (admin ≠ user)' },
      { perm: 'route:user', expected: false, reason: 'different domain (route ≠ api)' }
    ]
  },
  {
    title: 'CASE 2: User matches wildcard patterns (user more specific)',
    required: "api:*:read:*",
    tests: [
      { perm: 'api:user:read:self', expected: true, reason: 'specific matches wildcard pattern' },
      { perm: 'api:admin:read:all', expected: true, reason: 'specific matches wildcard pattern' },
      { perm: 'api:customer:read:own', expected: true, reason: 'specific matches wildcard pattern' },
      { perm: 'api:admin:read', expected: true, reason: 'shorter but matches wildcards' },
      { perm: 'api:*:read', expected: true, reason: 'shorter wildcard matches wildcard' },
      { perm: 'api:*:read:*', expected: true, reason: 'user wildcards match wildcard pattern' },
      { perm: 'api:user:write:self', expected: false, reason: 'wrong action (write ≠ read)' },
      { perm: 'route:user:read:self', expected: false, reason: 'wrong domain (route ≠ api)' },
      { perm: 'api:user:read:self:extra', expected: true, reason: 'longer than pattern but ends with *' }
    ]
  },
  {
    title: 'CASE 3: Mixed wildcard scenarios',
    required: "route:*",
    tests: [
      { perm: 'route:admin', expected: true, reason: 'specific matches wildcard' },
      { perm: 'route:user:profile', expected: true, reason: 'longer specific, wildcard at end' },
      { perm: 'route:*', expected: true, reason: 'wildcard matches wildcard' },
      { perm: 'route', expected: true, reason: 'shorter hierarchical' },
      { perm: '*:admin', expected: true, reason: 'user wildcard matches specific domain' },
      { perm: 'route:*:profile', expected: false, reason: 'user longer than required without wildcard at end' },
      { perm: 'api:user', expected: false, reason: 'wrong domain (api ≠ route)' }
    ]
  },
  {
    title: 'CASE 4: Complex wildcard patterns',
    required: "api:*:write:*",
    tests: [
      { perm: 'api:user:write:self', expected: true, reason: 'matches pattern exactly' },
      { perm: 'api:admin:write:all', expected: true, reason: 'matches pattern exactly' },
      { perm: 'api:user:read:self', expected: false, reason: 'wrong action (read ≠ write)' },
      { perm: 'api:user:write', expected: true, reason: 'shorter hierarchical' },
      { perm: 'api:*:write', expected: true, reason: 'shorter wildcard matches' },
      { perm: 'api:*:write:*', expected: true, reason: 'user wildcards match wildcard pattern' },
      { perm: 'api:*:write', expected: true, reason: 'shorter wildcard hierarchical' }
    ]
  }
];

testCases.forEach(testCase => {
  console.log(`\n📋 ${testCase.title}`);
  console.log(`Required permission: "${testCase.required}"`);
  console.log('-'.repeat(70));

  testCase.tests.forEach(test => {
    const result = matchesPermission(test.perm, testCase.required);
    const icon = result ? '✅' : '❌';
    const expectedIcon = test.expected ? '✅' : '❌';
    const status = result === test.expected ? 'PASS' : '⚠️  FAIL';

    console.log(`${icon} "${test.perm}" → ${result} | Expected: ${expectedIcon} ${test.expected} | ${status}`);
    console.log(`   📝 ${test.reason}`);

    if (result !== test.expected) {
      console.log(`   ⚠️  UNEXPECTED RESULT! Expected ${test.expected} but got ${result}`);
    }
  });
});

console.log('\n' + '='.repeat(70));
console.log('📝 Logique simplifiée:');
console.log('1. ✅ Principe principal: Plus court couvre plus long (votre logique originale)');
console.log('2. ✅ Bonus: Support wildcards dans les permissions requises');
console.log('3. ✅ Bonus: Support wildcards dans les permissions utilisateur');

console.log('\n🎯 Exemples spécifiques:');
const examples = [
  { user: 'api:user:read:self', required: 'api:*:read:*', expected: true },
  { user: 'api:*:read', required: 'api:user:read:self', expected: true },
  { user: 'api:admin:read:self', required: 'api:user:read:*', expected: false }
];

examples.forEach(ex => {
  const result = matchesPermission(ex.user, ex.required);
  const icon = result ? '✅' : '❌';
  const expectedIcon = ex.expected ? '✅' : '❌';
  const status = result === ex.expected ? 'PASS' : 'FAIL';
  console.log(`${icon} User "${ex.user}" vs required "${ex.required}" → ${result} | Expected: ${expectedIcon} | ${status}`);
});
