export function demoInventory() {
  const devices = [
    { id: 'router-west', name: 'west-yard-router', addresses: ['100.80.0.10'], tags: ['tag:site-west'], os: 'linux', connected: true, advertisedRoutes: ['10.118.0.0/24'], enabledRoutes: ['10.118.0.0/24'] },
    { id: 'laptop-service', name: 'service-laptop', addresses: ['100.80.0.21'], user: 'alex@example.com', os: 'windows', connected: true, advertisedRoutes: ['10.118.0.0/24'], enabledRoutes: ['10.118.0.0/24'] },
    { id: 'laptop-old', name: 'commissioning-laptop', addresses: ['100.80.0.22'], user: 'sam@example.com', os: 'windows', connected: false, lastSeen: new Date(Date.now() - 9 * 86400000).toISOString(), advertisedRoutes: [], enabledRoutes: ['10.118.0.0/24', '192.168.10.0/24'] },
    { id: 'router-office', name: 'office-router', addresses: ['100.80.0.11'], tags: ['tag:office'], os: 'linux', connected: true, advertisedRoutes: ['10.40.0.0/16'], enabledRoutes: ['10.40.0.0/16'] },
    { id: 'laptop-field', name: 'field-laptop', addresses: ['100.80.0.23'], user: 'alex@example.com', os: 'windows', connected: true, advertisedRoutes: ['10.40.20.0/24'], enabledRoutes: ['10.40.20.0/24'] },
    { id: 'router-lab', name: 'lab-router', addresses: ['100.80.0.12'], tags: ['tag:lab'], os: 'linux', connected: true, advertisedRoutes: ['172.20.8.0/24'], enabledRoutes: ['172.20.8.0/24'] },
    { id: 'laptop-spare', name: 'workshop-laptop', addresses: ['100.80.0.24'], user: 'sam@example.com', os: 'windows', connected: true, advertisedRoutes: ['192.168.10.0/24'], enabledRoutes: [] },
    { id: 'monitor', name: 'monitoring-server', addresses: ['100.80.0.30'], tags: ['tag:monitor'], os: 'linux', connected: true, advertisedRoutes: [], enabledRoutes: [] },
    { id: 'viewer', name: 'office-workstation', addresses: ['100.80.0.40'], user: 'viewer@example.com', os: 'windows', connected: true, advertisedRoutes: [], enabledRoutes: [] },
  ].map(d => ({ user: '', tags: [], authorized: true, external: false, ...d }));
  const policy = {
    groups: { 'group:engineering': ['alex@example.com', 'sam@example.com'] },
    hosts: { 'west-yard': '10.118.0.0/24' },
    acls: [
      { action: 'accept', src: ['group:engineering'], dst: ['west-yard:*', '10.40.0.0/16:22,443', '172.20.8.0/24:*', '192.168.10.0/24:*'] },
      { action: 'accept', src: ['tag:monitor'], dst: ['10.118.0.24:443', '10.118.0.27:443'] },
    ],
    grants: [{ src: ['viewer@example.com'], dst: ['west-yard'], ip: ['tcp:443'], srcPosture: ['posture:managed'] }],
    postures: { 'posture:managed': ['node:os == \'windows\''] },
  };
  return { devices, policy, users: [], warnings: [], mode: 'demo', tailnet: 'example.com', policyAvailable: true, fetchedAt: new Date().toISOString() };
}
