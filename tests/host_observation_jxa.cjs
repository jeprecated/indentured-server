// Execute the shipped JXA source with an intentionally opaque CF bridge.
// No macOS session, permissions, network, or third-party JS packages required.
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const source = readFileSync(process.env.HOST_OBSERVATION_SCRIPT ||
    join(__dirname, '../src/host_observation/enumerate.js'), 'utf8');

function observe(overrides = {}, { mode = 'list', missingBindings = false } = {}) {
    class CFRef { constructor(value) { this.value = value; } }
    let bridges = 0;
    let permissionChecks = 0;
    const rect = (x, y) => ({ origin: { x, y }, size: { width: 1920, height: 1080 } });
    const rectangles = { 303: rect(0, 0), 101: rect(-1920, 0), 202: rect(0, -1080) };
    const screens = [303, 101, 202].map(id => ({
        deviceDescription: { objectForKey: () => id },
        get frame() { throw Error('Cocoa coordinates must not be used'); },
    }));
    const collection = items => ({ count: items.length, objectAtIndex: i => items[i] });
    const session = {
        kCGSSessionOnConsoleKey: true,
        kCGSSessionUserIDKey: 501,
        CGSSessionScreenIsLocked: false,
    };
    const api = {
        CGSessionCopyCurrentDictionary: () => new CFRef(session),
        CGPreflightScreenCaptureAccess: () => { permissionChecks++; return true; },
        CGRequestScreenCaptureAccess: () => { throw Error('unexpected permission prompt'); },
        NSWorkspace: { sharedWorkspace: { runningApplications: collection([
            { activationPolicy: 0, isTerminated: false, isHidden: false,
                processIdentifier: 123, localizedName: 'Windowless', bundleIdentifier: null },
        ]) } },
        CGWindowListCopyWindowInfo: () => new CFRef([{
            kCGWindowNumber: 456, kCGWindowOwnerPID: 123, kCGWindowIsOnscreen: true,
            kCGWindowLayer: 0, kCGWindowSharingState: 1,
            kCGWindowBounds: { X: 0, Y: -1080, Width: 100, Height: 50 },
        }]),
        NSScreen: { screens: collection(screens) },
        CGDisplayBounds: id => rectangles[id],
        ...overrides,
    };
    const permissionNames = ['CGPreflightScreenCaptureAccess', 'CGRequestScreenCaptureAccess'];
    const nativePermissions = Object.fromEntries(permissionNames.map(name => [name, api[name]]));
    const bindings = [];
    if (missingBindings) permissionNames.forEach(name => { delete api[name]; });
    const context = vm.createContext({
        $: api,
        ObjC: {
            import: () => {},
            bindFunction: (name, signature) => {
                assert.ok(permissionNames.includes(name), 'only known permission APIs may be bound');
                assert.equal(api[name], undefined, 'do not rebind APIs already supplied by metadata');
                assert.deepEqual(JSON.parse(JSON.stringify(signature)), ['bool', []]);
                bindings.push(name);
                api[name] = nativePermissions[name];
            },
            unwrap: x => x,
            castRefToObject: ref => {
                if (ref === null) return null;
                assert.ok(ref instanceof CFRef, 'expected opaque Core Foundation reference');
                bridges++;
                return ref.value;
            },
            deepUnwrap: value => {
                assert.ok(!(value instanceof CFRef), 'must bridge before deepUnwrap');
                return value;
            },
        },
    });
    vm.runInContext(source, context);
    return { result: JSON.parse(context.run([mode, '501'])), bridges, permissionChecks, bindings };
}

test('actual CGSession CFSTR keys allow the correct unlocked user', () => {
    const { result, bridges } = observe();
    assert.equal(result.error, undefined);
    assert.equal(bridges, 2, 'session dictionary and window array are both bridged');
    assert.equal(result.applications[0].name, 'Windowless');
    assert.equal(result.windows[0].window_id, 456);
});

test('reject null, wrong UID, locked, off-console and C-symbol-name dictionaries', () => {
    for (const session of [
        null,
        { kCGSSessionOnConsoleKey: true, kCGSSessionUserIDKey: 502 },
        { kCGSSessionOnConsoleKey: true, kCGSSessionUserIDKey: 501, CGSSessionScreenIsLocked: true },
        { kCGSSessionOnConsoleKey: false, kCGSSessionUserIDKey: 501 },
        { kCGSessionOnConsoleKey: true, kCGSessionUserIDKey: 501 },
    ]) {
        // Test the session predicate through a bridged fixture, not string
        // assertions on its implementation.
        const context = vm.createContext({
            $: { CGSessionCopyCurrentDictionary: () => ({}),
                CGPreflightScreenCaptureAccess: () => { throw Error('session guard bypassed'); },
                CGRequestScreenCaptureAccess: () => { throw Error('unexpected permission request'); } },
            ObjC: { import: () => {}, castRefToObject: () => session, deepUnwrap: x => x },
        });
        vm.runInContext(source, context);
        const result = JSON.parse(context.run(['list', '501']));
        assert.match(result.error, /GUI session unavailable/);
    }
});

test('three display IDs use CG bounds, not NSScreen order or Cocoa coordinates', () => {
    const { result } = observe();
    assert.deepEqual(result.displays.map(d => d.display_id), [303, 101, 202]);
    assert.deepEqual(result.displays[1].bounds, { x: -1920, y: 0, width: 1920, height: 1080 });
    assert.equal(result.displays[2].bounds.y, result.windows[0].bounds.y);
    assert.ok(result.displays.every(d => !('index' in d)), 'no unproven display ordinal mapping');
});

test('permission denial stays structured and never prompts during listing', () => {
    for (const missingBindings of [false, true]) {
        const { result } = observe({ CGPreflightScreenCaptureAccess: () => false }, { missingBindings });
        assert.match(result.error, /Screen Recording access denied/);
    }
});

test('missing JXA metadata is repaired with exact native permission signatures', () => {
    const { result, bindings } = observe({}, { missingBindings: true });
    assert.equal(result.error, undefined);
    assert.equal(result.windows[0].window_id, 456);
    assert.deepEqual(bindings, ['CGPreflightScreenCaptureAccess', 'CGRequestScreenCaptureAccess']);
});

test('existing metadata is retained and granted startup consent is not requested again', () => {
    for (const missingBindings of [false, true]) {
        const { result, permissionChecks, bindings } = observe({}, { mode: 'permissions', missingBindings });
        assert.equal(result.screen_recording, 'granted');
        assert.equal(permissionChecks, 1);
        assert.equal(bindings.length, missingBindings ? 2 : 0);
    }
});

test('startup requests missing consent once and preserves a denied result', () => {
    for (const missingBindings of [false, true]) {
        for (const granted of [false, true]) {
            let requests = 0;
            const { result } = observe({
                CGPreflightScreenCaptureAccess: () => false,
                CGRequestScreenCaptureAccess: () => { requests++; return granted; },
            }, { mode: 'permissions', missingBindings });
            assert.equal(requests, 1);
            if (granted) assert.equal(result.screen_recording, 'granted');
            else assert.match(result.error, /Screen Recording access is not granted yet/);
        }
    }
});
