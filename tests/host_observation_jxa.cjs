// Execute the shipped JXA source with an intentionally opaque CF bridge.
// No macOS session, permissions, network, or third-party JS packages required.
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const source = readFileSync(process.env.HOST_OBSERVATION_SCRIPT ||
    join(__dirname, '../src/host_observation/enumerate.js'), 'utf8');

function observe(overrides = {}) {
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
    const context = vm.createContext({
        $: api,
        ObjC: {
            import: () => {},
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
    return { result: JSON.parse(context.run(['list', '501'])), bridges, permissionChecks };
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
                CGPreflightScreenCaptureAccess: () => { throw Error('session guard bypassed'); } },
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
    const { result } = observe({ CGPreflightScreenCaptureAccess: () => false });
    assert.match(result.error, /Screen Recording access denied/);
});
