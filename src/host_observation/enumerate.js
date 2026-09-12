// Runs only as fixed code in /usr/bin/osascript, inside the GUI user's LaunchAgent.
// No Apple Events/System Events automation or Accessibility permission is used.
ObjC.import('AppKit');
ObjC.import('CoreGraphics');

function run(argv) {
    try {
        if (argv[0] === 'permissions') {
            var granted = Boolean($.CGPreflightScreenCaptureAccess());
            if (!granted) granted = Boolean($.CGRequestScreenCaptureAccess());
            if (!granted) return JSON.stringify({error: 'Screen Recording access is not granted yet; approve the prompt or Settings entry and restart the helper'});
            return JSON.stringify({schema_version: '1', screen_recording: 'granted'});
        }
        var session = ObjC.deepUnwrap($.CGSessionCopyCurrentDictionary());
        if (!session || !session.kCGSessionOnConsoleKey ||
            Number(session.kCGSessionUserIDKey) !== Number(argv[1]) ||
            session.CGSSessionScreenIsLocked) {
            return JSON.stringify({error: 'GUI session unavailable, locked, or belongs to another user; run the helper as a LaunchAgent in the active logged-in user session'});
        }
        if (!$.CGPreflightScreenCaptureAccess()) {
            return JSON.stringify({error: 'Screen Recording access denied; window titles and captures would be incomplete'});
        }
        var result = {applications: [], windows: [], displays: []};
        var applications = $.NSWorkspace.sharedWorkspace.runningApplications;
        var hidden = {};
        for (var i = 0; i < Number(applications.count); i++) {
            var app = applications.objectAtIndex(i);
            // Regular and accessory applications, excluding background-only processes.
            if (Number(app.activationPolicy) > 1 || app.isTerminated) continue;
            var pid = Number(app.processIdentifier);
            hidden[pid] = Boolean(app.isHidden);
            result.applications.push({pid: pid, name: ObjC.unwrap(app.localizedName) || '',
                bundle_id: ObjC.unwrap(app.bundleIdentifier) || null, hidden: hidden[pid]});
        }
        // Include off-screen/minimized windows in inventory, but not in capture eligibility.
        var windows = ObjC.deepUnwrap($.CGWindowListCopyWindowInfo(16, 0));
        if (!windows) return JSON.stringify({error: 'WindowServer inventory unavailable'});
        windows.forEach(function(w) {
            var b = w.kCGWindowBounds || {};
            var pid = Number(w.kCGWindowOwnerPID);
            var visible = Boolean(w.kCGWindowIsOnscreen);
            var layer = Number(w.kCGWindowLayer);
            var bounds = {x: Number(b.X || 0), y: Number(b.Y || 0),
                width: Number(b.Width || 0), height: Number(b.Height || 0)};
            result.windows.push({window_id: Number(w.kCGWindowNumber), pid: pid,
                title: w.kCGWindowName || '', on_screen: visible, layer: layer, bounds: bounds,
                capturable: visible && !hidden[pid] && layer === 0 && bounds.width > 0 && bounds.height > 0 && Number(w.kCGWindowSharingState) > 0});
        });
        var screens = $.NSScreen.screens;
        for (var j = 0; j < Number(screens.count); j++) {
            var screen = screens.objectAtIndex(j);
            var frame = screen.frame;
            result.displays.push({display_id: Number(ObjC.unwrap(screen.deviceDescription.objectForKey('NSScreenNumber'))),
                index: j + 1, bounds: {x: Number(frame.origin.x), y: Number(frame.origin.y),
                    width: Number(frame.size.width), height: Number(frame.size.height)}});
        }
        if (!result.displays.length) return JSON.stringify({error: 'No graphical displays available'});
        return JSON.stringify(result);
    } catch (error) {
        return JSON.stringify({error: 'Native GUI inspection failed: ' + String(error)});
    }
}
