// Appended after enumerate.js by check-darwin.sh. Override only the entry point;
// exercise the shipped unwrapCF with REAL native refs, without querying a GUI,
// prompting for permission, or reading screen contents.
function run() {
    // Check the REAL shipped API bindings, without calling any permission or
    // desktop inspection function. Synthetic CF tests alone miss absent APIs.
    if (typeof $.CGPreflightScreenCaptureAccess !== 'function' ||
        typeof $.CGRequestScreenCaptureAccess !== 'function' ||
        typeof $.CGSessionCopyCurrentDictionary !== 'function' ||
        typeof $.CGWindowListCopyWindowInfo !== 'function' ||
        typeof $.CGDisplayBounds !== 'function') {
        throw new Error('required CoreGraphics API binding unavailable');
    }
    ObjC.import('Foundation');
    var array = unwrapCF($.CFArrayCreate(null, null, 0, null));
    var dictionary = unwrapCF($.CFDictionaryCreate(null, null, null, 0, null, null));
    if (!Array.isArray(array) || array.length !== 0 || !dictionary ||
        typeof dictionary !== 'object' || Object.keys(dictionary).length !== 0) {
        throw new Error('Core Foundation collection bridging failed');
    }
    var xml = '<plist version="1.0"><dict>' +
        '<key>kCGSSessionUserIDKey</key><integer>501</integer>' +
        '<key>kCGSSessionOnConsoleKey</key><true/>' +
        '<key>windows</key><array><dict><key>kCGWindowNumber</key><integer>456</integer></dict></array>' +
        '</dict></plist>';
    var data = $(xml).dataUsingEncoding($.NSUTF8StringEncoding);
    var nested = unwrapCF($.CFPropertyListCreateWithData(null, data, 0, null, null));
    if (nested.kCGSSessionUserIDKey !== 501 || nested.kCGSSessionOnConsoleKey !== true ||
        !Array.isArray(nested.windows) || nested.windows[0].kCGWindowNumber !== 456) {
        throw new Error('nested Core Foundation values did not unwrap');
    }
    var rectangle = $.CGRectMake(-1920, -1080, 1920, 1080);
    if (Number(rectangle.origin.x) !== -1920 || Number(rectangle.origin.y) !== -1080 ||
        Number(rectangle.size.width) !== 1920 || Number(rectangle.size.height) !== 1080) {
        throw new Error('CoreGraphics rectangle bridging failed');
    }
    return 'native host-observation CF/CGRect and API bindings: passed (no GUI/TCC attestation)';
}
