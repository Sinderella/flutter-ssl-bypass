/*
 * diag.js — dump runtime state for Flutter SSL bypass repair.
 *
 * Run with:
 *   frida -U -f com.example.flutterapp -l tools/diag.js --no-pause
 *
 * Writes /data/local/tmp/flutter-diag.txt (or /sdcard/ or app files dir).
 * Pull with:  adb pull /data/local/tmp/flutter-diag.txt
 */

function waitForLibflutter(cb) {
    var handle = setInterval(function () {
        var m = Process.findModuleByName("libflutter.so");
        if (m) { clearInterval(handle); cb(m); }
    }, 0);
}

function asciiToHexPattern(str) {
    var out = "";
    for (var i = 0; i < str.length; i++) {
        if (i > 0) out += " ";
        out += str.charCodeAt(i).toString(16).padStart(2, "0");
    }
    return out;
}

function tryEnumerateRanges(mod, filter) {
    try { return mod.enumerateRanges(filter); } catch (e) { return null; }
}

/**
 * Gather every mapped range the target module lives in.
 * Uses Process.enumerateRanges which accepts a broader filter, then intersects
 * with the module's [base, base+size] window.
 */
function gatherModuleRanges(mod) {
    var modStart = mod.base;
    var modEnd = mod.base.add(mod.size);
    var out = [];
    // Process.enumerateRanges accepts a protection like 'r--'; enumerate the common ones.
    ["r--", "r-x", "rw-", "--x"].forEach(function (prot) {
        var rs;
        try { rs = Process.enumerateRanges(prot); } catch (e) { rs = []; }
        for (var i = 0; i < rs.length; i++) {
            var r = rs[i];
            var rStart = r.base;
            var rEnd = r.base.add(r.size);
            // Intersect with module window.
            if (rEnd.compare(modStart) <= 0) continue;
            if (rStart.compare(modEnd) >= 0) continue;
            out.push({ base: r.base, size: r.size, protection: r.protection });
        }
    });
    // Dedupe
    var seen = {};
    var unique = [];
    for (var i = 0; i < out.length; i++) {
        var k = out[i].base.toString() + ":" + out[i].size;
        if (!seen[k]) { seen[k] = true; unique.push(out[i]); }
    }
    return unique;
}

function scanWholeModule(mod, str) {
    var pattern = asciiToHexPattern(str);
    var hits = [];
    // Approach 1: scan the whole module as one continuous range.
    try {
        var matches = Memory.scanSync(mod.base, mod.size, pattern);
        for (var j = 0; j < matches.length; j++) hits.push({ addr: matches[j].address, via: "module-window" });
    } catch (e) { /* fall through */ }

    // Approach 2: also scan each enumerated sub-range (catches cases where the
    // module window scan throws mid-way on an unmapped page).
    var subranges = gatherModuleRanges(mod);
    for (var r = 0; r < subranges.length; r++) {
        try {
            var m2 = Memory.scanSync(subranges[r].base, subranges[r].size, pattern);
            for (var k = 0; k < m2.length; k++) hits.push({ addr: m2[k].address, via: "sub:" + subranges[r].protection });
        } catch (e) {}
    }

    // Dedupe by address
    var seen = {};
    var unique = [];
    for (var n = 0; n < hits.length; n++) {
        var key = hits[n].addr.toString();
        if (!seen[key]) { seen[key] = true; unique.push(hits[n]); }
    }
    return unique;
}

function readInsnText(addr) {
    try {
        var parsed = Instruction.parse(addr);
        return parsed.mnemonic + " " + (parsed.opStr || "");
    } catch (e) { return "(unreadable)"; }
}

function hexBytes(addr, n) {
    try {
        var bytes = addr.readByteArray(n || 16);
        var u8 = new Uint8Array(bytes);
        var out = "";
        for (var i = 0; i < u8.length; i++) out += u8[i].toString(16).padStart(2, "0") + " ";
        return out.trim();
    } catch (e) { return "(unreadable)"; }
}

function main(mod) {
    var out = [];
    var push = function (line) { out.push(line); };

    push("=== Flutter SSL bypass diagnostic ===");
    push("Time: " + new Date().toISOString());
    push("Process.arch: " + Process.arch);
    push("Process.platform: " + Process.platform);
    push("");

    push("--- Module ---");
    push("name: " + mod.name);
    push("path: " + mod.path);
    push("base: " + mod.base);
    push("size: 0x" + mod.size.toString(16) + " (" + mod.size + ")");
    push("");

    push("--- mod.enumerateRanges by filter ---");
    ["r--", "r-x", "rw-", "--x"].forEach(function (filter) {
        var rr = tryEnumerateRanges(mod, filter);
        if (rr == null) { push("  '" + filter + "' : threw"); return; }
        push("  '" + filter + "' : " + rr.length + " range(s)");
        for (var j = 0; j < rr.length; j++) {
            push("    " + rr[j].base + "  size=0x" + rr[j].size.toString(16) + "  prot=" + rr[j].protection);
        }
    });
    push("");

    push("--- Process.enumerateRanges intersected with module window ---");
    var subranges = gatherModuleRanges(mod);
    push("count: " + subranges.length);
    for (var i = 0; i < subranges.length; i++) {
        push("  " + subranges[i].base + "  size=0x" + subranges[i].size.toString(16) + "  prot=" + subranges[i].protection);
    }
    push("");

    push("--- String scan: ssl_x509.cc path ---");
    var ssl_x509_hits = scanWholeModule(mod, "../../../flutter/third_party/boringssl/src/ssl/ssl_x509.cc");
    push("hits: " + ssl_x509_hits.length);
    for (var k = 0; k < ssl_x509_hits.length; k++) push("  " + ssl_x509_hits[k].addr + " (via " + ssl_x509_hits[k].via + ")");
    push("");

    push("--- String scan: handshake.cc path ---");
    var hs_hits = scanWholeModule(mod, "../../../flutter/third_party/boringssl/src/ssl/handshake.cc");
    push("hits: " + hs_hits.length);
    for (var k = 0; k < hs_hits.length; k++) push("  " + hs_hits[k].addr + " (via " + hs_hits[k].via + ")");
    push("");

    push("--- String scan: ssl_client (with \\0 suffix check) ---");
    var sc_hits = scanWholeModule(mod, "ssl_client");
    push("raw hits: " + sc_hits.length);
    for (var k = 0; k < sc_hits.length; k++) {
        var h = sc_hits[k].addr;
        var nullCheck = "";
        try { nullCheck = "  next=" + h.add(10).readU8(); } catch (e) { nullCheck = "  next=(unreadable)"; }
        push("  " + h + nullCheck + "  bytes=" + hexBytes(h, 16));
    }
    push("");

    // --- ADRP+ADD xref scan against ssl_x509.cc first hit ---
    if (ssl_x509_hits.length > 0) {
        var target = ssl_x509_hits[0].addr;
        push("--- ADRP+ADD xref scan across whole module for target " + target + " ---");

        var pageMask = ptr("0xfffffffffffff000");
        var xrefs = [];

        // Scan the full module window.
        var scanBase = mod.base;
        var scanEnd = mod.base.add(mod.size);
        var p = scanBase;
        var scanned = 0;
        var errors = 0;
        while (p.compare(scanEnd) < 0) {
            var insn;
            try { insn = p.readU32(); } catch (e) { errors++; p = p.add(0x1000); continue; }
            if ((insn & 0x9f000000) === 0x90000000) {
                var adrpRd = insn & 0x1f;
                var immhi = (insn >>> 5) & 0x7ffff;
                var immlo = (insn >>> 29) & 0x3;
                var imm = (immhi << 2) | immlo;
                if (imm & 0x100000) imm |= ~0x1fffff;
                var pcPage = p.and(pageMask);
                var adrpTarget = pcPage.add(imm * 0x1000);
                try {
                    var next = p.add(4).readU32();
                    if ((next & 0x7fc00000) === 0x11000000) {
                        var shift = (next >>> 22) & 0x3;
                        var addImm = (next >>> 10) & 0xfff;
                        if (shift === 1) addImm <<= 12;
                        var addRn = (next >>> 5) & 0x1f;
                        var addRd = next & 0x1f;
                        if (addRn === adrpRd && addRd === adrpRd) {
                            var computed = adrpTarget.add(addImm);
                            if (computed.equals(target)) {
                                xrefs.push({ adrp: p, rd: adrpRd });
                            }
                        }
                    }
                } catch (e) {}
            }
            p = p.add(4);
            scanned++;
        }
        push("  scanned: " + scanned + " instructions, readU32 errors: " + errors);
        push("  xrefs found: " + xrefs.length);
        for (var xi = 0; xi < xrefs.length; xi++) {
            var x = xrefs[xi];
            push("  xref #" + xi + " @ " + x.adrp + "  Rd=X" + x.rd);
            // 6 insns before + the pair + 6 after
            for (var off = -24; off <= 28; off += 4) {
                var a = x.adrp.add(off);
                var marker = (off === 0) ? " <-- ADRP" : (off === 4) ? " <-- ADD" : "";
                push("    " + a + ": " + readInsnText(a) + marker);
            }
            push("");
        }
    }

    // --- Same scan for ssl_client string ---
    if (sc_hits.length > 0) {
        var target2 = sc_hits[0].addr;
        push("--- ADRP+ADD xref scan across whole module for ssl_client " + target2 + " ---");
        var pageMask2 = ptr("0xfffffffffffff000");
        var xrefs2 = [];
        var p2 = mod.base;
        var scanEnd2 = mod.base.add(mod.size);
        var scanned2 = 0;
        while (p2.compare(scanEnd2) < 0) {
            var insn2;
            try { insn2 = p2.readU32(); } catch (e) { p2 = p2.add(0x1000); continue; }
            if ((insn2 & 0x9f000000) === 0x90000000) {
                var adrpRd2 = insn2 & 0x1f;
                var immhi2 = (insn2 >>> 5) & 0x7ffff;
                var immlo2 = (insn2 >>> 29) & 0x3;
                var imm2 = (immhi2 << 2) | immlo2;
                if (imm2 & 0x100000) imm2 |= ~0x1fffff;
                var pcPage2 = p2.and(pageMask2);
                var adrpTarget2 = pcPage2.add(imm2 * 0x1000);
                try {
                    var next2 = p2.add(4).readU32();
                    if ((next2 & 0x7fc00000) === 0x11000000) {
                        var shift2 = (next2 >>> 22) & 0x3;
                        var addImm2 = (next2 >>> 10) & 0xfff;
                        if (shift2 === 1) addImm2 <<= 12;
                        var addRn2 = (next2 >>> 5) & 0x1f;
                        var addRd2 = next2 & 0x1f;
                        if (addRn2 === adrpRd2 && addRd2 === adrpRd2) {
                            var computed2 = adrpTarget2.add(addImm2);
                            if (computed2.equals(target2)) {
                                xrefs2.push({ adrp: p2, rd: adrpRd2 });
                            }
                        }
                    }
                } catch (e) {}
            }
            p2 = p2.add(4);
            scanned2++;
        }
        push("  scanned: " + scanned2 + ", xrefs found: " + xrefs2.length);
        for (var xi2 = 0; xi2 < xrefs2.length; xi2++) {
            var x2 = xrefs2[xi2];
            push("  xref #" + xi2 + " @ " + x2.adrp + "  Rd=X" + x2.rd);
            for (var off2 = -24; off2 <= 28; off2 += 4) {
                var a2 = x2.adrp.add(off2);
                var marker2 = (off2 === 0) ? " <-- ADRP" : (off2 === 4) ? " <-- ADD" : "";
                push("    " + a2 + ": " + readInsnText(a2) + marker2);
            }
            push("");
        }
    }

    push("--- Other anchor string counts ---");
    ["handshake.cc", "x509.cc", "CERTIFICATE_VERIFY_FAILED", "ssl_server", "tls_method.cc", "handshake_client.cc"].forEach(function (s) {
        var hits = scanWholeModule(mod, s);
        push("  '" + s + "' : " + hits.length);
    });
    push("");

    push("=== done ===");

    var body = out.join("\n");
    var paths = [
        "/data/local/tmp/flutter-diag.txt",
        "/sdcard/flutter-diag.txt"
    ];
    try {
        var pkg = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName().toString();
        paths.push("/data/data/" + pkg + "/files/flutter-diag.txt");
    } catch (e) {}

    var written = null;
    for (var pi = 0; pi < paths.length; pi++) {
        try {
            var f = new File(paths[pi], "w");
            f.write(body);
            f.flush();
            f.close();
            written = paths[pi];
            break;
        } catch (e) {}
    }

    if (written) {
        console.log("[diag] wrote " + body.length + " bytes to " + written);
        console.log("[diag] pull with: adb pull " + written);
    } else {
        console.log("[diag] could not write to device; full output follows:");
        console.log(body);
    }
}

waitForLibflutter(main);
