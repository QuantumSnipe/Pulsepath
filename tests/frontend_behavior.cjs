// Exercise the shipped inline JavaScript without a browser or third-party packages.
// These DOM stubs cover rendering and events; they do not validate CSS or layout.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");

class Element {
  constructor(tagName = "div") {
    this.tagName = tagName;
    this.children = [];
    this.attributes = {};
    this.style = { setProperty(name, value) { this[name] = String(value); } };
    this.dataset = {};
    this.events = {};
    this.value = "";
    this.hidden = false;
    this.disabled = false;
    this._text = "";
    this.classList = {
      contains: name => this.className.split(/\s+/).includes(name),
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/), ...names])].join(" ").trim(); },
      remove: (...names) => { this.className = this.className.split(/\s+/).filter(name => !names.includes(name)).join(" "); },
      toggle: (name, force) => {
        const enabled = force === undefined ? !this.classList.contains(name) : force;
        this.classList[enabled ? "add" : "remove"](name);
        return enabled;
      },
    };
  }
  get className() { return this.attributes.class || ""; }
  set className(value) { this.attributes.class = value; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(""); }
  set textContent(value) { this._text = String(value); this.children = []; }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
    if (name.startsWith("data-")) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = String(value);
  }
  getAttribute(name) { return this.attributes[name] ?? null; }
  removeAttribute(name) { delete this.attributes[name]; }
  append(...nodes) { this.children.push(...nodes); }
  appendChild(node) { this.append(node); return node; }
  replaceChildren(...nodes) { this._text = ""; this.children = nodes; }
  addEventListener(name, callback) { this.events[name] = callback; }
  click() { if (!this.disabled) return this.events.click?.({ currentTarget: this, target: this, preventDefault() {}, stopPropagation() {} }); }
  matches(selector) {
    if (selector.startsWith(".")) return this.classList.contains(selector.slice(1));
    if (selector.startsWith("#")) return this.getAttribute("id") === selector.slice(1);
    if (selector.startsWith("[")) return this.getAttribute(selector.slice(1, -1)) !== null;
    return this.tagName === selector;
  }
  querySelectorAll(selector) {
    return this.children.flatMap(child => [...(child.matches(selector) ? [child] : []), ...child.querySelectorAll(selector)]);
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  getTotalLength() { return 100; }
  getPointAtLength(length) { return { x: length, y: length }; }
  getBoundingClientRect() { return { left: 0, top: 0, width: 1600, height: 800 }; }
  setPointerCapture(id) { this.capturedPointer = id; }
  hasPointerCapture(id) { return this.capturedPointer === id; }
  releasePointerCapture() { this.capturedPointer = null; }
}

function createApp(protocol = "http:", { reducedMotion = false, hidden = false, timeZone = null } = {}) {
  const elements = new Map();
  for (const match of html.matchAll(/<([a-z][a-z0-9]*)\b([^>]*\bid="([^"]+)"[^>]*)>/gi)) {
    const element = new Element(match[1]);
    element.setAttribute("id", match[3]);
    element.className = match[2].match(/\bclass="([^"]*)"/)?.[1] || "";
    element.hidden = /\bhidden\b/.test(match[2]);
    elements.set(match[3], element);
  }
  const documentEvents = new Map();
  const document = {
    hidden,
    addEventListener: (name, callback) => documentEvents.set(name, callback),
    getElementById: id => elements.get(id) || [...elements.values()].map(element => element.querySelector(`#${id}`)).find(Boolean) || null,
    createElement: tag => new Element(tag),
    createElementNS: (_, tag) => new Element(tag),
    createDocumentFragment: () => new Element("fragment"),
    querySelectorAll: selector => [...elements.values()].flatMap(element => element.querySelectorAll(selector)),
  };
  let now = 1_800_000_000_000;
  let responseFor = () => { throw new Error("No collector response scheduled"); };
  const timers = new Map();
  let nextTimer = 1;
  const frames = new Map();
  let nextFrame = 1;
  const location = { protocol, hostname: "127.0.0.1", origin: "http://127.0.0.1:8765" };
  const motionEvents = new Map();
  const motionPreference = {
    matches: reducedMotion,
    addEventListener: (name, callback) => motionEvents.set(name, callback),
  };
  const window = {
    location,
    setTimeout: callback => { const id = nextTimer++; timers.set(id, callback); return id; },
    clearTimeout: id => timers.delete(id),
    addEventListener() {},
    matchMedia: () => motionPreference,
  };
  const context = vm.createContext({
    document, window, location, navigator: {}, console, URL, AbortController,
    // A pinned zone keeps the time-zone origin estimate the same on every machine.
    Intl: timeZone ? Object.assign(Object.create(Intl), {
      DateTimeFormat: (locale, options) => new Intl.DateTimeFormat(locale, { timeZone, ...options }),
    }) : Intl,
    Date: class extends Date { static now() { return now; } },
    performance: { now: () => now },
    requestAnimationFrame: callback => { const id = nextFrame++; frames.set(id, callback); return id; },
    cancelAnimationFrame: id => frames.delete(id),
    fetch: async (url, options) => {
      if (url.startsWith("data/")) return { ok: false };
      return responseFor(url, options);
    },
  });
  let source = html.split("<script>")[1].split("</script>")[0];
  // Leave all initialization and rendering intact. Drive the two recurring
  // network loops explicitly so one check cannot race another scheduled poll.
  source = source.replace(/^\s*pollCollector\(\);\s*$/m, "").replace(/^\s*(?:if \(location.protocol !== "file:"\) )?pollSecurity\(\);\s*$/m, "");
  source = source.replace(/\}\)\(\);\s*$/, `
    globalThis.app = {
      pollCollector, pollSecurity, setSourceMode, liveFlowToDisplay, showFindingConnection, pollTrace,
      applyTraceToFlow, renderText, renderRoute, startTrace, stopTrace, selectFlow, probePacing,
      state: () => ({ sourceMode, collectorState, lastSuccessfulPoll, flows, selected, latestLocalFlows, showIntermediateHops, tx, ty, zoom }),
    };
  })();`);
  vm.runInContext(source, context, { filename: "index.html" });
  return {
    ...context.app, elements, timers, frames,
    setReducedMotion: matches => {
      motionPreference.matches = matches;
      motionEvents.get("change")?.({ matches });
    },
    press(key, { target = { closest: () => null }, ...modifiers } = {}) {
      documentEvents.get("keydown")?.({
        key, target, repeat: false, metaKey: false, ctrlKey: false, altKey: false, ...modifiers, preventDefault() {},
      });
    },
    setHidden: hidden => {
      document.hidden = hidden;
      documentEvents.get("visibilitychange")?.();
    },
    frame(seconds = 1 / 60) {
      now += seconds * 1000;
      const scheduled = [...frames];
      frames.clear();
      scheduled.forEach(([, callback]) => callback(now));
    },
    respond: callback => { responseFor = callback; },
    advance: seconds => { now += seconds * 1000; },
    now: () => now / 1000,
    async tick(name) {
      const scheduled = [...timers].find(([, callback]) => callback.name === name);
      assert.ok(scheduled, `${name} must be scheduled`);
      timers.delete(scheduled[0]);
      await scheduled[1]();
    },
    async poll(rows, status = {}, failAt = null, scheduled = false, flowsOK = true) {
      responseFor = url => {
        if (url === failAt) throw new Error("Collector disconnected");
        if (url === "/api/status") return { ok: true, json: async () => ({ last_successful_poll: now / 1000, active_window_seconds: 10, last_error: null, ...status }) };
        if (url === "/api/flows") return { ok: flowsOK, json: async () => ({ flows: rows }) };
        throw new Error(`Unexpected request: ${url}`);
      };
      if (scheduled) await this.tick("pollCollector");
      else {
        for (const [id, callback] of timers) if (callback.name === "pollCollector") timers.delete(id);
        await context.app.pollCollector();
      }
    },
  };
}

function row(now, overrides = {}) {
  return {
    id: "browser-https", process: "Browser", protocol: "TCP", service: "HTTPS",
    remote_ip: "203.0.113.20", remote_port: 443, local_ip: "192.0.2.10", local_port: 50001,
    interface: "en0", last_seen: now, socket_count: 1, active: true,
    ...overrides,
  };
}

async function checkTraceControls() {
  const app = createApp();
  const first = row(app.now(), { trace_flow_id: "socket-a" });
  const second = row(app.now(), { id: "second", trace_flow_id: "socket-b", remote_ip: "203.0.113.30" });
  await app.poll([first, second]);
  const trace = { flow_id: "socket-a", target: first.remote_ip, status: "running", started_at: 1, hops: [] };
  const reply = result => ({ ok: true, status: 200, json: async () => result });
  const activities = () => app.elements.get("activityList").querySelectorAll(".activity");
  app.respond(() => reply(trace));
  await app.startTrace();
  assert.match(activities()[0].textContent, /Calculating route/);
  assert.equal(activities()[0].classList.contains("tracing"), true);
  assert.equal(activities()[1].classList.contains("tracing"), false);
  assert.equal(app.elements.get("traceRouteButton").textContent, "Stop tracing route");
  assert.equal(app.elements.get("hopTraceButton").disabled, false);
  app.selectFlow(1);
  assert.equal(app.elements.get("traceRouteButton").textContent, "Trace route");
  assert.equal(activities()[0].classList.contains("tracing"), true, "Selecting another connection must retain the running trace indicator");
  // A second probe can run independently, and stopping one must not stop it.
  app.respond(() => reply({ ...trace, flow_id: "socket-b", target: second.remote_ip }));
  await app.startTrace();
  app.selectFlow(0);
  let resolveOldPoll;
  app.respond(() => new Promise(resolve => { resolveOldPoll = resolve; }));
  const oldPoll = app.pollTrace("socket-a", first.id);
  let stopURL;
  app.respond((url, options) => { stopURL = url; assert.equal(options.method, "POST"); return reply({ ...trace, status: "cancelled" }); });
  await app.stopTrace();
  assert.equal(stopURL, "/api/traces/socket-a/stop", "Stop targets the originally traced socket");
  assert.equal(activities()[0].classList.contains("tracing"), false);
  assert.equal(activities()[1].classList.contains("tracing"), true);
  assert.match(app.elements.get("hopDisclosureStatus").textContent, /tracing stopped/i);
  assert.equal(app.elements.get("traceRouteButton").textContent, "Trace route");
  resolveOldPoll(reply(trace));
  await oldPoll;
  assert.equal(activities()[0].classList.contains("tracing"), false, "Late running responses cannot revive cancelled traces");
  // A disappearing socket still has a row and a usable stop action.
  await app.poll([first]);
  app.selectFlow(1);
  assert.equal(app.state().flows[1].active, false);
  assert.equal(app.elements.get("traceRouteButton").hidden, false);
  app.respond(() => { throw new Error("Offline"); });
  await app.stopTrace();
  assert.equal(app.elements.get("traceRouteButton").disabled, false);
  assert.match(activities()[1].textContent, /Trace status unavailable/);
  app.respond(() => reply({ ...trace, target: second.remote_ip, status: "complete" }));
  await app.pollTrace("socket-b", second.id);
  assert.equal(activities()[1].classList.contains("tracing"), true, "Completion preserves the enabled route highlight");
  assert.match(activities()[1].textContent, /Trace enabled/);
  assert.equal(app.elements.get("traceRouteButton").textContent, "Stop tracing route");
  app.respond(() => { throw new Error("A finished calculation needs no cancellation request"); });
  await app.stopTrace();
  assert.equal(activities()[1].classList.contains("tracing"), false, "Explicit Stop disables a completed trace");
  app.selectFlow(0);
  app.respond(() => ({ ok: false, status: 404, json: async () => ({ error: "Connection unavailable" }) }));
  await app.startTrace();
  assert.equal(activities()[0].classList.contains("tracing"), false, "Rejected starts must not leave a tracing badge");
}

async function checkTraceShortcut() {
  const app = createApp();
  await app.poll([row(app.now())]);
  let starts = 0;
  app.respond((url, options) => {
    if (options.method === "POST") starts++;
    return { ok: true, json: async () => ({ target: "203.0.113.20", status: "running", started_at: 1, hops: [] }) };
  });
  app.press("t", { target: { closest: selector => selector.includes("input") ? {} : null } });
  app.press("t", { metaKey: true });
  assert.equal(starts, 0, "Typing a t or pressing a shortcut chord never sends probes");
  app.press("t");
  assert.equal(starts, 1, "T traces the selected connection");
  app.press("T");
  assert.equal(starts, 1, "A second press while the trace is starting does nothing");
  await new Promise(resolve => setImmediate(resolve));
}

async function checkEnabledTraceView() {
  const app = createApp();
  const first = row(app.now());
  const second = row(app.now(), { id: "second", remote_ip: "203.0.113.30" });
  await app.poll([first, second]);
  let starts = 0;
  let result = { target: first.remote_ip, status: "running", started_at: 1, hops: [] };
  app.respond((url, options) => {
    if (options.method === "POST") starts++;
    return { ok: true, json: async () => result };
  });
  await app.startTrace();
  result = { ...result, status: "complete", hops: [
    { index: 1, ip: "192.0.2.1", reply: true, rtt_ms: 5 },
    { index: 2, ip: null, reply: false, rtt_ms: null },
    { index: 3, ip: first.remote_ip, reply: true, rtt_ms: 10 },
  ] };
  await app.pollTrace(first.id, first.id);
  const markers = () => app.elements.get("routeLayer").querySelectorAll(".node-marker");
  const disclosure = app.elements.get("mapExplanation");
  assert.equal(Boolean(disclosure.open), false, "Trace results must not force the details panel open");
  assert.equal(markers().length, 4, "Returned hops must immediately appear on the map");
  assert.equal(app.elements.get("mapShell").classList.contains("show-intermediate-hops"), true, "CSS must keep enabled markers visible too");
  const stream = [...app.elements.get("routeLayer").querySelectorAll(".route-line")]
    .find(path => !path.classList.contains("inferred-segment"));
  assert.ok(stream, "An enabled trace keeps one activity stream");
  assert.match(stream.getAttribute("d"), /\bC\b/, "The traced stream stays a curve instead of a fixed chord");
  const gaps = [...app.elements.get("routeLayer").querySelectorAll(".inferred-segment")]
    .filter(path => path.classList.contains("traced-flow"));
  assert.equal(gaps.length, 2, "Unanswered hops stay marked without replacing the stream");
  assert.ok(gaps.every(path => stream.getAttribute("d").includes(path.getAttribute("d").slice(path.getAttribute("d").indexOf(" C")))),
    "Silent spans overlay the same smoothed stream");
  const packets = () => app.elements.get("routeLayer").querySelectorAll(".packet");
  assert.ok(packets().length > 0, "A live traced route still carries activity markers");
  const before = packets()[0].getAttribute("cx");
  app.frame(0.7);
  assert.notEqual(packets()[0].getAttribute("cx"), before, "Activity keeps moving after a trace is enabled");
  const pulses = app.elements.get("routeLayer").querySelectorAll(".hop-pulse");
  assert.equal(pulses.length, 2, "Each intermediate hop carries a pulse ring");
  const lit = new Set();
  for (let step = 0; step < 60; step++) {
    app.frame(4.2 / 60);
    pulses.forEach((pulse, index) => { if (Number(pulse.style.opacity) > 0) lit.add(index); });
  }
  assert.equal(lit.size, pulses.length, "Every hop lights up as activity passes it");
  app.setReducedMotion(true);
  assert.ok(pulses.every(pulse => Number(pulse.style.opacity) === 0), "Reduced motion leaves no frozen ripple");
  app.setReducedMotion(false);
  for (const open of [true, false]) {
    disclosure.open = open;
    disclosure.events.toggle({ currentTarget: disclosure });
    assert.equal(markers().length, 4, "Details panel toggles cannot change enabled route graphics");
  }
  app.selectFlow(1);
  assert.equal(markers().length, 2, "An untraced connection must not inherit other route markers");
  assert.match(app.elements.get("activityList").querySelectorAll(".activity")[0].textContent, /Trace enabled/);
  app.selectFlow(0);
  assert.equal(markers().length, 4, "Returning to an enabled route restores its markers automatically");
  await app.poll([first, second]);
  assert.equal(markers().length, 4, "Collector refresh must preserve enabled trace results");
  await app.poll([{ ...first, remote_ip: "203.0.113.99" }, second]);
  assert.equal(markers().length, 2, "A rotated endpoint cannot inherit the previous address's trace");
  assert.equal(app.elements.get("activityList").querySelectorAll(".tracing").length, 0);
  await app.poll([first, second]);
  assert.equal(markers().length, 4, "The enabled snapshot belongs to its original endpoint");
  app.setSourceMode("simulation");
  app.setSourceMode("live");
  assert.equal(markers().length, 4, "Switching views must preserve the enabled trace");
  assert.equal(starts, 1, "Keeping a trace enabled must not repeatedly probe the network");
  await app.stopTrace();
  assert.equal(markers().length, 2, "Stop returns the map to connection endpoints");
  assert.equal(app.elements.get("activityList").querySelectorAll(".tracing").length, 0);
  await app.poll([first, second]);
  assert.equal(markers().length, 2, "Polling cannot resurrect a disabled trace");
}

function checkMapGestures() {
  const app = createApp("file:");
  const map = app.elements.get("map");
  const marker = app.elements.get("routeLayer").querySelectorAll(".node-marker").at(-1);
  const inspector = app.elements.get("hopInspector");
  function pointer(type, x, y, extra = {}) {
    map.events[type]({ type, button: 0, pointerId: 1, clientX: x, clientY: y,
      target: { closest: () => marker }, preventDefault() {}, ...extra });
  }
  pointer("pointerdown", 100, 100);
  pointer("pointermove", 160, 120, { pointerId: 2 });
  assert.equal(app.state().tx, 0, "Other pointers cannot move the active gesture");
  pointer("pointermove", 160, 120);
  assert.equal(app.state().tx, 60, "Dragging from a marker pans the map");
  assert.equal(app.state().ty, 20);
  pointer("pointerup", 160, 120);
  marker.events.click({ detail: 1, stopPropagation() {} });
  assert.equal(inspector.hidden, true, "A drag and its generated click must not select a hop");
  assert.equal(map.classList.contains("dragging"), false);
  assert.equal(map.hasPointerCapture(1), false);
  pointer("pointerdown", 100, 100);
  pointer("pointercancel", 100, 100);
  assert.equal(inspector.hidden, true, "Cancelled presses cannot open details");
  pointer("pointerdown", 100, 100);
  pointer("lostpointercapture", 100, 100);
  pointer("pointermove", 180, 100);
  assert.equal(app.state().tx, 60, "Lost capture must stop panning");
  pointer("pointerdown", 100, 100);
  pointer("pointerup", 102, 101);
  assert.equal(inspector.hidden, false, "A marker tap with small hand movement still opens details");
}

function checkProbeTimingPacesTheStream() {
  const app = createApp();
  // Five equally spaced points, so any difference in time share comes from timing.
  const paced = hops => app.probePacing({
    remoteIp: "203.0.113.9",
    points: [0, 1, 2, 3, 4].map(step => ({ lon: step * 10, lat: 0, ...(step % 4 ? { hopIndex: step } : {}) })),
    traceResult: { hops },
  });
  const hop = (index, rtt_ms) => ({ index, ip: `192.0.2.${index}`, reply: rtt_ms != null, rtt_ms });
  const destination = rtt_ms => ({ index: 4, ip: "203.0.113.9", reply: true, rtt_ms });
  const spans = times => times.slice(1).map((time, i) => time - times[i]);

  const slowLast = spans(paced([hop(1, 5), hop(2, 10), hop(3, 15), destination(55)]));
  assert.ok(slowLast.at(-1) > slowLast[0] * 3, "The span that added the most delay takes the longest");
  const noisy = paced([hop(1, 5), hop(2, 80), hop(3, 15), destination(55)]);
  assert.ok(spans(noisy).every(span => span >= 0), "A slow router reply cannot send the stream backward");
  const tail = paced([hop(1, 5), hop(2, 30), hop(3, null)]);
  assert.ok(Math.abs(tail[4] - tail[2] - .5) < .02, "Spans past the last reply keep the average pace");
  assert.equal(paced([hop(1, null), hop(2, null), destination(55)]), null, "One reply is too little to pace by");
}

function checkRoundTripLimitsGeoEstimates() {
  const app = createApp("http:", { timeZone: "Europe/Zurich" });
  const zurich = { city: "Zurich", country: "Switzerland", longitude: 8.54, latitude: 47.37 };
  const edge = app.liveFlowToDisplay(row(app.now(), {
    id: "edge", remote_ip: "203.0.113.61", geo: zurich,
    sockets: [{ id: "socket-edge", remote_ip: "203.0.113.61", rtt_ms: 13.9, last_seen: app.now() }],
  }));
  app.applyTraceToFlow(edge, { target: "203.0.113.61", status: "complete", hops: [
    { index: 1, ip: "192.0.2.1", reply: true, rtt_ms: 16.1 },
    { index: 2, ip: "198.51.100.2", reply: true, rtt_ms: 13.7, geo: zurich },
    // The fastest reply carries a database city 6,500 km away: at least 65 ms by fiber.
    { index: 3, ip: "198.51.100.6", reply: true, rtt_ms: 13.5, geo: { city: "Mumbai", country: "India", longitude: 72.88, latitude: 19.08 } },
    { index: 4, ip: "198.51.100.9", reply: true, rtt_ms: 20.4, geo: { city: "Dublin", country: "Ireland", longitude: -6.26, latitude: 53.35 } },
    { index: 5, ip: null, reply: false, rtt_ms: null },
  ] });
  const hop = index => edge.points.find(point => point.hopIndex === index);
  assert.equal(hop(3).rejectedGeo, true, "A fast reply cannot come from farther away than its round trip allows");
  assert.equal(hop(2).approximate, true, "A distant database city must not withhold the correct nearby ones");
  assert.equal(hop(4).rejectedGeo, true, "Other hops are still judged against the credible anchor");

  const quiet = app.liveFlowToDisplay(row(app.now(), {
    id: "quiet", remote_ip: "203.0.113.62", geo: { city: "Sydney", country: "Australia", longitude: 151.2, latitude: -33.87 },
    sockets: [{ id: "socket-quiet", remote_ip: "203.0.113.62", rtt_ms: 14, last_seen: app.now() }],
  }));
  app.applyTraceToFlow(quiet, { target: "203.0.113.62", status: "complete", hops: [
    { index: 1, ip: "198.51.100.2", reply: true, rtt_ms: 9, geo: zurich },
    { index: 2, ip: null, reply: false, rtt_ms: null },
  ] });
  assert.equal(quiet.points.at(-1).rejectedGeo, true, "A destination that ignores probes is still held to the connection's round trip");
  const beside = (point, lon, lat) => Math.hypot(point.lon - lon, point.lat - lat);
  assert.ok(beside(quiet.points.at(-1), zurich.longitude, zurich.latitude) < 1, "A withheld destination stays beside the last credible hop");

  const untraced = app.liveFlowToDisplay(row(app.now(), {
    id: "balancer", remote_ip: "203.0.113.63", geo: { city: "Kansas City", country: "United States", longitude: -94.58, latitude: 39.1 },
    sockets: [{ id: "socket-balancer", remote_ip: "203.0.113.63", rtt_ms: 17.7, last_seen: app.now() }],
  }));
  const [mac, balancer] = untraced.points;
  assert.equal(balancer.rejectedGeo, true, "An untraced endpoint is held to its connection's round trip");
  assert.ok(beside(balancer, mac.lon, mac.lat) < 3, "Its marker stays near this Mac instead of the withheld city");
  assert.match(untraced.subtitle, /Kansas City, United States withheld/);
}

async function checkNearRoutesAreFramed() {
  const app = createApp("http:", { timeZone: "Europe/Zurich" });
  await app.poll([
    row(app.now(), { id: "near", remote_ip: "203.0.113.40", geo: { city: "Frankfurt", country: "Germany", longitude: 8.68, latitude: 50.11 } }),
    row(app.now(), { id: "far", remote_ip: "203.0.113.41", geo: { city: "Ashburn", country: "United States", longitude: -77.5, latitude: 39.0 } }),
    row(app.now(), { id: "unlocated", remote_ip: "203.0.113.42" }),
    row(app.now(), { id: "withheld", remote_ip: "203.0.113.43", geo: { city: "Dallas", country: "United States", longitude: -96.8, latitude: 32.8 },
      sockets: [{ id: "socket-withheld", remote_ip: "203.0.113.43", rtt_ms: 12, last_seen: app.now() }] }),
  ]);
  const choose = id => app.selectFlow(app.state().flows.findIndex(flow => flow.id === id));
  choose("near");
  assert.ok(app.state().zoom >= 3, "Choosing a nearby connection zooms to fit it");
  choose("far");
  assert.equal(app.state().zoom, 1, "A transatlantic connection keeps the world view");
  choose("unlocated");
  assert.equal(app.state().zoom, 1, "An unlocated endpoint's visual anchor is never zoomed into");
  choose("withheld");
  assert.equal(app.state().zoom, 4, "A withheld city is framed regionally, not at street level");
}

function checkReferenceLabels() {
  const app = createApp();
  const hosted = app.liveFlowToDisplay(row(app.now(), {
    network_reference: { name: "Google", label: "Google Cloud customer", service_class: "hosted", tag: "Google Cloud",
      category: "Cloud hosting", confidence: "reference", source_name: "Google", source_published: "2026-09-20T00:00:00Z" },
  })).points.at(-1);
  assert.match(hosted.shortDetail, /^Google Cloud customer/, "A hosted address names its class, not just the provider");
  assert.match(hosted.detail, /Reference · Google list/, "A published-range match is tagged Reference with its source");
}

function checkImplausibleDestinationDoesNotPullTheCurve() {
  const app = createApp();
  const far = app.liveFlowToDisplay(row(app.now(), {
    id: "anycast", remote_ip: "1.1.1.1", process: "IPNExtension",
    geo: { city: "Sydney", subdivision: "New South Wales", country: "Australia", longitude: 151.2, latitude: -33.87 },
    network_reference: { name: "Cloudflare", label: "Cloudflare network", anycast: true, category: "anycast" }
  }));
  app.applyTraceToFlow(far, {
    target: "1.1.1.1", status: "complete", hops: [
      { index: 2, ip: "198.51.100.50", reply: true, rtt_ms: 143, geo: { city: "Boston", country: "United States", longitude: -71.06, latitude: 42.36 } },
      { index: 4, ip: null, reply: false, rtt_ms: null },
      { index: 5, ip: "203.0.113.70", reply: true, rtt_ms: 149, geo: { city: "New York", country: "United States", longitude: -74, latitude: 40.71 } },
      { index: 9, ip: "1.1.1.1", reply: true, rtt_ms: 150, geo: { city: "Sydney", country: "Australia", longitude: 151.2, latitude: -33.87 } },
    ]
  });
  const endpoint = far.points.at(-1);
  assert.equal(endpoint.rejectedGeo, true, "A destination city that the timings contradict is withheld");
  assert.ok(Math.abs(endpoint.lon - (-74)) < 8 && endpoint.lat > 30, "The curve ends near the last plausible hop, not the rejected city");
  assert.match(far.subtitle, /Sydney, New South Wales, Australia withheld/);
  assert.match(endpoint.shortDetail, /city withheld/);
  assert.ok(far.points.every(point => Math.hypot(point.lon - 151.2, point.lat + 33.87) > 20),
    "Unanswered hops must not be stretched toward the rejected city");
  const plausible = app.liveFlowToDisplay(row(app.now(), {
    geo: { city: "Boston", country: "United States", longitude: -71.06, latitude: 42.36 }
  }));
  app.applyTraceToFlow(plausible, {
    target: plausible.remoteIp, status: "complete", hops: [
      { index: 1, ip: "192.0.2.1", reply: true, rtt_ms: 143, geo: { city: "Boston", longitude: -71.06, latitude: 42.36 } },
      { index: 2, ip: plausible.remoteIp, reply: true, rtt_ms: 149, geo: { city: "Boston", longitude: -71.06, latitude: 42.36 } },
    ]
  });
  assert.notEqual(plausible.points.at(-1).rejectedGeo, true, "A destination inside the timing budget keeps its estimate");
  assert.equal(plausible.points.at(-1).lon, -71.06);
}

async function checkHopDisclosure() {
  const app = createApp();
  const disclosure = app.elements.get("mapExplanation");
  const list = app.elements.get("hopList");
  const rows = () => list.querySelectorAll(".hop-row");
  const markers = () => app.elements.get("routeLayer").querySelectorAll(".node-marker");
  const toggle = open => {
    disclosure.open = open;
    disclosure.events.toggle({ currentTarget: disclosure, target: disclosure });
    assert.equal(app.state().showIntermediateHops, open);
  };
  assert.equal(list.tagName, "ol", "Probe hops must remain an ordered list");
  assert.equal(rows().length, 0, "No selection must not show old or sample hops");
  const geo = { city: "Example City", country: "Example Country", longitude: 8, latitude: 47 };
  await app.poll([row(app.now(), { geo, sockets: [
    { remote_ip: "203.0.113.20", process: "Browser", pid: 42, interface: "en0", bytes_in: 2048, bytes_out: 1024 },
    { remote_ip: "203.0.113.99", process: "Other", bytes_in: 90000, bytes_out: 90000 },
  ] })]);
  assert.equal(rows().length, 0, "An untraced live connection must not invent intermediate hops");
  const flow = app.state().flows[app.state().selected];
  const trace = {
    target: flow.remoteIp,
    status: "complete",
    hops: [
      { index: 1, ip: "192.0.2.1", hostname: "edge.example.net", reply: true, rtt_ms: 5, geo, asn: { number: 64500, organization: "Example Transit" } },
      { index: 2, ip: null, reply: false, rtt_ms: null },
      { index: 3, ip: "198.51.100.3", reply: true, rtt_ms: 8 },
      { index: 4, ip: "203.0.113.20", reply: true, rtt_ms: 12, geo },
    ],
  };
  app.applyTraceToFlow(flow, trace);
  app.renderText();
  app.renderRoute();
  assert.equal(rows().length, 4, "The ordered probe list includes the destination reply");
  assert.deepEqual(rows().map(element => element.children[0].textContent), [
    "Hop 1 · Responding", "Hop 2 · No response", "Hop 3 · Unlocated", "Hop 4 · Responding",
  ], "Hop order and response status must match the trace");
  assert.ok(rows().every(element => element.tagName === "button"), "Each listed hop must support focus by keyboard");
  assert.match(rows()[0].textContent, /192\.0\.2\.1/);
  assert.match(rows()[0].textContent, /edge\.example\.net/);
  assert.match(rows()[0].textContent, /Responding/);
  assert.match(rows()[0].textContent, /Example City/);
  assert.match(rows()[1].textContent, /No response/);
  assert.doesNotMatch(rows()[1].textContent, /Example City|192\.0\.2\.1|198\.51\.100\.3|VPN|gateway|undefined|null/i, "A silent hop cannot inherit a router identity or location");
  assert.match(rows()[2].textContent, /198\.51\.100\.3/);
  assert.match(rows()[2].textContent, /Unlocated/);
  assert.match(rows()[3].textContent, /destination reply/);
  assert.match(app.elements.get("hopCountBadge").textContent, /4 probe steps/);
  assert.equal(app.elements.get("hopDisclosureLabel").textContent, "Show hop details");
  assert.equal(markers().length, 5, "Completed traces show all collected markers with details collapsed");
  for (let i = 0; i < 9; i++) app.elements.get("zoomIn").click();
  assert.equal(markers().length, 5, "Zooming preserves enabled trace markers with details collapsed");
  const cityEvidence = app.elements.get("cityEvidenceText").textContent;
  const traceEvidence = app.elements.get("cityTraceEvidence").textContent;
  toggle(true);
  assert.equal(markers().length, 5, "Expanding reveals every intermediate marker");
  assert.equal(app.elements.get("hopDisclosureLabel").textContent, "Hide hop details");
  assert.ok(app.elements.get("routeLayer").querySelectorAll(".node-label").length < markers().length, "Expanding must preserve selective map labels");
  assert.equal(app.elements.get("cityEvidenceText").textContent, cityEvidence);
  assert.equal(app.elements.get("cityTraceEvidence").textContent, traceEvidence, "Hop disclosure must preserve destination evidence");
  assert.match(traceEvidence, /never verifies a city|cannot verify a city/);

  const inspector = app.elements.get("hopInspector");
  const facts = () => app.elements.get("hopInspectorFacts").textContent;
  const context = () => app.elements.get("hopConnectionFacts").textContent;
  rows()[0].click();
  assert.equal(inspector.hidden, false);
  assert.match(facts(), /192\.0\.2\.1.*Example Transit.*AS64500.*city unverified.*5\.0 ms/);
  assert.match(context(), /Next probe stepHop 2 · no response; identity unknown/);
  assert.match(context(), /TCP · socket metadata/);
  assert.match(context(), /PID 42 · en0/);
  assert.match(context(), /Received by this Mac2\.0 KB/);
  assert.doesNotMatch(context(), /90|Other/, "Other grouped endpoints must not inflate selected-endpoint counters");
  rows()[1].click();
  assert.match(facts(), /IP addressUnknown · no reply/);
  assert.doesNotMatch(facts(), /Example Transit|Example City|64500|192\.0\.2\.1/, "Silent hops must never inherit another hop's identity or geography");
  assert.match(context(), /Previous probe stepHop 1 · 192\.0\.2\.1/);
  rows()[2].click();
  assert.match(facts(), /198\.51\.100\.3/);
  assert.match(facts(), /Unknown · map position is illustrative/);
  rows()[3].click();
  assert.match(app.elements.get("hopInspectorTitle").textContent, /Hop 4/);
  assert.match(facts(), /12\.0 ms/);
  // Two probe steps can reply with the same destination IP. Selecting the row
  // must retain that step's own RTT rather than using the first matching IP.
  trace.hops.push({ index: 5, ip: flow.remoteIp, reply: true, rtt_ms: 20 });
  app.applyTraceToFlow(flow, trace);
  app.renderText();
  rows()[4].click();
  assert.match(facts(), /20\.0 ms/);
  trace.hops.pop();
  app.applyTraceToFlow(flow, trace);
  app.renderText();
  assert.equal(inspector.hidden, true, "A removed selected step must clear the inspector");

  toggle(false);
  assert.equal(markers().length, 5, "Collapsing details must not hide enabled trace markers");
  assert.equal(app.elements.get("hopDisclosureLabel").textContent, "Show hop details");
  const endpoint = markers().at(-1);
  assert.equal(endpoint.getAttribute("role"), "button");
  assert.equal(endpoint.getAttribute("tabindex"), "0");
  endpoint.events.keydown({ key: "Enter", preventDefault() {}, stopPropagation() {} });
  assert.equal(disclosure.open, true, "Keyboard marker activation opens details");
  assert.equal(inspector.hidden, false);

  for (const result of [{ status: "complete", hops: [] }, { status: "error", error: "Probe failed", hops: [] }]) {
    app.applyTraceToFlow(flow, trace);
    app.renderText();
    assert.equal(rows().length, 4);
    rows()[0].click();
    app.applyTraceToFlow(flow, result);
    app.renderText();
    app.renderRoute();
    assert.equal(rows().length, 0, "Empty and failed traces clear previous hop rows");
    assert.equal(inspector.hidden, true, "Empty and failed traces clear selected hop details");
    assert.equal(app.elements.get("hopCountBadge").textContent, "", "Empty and failed traces clear the previous hop count");
    toggle(true);
    assert.equal(markers().length, 2, "Empty and failed traces clear previous map hops");
    toggle(false);
  }
  app.applyTraceToFlow(flow, trace);
  app.renderText();
  rows()[0].click();
  toggle(true);
  await app.poll([row(app.now(), { id: "replacement", remote_ip: "203.0.113.50" })]);
  assert.equal(inspector.hidden, true, "Automatic connection replacement clears the old selection");
  assert.equal(disclosure.open, false);
  assert.equal(app.state().showIntermediateHops, false);
  await app.poll([]);
  assert.equal(rows().length, 0);
  const sample = createApp("file:");
  const sampleRows = sample.elements.get("hopList").querySelectorAll(".hop-row");
  assert.ok(sampleRows.length > 0, "Simulation keeps its sample intermediate hops available");
  assert.ok(sampleRows.every(element => /sample/i.test(element.textContent)), "Every simulated hop is clearly marked as a sample");
}

async function checkMotionLifecycle() {
  const app = createApp("http:", { reducedMotion: true });
  const packets = () => app.elements.get("routeLayer").querySelectorAll(".packet");
  const positions = () => packets().map(dot => [dot.getAttribute("cx"), dot.getAttribute("cy")]);
  const assertPositioned = () => {
    assert.ok(packets().length > 0, "Static activity markers remain available");
    assert.ok(positions().every(point => point.every(value => value !== null && Number.isFinite(Number(value)))),
      "Every activity marker has a finite route position even without animation");
  };
  await app.poll([row(app.now())]);
  assertPositioned();
  assert.equal(app.frames.size, 0, "Reduced motion at startup schedules no animation frames");
  const still = positions();
  app.frame(.5);
  assert.deepEqual(positions(), still, "Reduced motion holds markers still");
  app.setReducedMotion(false);
  assert.equal(app.frames.size, 1, "Changing the motion preference resumes one animation loop");
  app.frame(.5);
  assert.notDeepEqual(positions(), still, "An enabled frame advances activity along the route");
  app.setReducedMotion(true);
  assert.equal(app.frames.size, 0, "Changing the motion preference cancels a running loop");
  const frozen = positions();
  app.advance(1);
  app.renderRoute();
  assert.deepEqual(positions(), frozen, "Reduced-motion route refreshes preserve the static phase");
  app.setReducedMotion(false);
  const capture = app.elements.get("captureButton");
  capture.click();
  assert.equal(app.frames.size, 0, "Pause cancels the running animation");
  const paused = positions();
  app.advance(1);
  app.renderRoute();
  assertPositioned();
  assert.deepEqual(positions(), paused, "Refreshing a paused route cannot move markers to the SVG origin");
  assert.equal(app.frames.size, 0);
  capture.click();
  assert.equal(app.frames.size, 1, "Resume restarts the animation");
  assert.deepEqual(positions(), paused, "Resume preserves the paused phase");
  app.setHidden(true);
  assert.equal(app.frames.size, 0, "A hidden tab stops scheduling frames");
  app.advance(2);
  app.renderRoute();
  assert.deepEqual(positions(), paused, "Background refreshes preserve the current phase");
  assert.equal(app.frames.size, 0);
  app.setHidden(false);
  assert.equal(app.frames.size, 1, "A visible active tab restarts one loop");
  capture.click();
  app.setHidden(true);
  app.setHidden(false);
  app.setReducedMotion(true);
  app.setReducedMotion(false);
  assert.equal(app.frames.size, 0, "Visibility and system preferences cannot override explicit Pause");
  capture.click();
  await app.poll([row(app.now() - 20)]);
  assert.equal(packets().length, 0, "Inactive observations contain no activity sprites");
  assert.equal(app.frames.size, 0, "Inactive observations schedule no animation");
  await app.poll([]);
  app.showFindingConnection({ id: 101, created_at: app.now(), evidence: {
    process: "Browser", protocol: "TCP", remote_port: 443, remote_ip: "203.0.113.20",
  } });
  assert.equal(app.state().flows[app.state().selected].historical, true);
  assert.equal(packets().length, 0, "Historical previews contain no activity sprites");
  app.setHidden(true);
  app.setHidden(false);
  assert.equal(app.frames.size, 0, "A visibility change cannot animate historical evidence");
}

function checkVisualStylePreservesEvidence() {
  const app = createApp("file:");
  app.selectFlow(1);
  const disclosure = app.elements.get("mapExplanation");
  disclosure.open = true;
  disclosure.events.toggle({ currentTarget: disclosure, target: disclosure });
  const flow = app.state().flows[app.state().selected];
  const evidence = JSON.stringify(flow.points);
  const hopRows = app.elements.get("hopList").textContent;
  const markers = () => app.elements.get("routeLayer").querySelectorAll(".node-marker")
    .map(marker => [marker.getAttribute("data-point-key"), marker.getAttribute("role"), marker.getAttribute("tabindex")]);
  const originalMarkers = markers();
  const inferredSegments = () => app.elements.get("routeLayer").querySelectorAll(".inferred-segment")
    .map(segment => segment.getAttribute("d"));
  const originalInferredSegments = inferredSegments();
  const button = app.elements.get("visualStyleButton");
  for (const luminous of [false, true]) {
    button.click();
    assert.equal(button.getAttribute("aria-pressed"), String(luminous), "Style choice is exposed accessibly");
    assert.equal(app.elements.get("mapShell").classList.contains("luminous"), luminous);
    assert.equal(app.state().flows[app.state().selected], flow, "Style changes preserve the selected connection");
    assert.equal(JSON.stringify(flow.points), evidence, "Style changes preserve route evidence");
    assert.equal(app.state().showIntermediateHops, true, "Style changes preserve hop disclosure");
    assert.equal(app.elements.get("hopList").textContent, hopRows);
    assert.deepEqual(markers(), originalMarkers, "The same markers remain keyboard accessible");
    assert.deepEqual(inferredSegments(), originalInferredSegments, "Style changes preserve inferred-segment distinctions");
    assert.equal(app.frames.size, 1, "Changing style must not duplicate animation loops");
  }
}

async function checkConstellationSelectionAndFiltering() {
  const app = createApp();
  const layer = app.elements.get("constellationLayer");
  const links = () => layer.querySelectorAll(".constellation-link").map(link => link.getAttribute("data-stream-id"));
  const nodes = () => layer.querySelectorAll(".constellation-node");
  const selectedId = () => app.state().flows[app.state().selected]?.id;
  const geo = longitude => ({ city: "Example City", longitude, latitude: 40 });
  const rows = [row(app.now(), { id: "a", process: "Browser", geo: geo(10) }),
    row(app.now(), { id: "b", process: "Editor", remote_ip: "203.0.113.21", geo: geo(30) }),
    row(app.now() - 20, { id: "old", process: "Old App", geo: geo(50) })];
  await app.poll(rows);
  assert.deepEqual(links(), ["b"], "Only other fresh streams belong in the backdrop");
  assert.match(app.elements.get("constellationStatus").textContent, /2 of 2 active streams/);
  let requests = 0;
  app.respond(() => { requests++; throw new Error("Overview interaction must not start probes"); });
  for (const key of ["Enter", " "]) {
    const node = nodes()[0];
    assert.equal(node.getAttribute("role"), "button");
    assert.equal(node.getAttribute("tabindex"), "0");
    node.events.keydown({ key, preventDefault() {}, stopPropagation() {} });
    assert.equal(selectedId(), key === "Enter" ? "b" : "a", "Keyboard activation selects the corresponding live stream");
  }
  const map = app.elements.get("map");
  const node = nodes()[0];
  const pointer = (type, x, y) => map.events[type]({ type, button: 0, pointerId: 7,
    clientX: x, clientY: y, preventDefault() {},
    target: { closest: selector => selector === ".constellation-node" ? node : null } });
  pointer("pointerdown", 100, 100);
  pointer("pointermove", 130, 120);
  pointer("pointerup", 130, 120);
  node.events.click({ detail: 1, stopPropagation() {} });
  assert.equal(selectedId(), "a", "Dragging a background marker pans without selecting it");
  pointer("pointerdown", 100, 100);
  pointer("pointercancel", 100, 100);
  assert.equal(selectedId(), "a", "A cancelled background press cannot select");
  pointer("pointerdown", 100, 100);
  pointer("pointerup", 102, 101);
  assert.equal(selectedId(), "b", "A background tap selects after a small hand movement");
  assert.match(app.elements.get("selectedTitle").textContent, /Editor/);
  assert.equal(requests, 0, "Selecting a constellation stream sends no requests or probes");

  const search = app.elements.get("activitySearch");
  const filter = value => { search.value = value; search.events.input(); };
  filter("Editor");
  assert.equal(selectedId(), "b");
  assert.deepEqual(links(), [], "A filter refreshes the backdrop even if selection stays the same");
  filter("No matching application");
  assert.equal(selectedId(), undefined, "No matches clears the map selection");
  assert.deepEqual(links(), []);
  assert.equal(app.elements.get("routeLayer").querySelectorAll(".route-base").length, 0);
  assert.match(app.elements.get("constellationStatus").textContent, /No matching active streams/);
  filter("");
  assert.equal(selectedId(), "a", "Clearing the search restores an available selection");
  assert.deepEqual(links(), ["b"]);

  const flow = app.state().flows[app.state().selected];
  app.applyTraceToFlow(flow, { target: flow.remoteIp, status: "complete", hops: [
    { index: 1, ip: "192.0.2.1", reply: true, rtt_ms: 5 },
    { index: 2, ip: flow.remoteIp, reply: true, rtt_ms: 10 },
  ] });
  const disclosure = app.elements.get("mapExplanation");
  disclosure.open = true;
  disclosure.events.toggle({ currentTarget: disclosure });
  const points = JSON.stringify(flow.points);
  const button = app.elements.get("constellationButton");
  for (const enabled of [false, true]) {
    button.click();
    assert.equal(button.getAttribute("aria-pressed"), String(enabled));
    assert.equal(selectedId(), "a");
    assert.equal(JSON.stringify(flow.points), points, "Overview toggling preserves trace evidence");
    assert.equal(app.state().showIntermediateHops, true);
    assert.equal(links().length, enabled ? 1 : 0);
    assert.equal(app.frames.size, 1, "Overview and selected route share one animation loop");
  }
}

async function checkConstellationGroupsAndCap() {
  const app = createApp();
  const shared = { city: "Example City", longitude: 8, latitude: 47 };
  await app.poll([row(app.now(), { id: "a", geo: shared }),
    row(app.now(), { id: "b", process: "Editor", remote_ip: "203.0.113.21", geo: shared })]);
  const layer = app.elements.get("constellationLayer");
  const marker = layer.querySelector(".constellation-node");
  assert.equal(layer.querySelectorAll(".constellation-node").length, 1, "Identical map positions share an explicit chooser");
  assert.match(marker.getAttribute("aria-label"), /2 streams.*estimated location/);
  marker.click();
  const picker = app.elements.get("constellationPicker");
  const choices = () => app.elements.get("constellationChoices").querySelectorAll("button");
  assert.equal(picker.hidden, false);
  assert.deepEqual(choices().map(choice => choice.getAttribute("data-stream-choice")), ["a", "b"],
    "Shared-position choices include the selected stream");
  picker.events.keydown({ key: "Escape", preventDefault() {}, stopPropagation() {} });
  assert.equal(picker.hidden, true);
  marker.click();
  app.elements.get("constellationClose").click();
  assert.equal(picker.hidden, true);
  marker.click();
  choices()[1].click();
  assert.equal(app.state().flows[app.state().selected].id, "b");
  assert.equal(picker.hidden, true, "Choosing a stream closes the chooser");
  layer.querySelector(".constellation-node").click();
  await app.poll([]);
  assert.equal(picker.hidden, true, "Removed streams close a stale chooser");
  assert.equal(layer.children.length, 0);

  const rows = Array.from({ length: 30 }, (_, i) => row(app.now(), { id: `stream-${String(i).padStart(2, "0")}`,
    remote_ip: `203.0.113.${i + 1}`, geo: { longitude: -150 + i * 9, latitude: 35 } }));
  await app.poll(rows);
  app.selectFlow(29);
  const links = () => layer.querySelectorAll(".constellation-link").map(link => link.getAttribute("data-stream-id"));
  const visible = links();
  assert.equal(visible.length, 23, "The selected stream occupies one of the 24 displayed slots");
  assert.equal(visible.includes("stream-29"), false, "Selected route is never duplicated in the background");
  assert.match(app.elements.get("constellationStatus").textContent, /24 of 30 active streams.*filter to narrow/);
  assert.equal(app.elements.get("activityList").querySelectorAll(".activity").length, 30, "The map cap does not remove sidebar streams");
  await app.poll(rows.slice().reverse());
  assert.equal(app.state().flows[app.state().selected].id, "stream-29");
  assert.deepEqual(links(), visible, "Collector ordering cannot flicker the visible subset");
}

async function checkConstellationMotionAndFreshness() {
  const app = createApp("http:", { reducedMotion: true });
  const layer = app.elements.get("constellationLayer");
  const positions = () => layer.querySelectorAll(".constellation-pulse").map(dot => [dot.getAttribute("cx"), dot.getAttribute("cy")]);
  const rows = () => [row(app.now() - 20, { id: "inactive" }),
    row(app.now(), { id: "active", remote_ip: "203.0.113.50" })];
  await app.poll(rows());
  assert.equal(app.elements.get("routeLayer").querySelectorAll(".packet").length, 0);
  assert.equal(positions().length, 1, "An inactive selection can retain other active streams as context");
  assert.ok(positions()[0].every(value => value !== null && Number.isFinite(Number(value))));
  assert.equal(app.frames.size, 0);
  const reduced = positions();
  app.advance(1);
  app.renderRoute();
  assert.deepEqual(positions(), reduced, "Reduced motion preserves backdrop phase across refreshes");
  app.setReducedMotion(false);
  assert.equal(app.frames.size, 1, "Background activity can animate without selected-route packets");
  app.frame(.5);
  assert.notDeepEqual(positions(), reduced);
  app.elements.get("captureButton").click();
  const paused = positions();
  app.advance(1);
  app.renderRoute();
  assert.deepEqual(positions(), paused);
  assert.equal(app.frames.size, 0);
  app.setHidden(true);
  app.setHidden(false);
  assert.equal(app.frames.size, 0, "Visibility cannot override explicit pause");
  app.elements.get("captureButton").click();
  app.setHidden(true);
  app.advance(1);
  app.renderRoute();
  assert.deepEqual(positions(), paused, "Hidden-tab refresh cannot move background pulses");
  assert.equal(app.frames.size, 0);
  app.setHidden(false);
  assert.equal(app.frames.size, 1);
  await app.poll([], {}, "/api/status");
  assert.equal(layer.children.length, 0, "Disconnected collector data cannot remain active context");
  assert.equal(app.frames.size, 0);
  await app.poll(rows());
  app.advance(20);
  await app.tick("refreshFreshness");
  assert.equal(layer.children.length, 0, "A clock-aged feed loses all active constellation graphics");
  assert.equal(app.frames.size, 0);
  await app.poll(rows());
  app.showFindingConnection({ id: 900, created_at: app.now(), evidence: {
    process: "Historical App", protocol: "TCP", remote_port: 444, remote_ip: "198.51.100.240",
  } });
  assert.equal(app.state().flows[app.state().selected].historical, true);
  assert.equal(layer.children.length, 0, "Historical investigation hides live overview context");
  assert.equal(app.frames.size, 0);
  assert.match(app.elements.get("constellationStatus").textContent, /Historical focus/);
  const sample = createApp("file:");
  assert.ok(sample.elements.get("constellationLayer").querySelectorAll(".constellation-link").length > 0);
  assert.match(sample.elements.get("constellationStatus").textContent, /sample streams/);
}

async function checkGeoAttribution() {
  const app = createApp();
  const attribution = app.elements.get("geoAttribution");
  assert.equal(attribution.hidden, true, "DB-IP attribution stays hidden until a local database is available");
  await app.poll([], { geoip_available: false, asn_available: false });
  assert.equal(attribution.hidden, true);
  await app.poll([], { geoip_available: true, asn_available: false });
  assert.equal(attribution.hidden, false, "City GeoIP availability shows the DB-IP attribution");
  await app.poll([], { geoip_available: false, asn_available: true });
  assert.equal(attribution.hidden, false, "ASN availability also shows the DB-IP attribution");
  await app.poll([], {});
  assert.equal(attribution.hidden, true, "A status without either database hides the attribution again");
}

async function main() {
  const app = createApp();
  assert.equal(app.state().sourceMode, "live", "HTTP startup should wait for the collector");
  assert.equal(app.state().flows.length, 0, "Startup must not display demo connections");
  assert.equal(app.elements.get("modeButton").hidden, false, "Simulation remains an explicit choice even without a collector");
  await app.poll([]);
  assert.equal(app.state().collectorState, "live", "An empty successful collection is connected");
  assert.equal(app.state().flows.length, 0);

  await app.poll([row(app.now())]);
  assert.equal(app.state().flows.length, 1);
  assert.match(app.elements.get("selectedTitle").textContent, /Browser/);
  assert.ok(app.elements.get("routeLayer").querySelectorAll(".packet").length > 0, "Fresh activity can animate");
  await app.poll([]);
  assert.equal(app.state().flows.length, 0, "An empty poll replaces the prior connection list");
  assert.equal(app.elements.get("routeLayer").querySelectorAll(".route-base").length, 0, "An empty feed clears the selected map route");
  assert.doesNotMatch(app.elements.get("selectedTitle").textContent, /Browser/, "The old selection must not remain visible");
  assert.equal(app.elements.get("traceRouteButton").hidden, true);

  await app.poll([row(app.now())]);
  await app.poll([], {}, "/api/status");
  assert.equal(app.state().sourceMode, "live", "Request failure must not enter simulation");
  assert.equal(app.state().collectorState, "disconnected");
  assert.match(app.elements.get("liveStateText").textContent, /disconnected/i);
  assert.equal(app.elements.get("routeLayer").querySelectorAll(".packet").length, 0, "Disconnected data must stop animating");
  await app.poll([row(app.now())], {}, null, true);
  assert.equal(app.state().collectorState, "live");
  assert.equal(app.state().sourceMode, "live");
  assert.ok(app.elements.get("routeLayer").querySelectorAll(".packet").length > 0);

  for (const failure of ["/api/flows", "malformed", "http-error"]) {
    const lastSuccess = app.state().lastSuccessfulPoll;
    app.advance(1);
    await app.poll(failure === "malformed" ? null : [], {}, failure === "/api/flows" ? failure : null, false, failure !== "http-error");
    assert.equal(app.state().collectorState, "disconnected", `${failure} must be visible as a collection failure`);
    assert.equal(app.state().sourceMode, "live");
    assert.equal(app.state().lastSuccessfulPoll, lastSuccess, "A failed response cannot refresh collection time");
    await app.poll([row(app.now())], {}, null, true);
    assert.equal(app.state().collectorState, "live");
  }

  app.advance(20);
  await app.tick("refreshFreshness");
  assert.equal(app.state().collectorState, "stale", "The clock must age activity even while a request is pending");
  assert.equal(app.elements.get("routeLayer").querySelectorAll(".packet").length, 0);
  await app.poll([row(app.now())]);
  app.advance(20);
  await app.poll([row(app.now() - 20)], { last_successful_poll: app.now() - 20 });
  assert.equal(app.state().collectorState, "stale", "A responding HTTP API does not make stalled collection live");
  assert.equal(app.elements.get("routeLayer").querySelectorAll(".packet").length, 0);
  assert.match(app.elements.get("liveStateText").textContent, /stale/i);
  await app.poll([row(app.now() - 20)]);
  assert.equal(app.state().collectorState, "live");
  assert.equal(app.state().flows[0].active, false, "A healthy collector cannot make an old socket active");
  assert.equal(app.elements.get("routeLayer").querySelectorAll(".packet").length, 0);

  app.elements.get("modeButton").click();
  assert.equal(app.state().sourceMode, "simulation");
  const demoIDs = app.state().flows.map(flow => flow.id).join(",");
  await app.poll([row(app.now())]);
  assert.equal(app.state().sourceMode, "simulation", "Recovery must respect the user's explicit simulation choice");
  assert.equal(app.state().flows.map(flow => flow.id).join(","), demoIDs);
  app.elements.get("modeButton").click();
  assert.equal(app.state().sourceMode, "live");
  assert.equal(app.state().flows[0].id, "browser-https");

  for (const port of [443, 5222, 5228, 8443]) {
    const display = app.liveFlowToDisplay(row(app.now(), { remote_port: port }));
    assert.doesNotMatch(JSON.stringify(display.steps), /\bencrypted\b/i, `Port ${port} is not proof of encryption`);
    assert.match(JSON.stringify(display.steps), /service inferred from port/i);
  }
  const evidence = createApp();
  await evidence.poll([row(evidence.now())]);
  assert.equal(evidence.elements.get("cityEvidenceBadge").textContent, "City unverified");
  assert.match(evidence.elements.get("cityEvidenceText").textContent, /No usable city estimate/);
  const geo = { city: "Example City", country: "Example Country", longitude: 8, latitude: 47 };
  await evidence.poll([row(evidence.now(), { geo })]);
  assert.match(evidence.elements.get("cityEvidenceText").textContent, /Offline GeoIP suggests Example City/);
  assert.equal(evidence.elements.get("cityEvidenceBadge").textContent, "City unverified", "A GeoIP match cannot verify a city");
  await evidence.poll([row(evidence.now(), { geo, network_reference: { name: "Example Network", label: "Example edge", category: "reference", anycast: true } })]);
  assert.match(evidence.elements.get("cityEvidenceText").textContent, /multiple sites/);
  assert.match(evidence.elements.get("cityTraceEvidence").textContent, /cannot verify a city/);
  await evidence.poll([]);
  assert.equal(evidence.elements.get("cityEvidenceBadge").textContent, "No selection");
  const reconnect = createApp();
  await reconnect.poll([]);
  reconnect.showFindingConnection({ id: 99, created_at: reconnect.now(), evidence: { process: "Browser", protocol: "TCP", remote_port: 443, remote_ip: "203.0.113.20" } });
  assert.equal(reconnect.state().flows[reconnect.state().selected].historical, true);
  const fresh = row(reconnect.now(), { sockets: [{ remote_ip: "203.0.113.20", remote_port: 443, last_seen: reconnect.now() }] });
  await reconnect.poll([fresh]);
  assert.equal(reconnect.state().flows[reconnect.state().selected].id, fresh.id, "A historical selection must promote to the reconnected active endpoint");
  const rotated = row(reconnect.now(), { remote_ip: "203.0.113.21" });
  await reconnect.poll([rotated]);
  reconnect.respond(() => ({ ok: true, json: async () => ({ target: "203.0.113.20", status: "complete", hops: [{ index: 1, ip: "203.0.113.20", reply: true, rtt_ms: 1 }] }) }));
  await reconnect.pollTrace("old-socket", rotated.id);
  assert.equal(reconnect.state().flows[0].traceResult, undefined, "A finished trace must not attach to a different endpoint in the group");
  const disconnected = createApp();
  await disconnected.poll([], {}, "/api/status");
  assert.equal(disconnected.state().sourceMode, "live");
  assert.equal(disconnected.state().flows.length, 0, "A first-request failure must not populate demo rows");
  assert.equal(disconnected.elements.get("modeButton").hidden, false);
  assert.equal(createApp("file:").state().sourceMode, "simulation", "Opening the standalone file still provides the demo");
  const transfer = createApp();
  transfer.respond(() => ({ ok: true, json: async () => ({ recording: true, learning: false, attention_count: 1,
    findings: [{ id: 77, severity: "attention", title: "Unusual outbound transfer for Example App",
      explanation: "A sustained measured change. Backups can explain it.", created_at: transfer.now(),
      evidence: { event_type: "outbound_change", process: "Example App", remote_ip: "203.0.113.8", remote_port: 443,
        protocol: "TCP", measured_socket_count: 2, bytes_out: 30000000, window_seconds: 60,
        threshold_bytes_out: 10485760, baseline_window_seconds: 60, baseline_window_count: 6,
        coverage: "All observed sockets; unobserved traffic is unknown" } }],
  }) }));
  await transfer.pollSecurity();
  const transferCard = transfer.elements.get("findingsList").children[0];
  const measurement = transferCard.querySelector("details");
  assert.ok(measurement, "Transfer findings expose their measured evidence");
  assert.equal(measurement.getAttribute("open"), null, "Evidence starts collapsed");
  assert.match(measurement.textContent, /30000000 bytes over 60 seconds/);
  assert.match(measurement.textContent, /unobserved traffic is unknown/);
  assert.match(measurement.textContent, /not verified signing identities/);
  measurement.open = true;
  await transfer.pollSecurity();
  assert.equal(transfer.elements.get("findingsList").querySelector("details").open, true,
    "Refreshing findings must preserve an open evidence disclosure");
  transferCard.querySelector("button").click();
  assert.equal(transfer.state().flows[transfer.state().selected].historical, true, "Recorded transfer opens a historical map preview");
  const together = createApp();
  together.respond(() => ({ ok: true, json: async () => ({ recording: true, learning: false, attention_count: 1,
    findings: [{ id: "coincidence:1,2", severity: "attention", title: "Coinciding changes for Example App",
      explanation: "2 observations of this stream fell within 30 minutes: New destination; Outbound transfer · 30000000 bytes. Together they are a coincidence to review, not a malware verdict.",
      created_at: together.now(),
      evidence: { event_type: "coincidence", process: "Example App", remote_ip: "203.0.113.8", remote_port: 443,
        protocol: "TCP", destination: "203.0.113.8:443",
        signals: [
          { kind: "novelty", label: "New destination", detail: "First contact." },
          { kind: "outbound_change", label: "Outbound transfer · 30000000 bytes", detail: "Measured upload.",
            measured_socket_count: 2, bytes_out: 30000000, window_seconds: 60, threshold_bytes_out: 10485760,
            baseline_window_seconds: 60, baseline_window_count: 6,
            coverage: "All observed sockets; unobserved traffic is unknown" },
        ] } }],
  }) }));
  await together.pollSecurity();
  const togetherCard = together.elements.get("findingsList").children[0];
  assert.match(togetherCard.textContent, /not a malware verdict/);
  assert.deepEqual(
    togetherCard.querySelectorAll(".finding-signal").map(node => node.textContent),
    ["New destination", "Outbound transfer · 30000000 bytes"],
  );
  assert.match(togetherCard.querySelector("details").textContent, /30000000 bytes over 60 seconds/);
  togetherCard.querySelector("button").click();
  assert.equal(together.state().flows[together.state().selected].remoteIp, "203.0.113.8");
  const ordered = createApp();
  const older = row(ordered.now(), { id: "older", process: "Older App", remote_ip: "192.0.2.10", first_seen: ordered.now() - 100 });
  const newer = row(ordered.now(), { id: "newer", process: "Newer App", remote_ip: "198.51.100.10", first_seen: ordered.now() - 5 });
  await ordered.poll([older, newer]);
  assert.equal(ordered.state().flows[0].id, "newer", "A connection that just appeared leads the live list");
  assert.match(ordered.elements.get("activityList").children[0].textContent, /Newer App/);
  assert.match(ordered.elements.get("activityList").children[1].textContent, /Older App/);
  ordered.selectFlow(1);
  await ordered.poll([newer, older]);
  assert.equal(ordered.state().flows.map(flow => flow.id).join(","), "newer,older");
  assert.equal(ordered.state().flows[ordered.state().selected].id, "older", "Reordering must keep the selected connection");
  ordered.elements.get("modeButton").click();
  const demoOrder = ordered.state().flows.map(flow => flow.id).join(",");
  ordered.elements.get("modeButton").click();
  assert.notEqual(demoOrder, "newer,older", "Simulation keeps its example order");
  checkMapGestures();
  await checkTraceControls();
  await checkTraceShortcut();
  await checkEnabledTraceView();
  await checkHopDisclosure();
  checkImplausibleDestinationDoesNotPullTheCurve();
  checkRoundTripLimitsGeoEstimates();
  checkReferenceLabels();
  await checkNearRoutesAreFramed();
  checkProbeTimingPacesTheStream();
  await checkMotionLifecycle();
  checkVisualStylePreservesEvidence();
  await checkConstellationSelectionAndFiltering();
  await checkConstellationGroupsAndCap();
  await checkConstellationMotionAndFreshness();
  await checkGeoAttribution();
  console.log("Frontend polling, recovery, empty selection, simulation, freshness, evidence, hop disclosure, motion lifecycle, visual style, constellation, and attribution checks passed.");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
