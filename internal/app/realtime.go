package app

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (a *App) broadcast() {
	a.eventsMu.Lock()
	defer a.eventsMu.Unlock()
	for ch := range a.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
func (a *App) serveEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	a.mu.Lock()
	u, _, isAPI := a.session(r)
	a.mu.Unlock()
	if u == nil || isAPI {
		http.Error(w, "Sign in required", 401)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unavailable", 500)
		return
	}
	http.NewResponseController(w).SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()
	ch := make(chan struct{}, 1)
	a.eventsMu.Lock()
	if a.subscribers == nil {
		a.subscribers = map[chan struct{}]struct{}{}
	}
	a.subscribers[ch] = struct{}{}
	a.eventsMu.Unlock()
	defer func() { a.eventsMu.Lock(); delete(a.subscribers, ch); a.eventsMu.Unlock() }()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			a.mu.Lock()
			current, _, _ := a.session(r)
			a.mu.Unlock()
			if current == nil {
				return
			}
			if _, e := fmt.Fprint(w, "event: change\ndata: {\"changed\":true}\n\n"); e != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			a.mu.Lock()
			current, _, _ := a.session(r)
			a.mu.Unlock()
			if current == nil {
				return
			}
			if _, e := fmt.Fprint(w, ": heartbeat\n\n"); e != nil {
				return
			}
			flusher.Flush()
		}
	}
}
func (a *App) collectorRoute(req *http.Request, u, b M) result {
	if req.Method == "GET" {
		requirePage(u, "collectors", "view")
	} else {
		requireAdmin(u)
	}
	if req.URL.Path == "/api/collectors" {
		if req.Method == "GET" {
			rows := []M{}
			for _, c := range a.q("SELECT id,name,org_id AS orgId,asset_id AS assetId,created,expires,last_seen AS lastSeen FROM collectors ORDER BY created DESC") {
				host := a.get("SELECT * FROM records WHERE id=? AND deleted IS NULL", c["assetId"])
				if withinOrgScope(u, host) {
					rows = append(rows, c)
				}
			}
			return out(200, rows)
		}
		if req.Method == "POST" {
			name := strings.TrimSpace(S(b, "name"))
			if name == "" {
				fail(400, "Collector name is required")
			}
			var host M
			cid := id()
			if S(b, "assetId") == "" {
				organization := a.raw(u, S(b, "orgId"), false)
				if S(organization, "type") != "organizations" {
					fail(400, "Choose an organization for discovery")
				}
				created := a.insert(u, "assets", M{"name": "Discovery host — " + name, "orgId": organization["id"], "category": "Computer", "status": "Awaiting discovery", "autoDiscovered": true, "collectorId": cid, "sourceKey": "host", "discoverySource": "Endpoint collector"})
				host = a.get("SELECT * FROM records WHERE id=?", created["id"])
			} else {
				host = a.raw(u, S(b, "assetId"), false)
			}
			if S(b, "orgId") != "" && S(host, "org_id") != S(b, "orgId") {
				fail(400, "The selected host belongs to another organization")
			}
			if S(host, "type") != "assets" {
				fail(400, "Choose the device where this collector will run")
			}
			rawToken, expires := "tri_collector_"+token(32), time.Now().Add(90*24*time.Hour).UnixMilli()
			a.run("INSERT INTO collectors(id,name,org_id,asset_id,user_id,hash,created,expires) VALUES(?,?,?,?,?,?,?,?)", cid, name, S(host, "org_id"), S(host, "id"), S(u, "id"), digest(rawToken), timestamp(), expires)
			a.audit(u, "collector_created", cid, S(host, "id"))
			return out(201, M{"id": cid, "token": rawToken, "expires": expires, "assetId": host["id"]})
		}
	}
	if req.Method == "DELETE" {
		cid := strings.TrimPrefix(req.URL.Path, "/api/collectors/")
		a.run("DELETE FROM collectors WHERE id=?", cid)
		a.run("DELETE FROM discovery_profiles WHERE collector_id=?", cid)
		a.audit(u, "collector_revoked", cid, "")
		return out(200, M{"ok": true})
	}
	fail(405, "Method not allowed")
	return result{}
}
func (a *App) telemetry(req *http.Request, b M) result {
	collector, u, host := a.collectorAuth(req)
	oid, cid := S(collector, "org_id"), S(collector, "id")
	if S(host, "org_id") != oid {
		fail(409, "Collector device moved organizations; register the collector again")
	}
	samples, ok := b["connections"].([]any)
	if !ok || len(samples) > 2000 {
		fail(400, "Submit up to 2000 connections")
	}
	existing := map[string]M{}
	for _, r := range a.q("SELECT * FROM records WHERE org_id=? AND deleted IS NULL", oid) {
		d := decode(S(r, "data"))
		if S(d, "collectorId") == cid {
			existing[S(d, "sourceKey")] = r
		}
	}
	actor := clone(u)
	actor["name"] = "Collector: " + S(collector, "name")
	observed := timestamp()
	upsert := func(kind, key string, d M) M {
		d["orgId"] = oid
		d["collectorId"] = cid
		d["sourceKey"] = key
		d["visibility"] = "internal"
		d["observed"] = true
		d["lastSeen"] = observed
		if r := existing[key]; r != nil {
			previous := decode(S(r, "data"))
			for _, field := range []string{"approvalStatus", "approvedAt", "approvedBy", "listeningPorts", "servicePort", "notes", "customFields", "relatedIds"} {
				if _, present := d[field]; (!present || field == "notes") && previous[field] != nil {
					d[field] = previous[field]
				}
			}
			delete(previous, "lastSeen")
			compare := clone(d)
			delete(compare, "lastSeen")
			if J(previous) == J(compare) {
				a.run("UPDATE records SET data=?,updated=? WHERE id=?", J(d), observed, S(r, "id"))
				return a.safe(a.get("SELECT * FROM records WHERE id=?", S(r, "id")))
			}
			d["version"] = r["version"]
			result := a.update(actor, r, d)
			existing[key] = a.get("SELECT * FROM records WHERE id=?", S(result, "id"))
			return result
		}
		result := a.insert(actor, kind, d)
		existing[key] = a.get("SELECT * FROM records WHERE id=?", S(result, "id"))
		return result
	}
	var discovery any
	if snapshot, ok := b["discovery"].(map[string]any); ok {
		if obj(a.discoveryProfile(cid)["config"])["enabled"] == false {
			fail(409, "Discovery is disabled for this collector")
		}
		discovery = a.ingestDiscovery(collector, actor, host, snapshot, observed, upsert)
		host = a.get("SELECT * FROM records WHERE id=?", collector["asset_id"])
	}
	apps := map[string]M{}
	listeners := map[string]M{}
	appPorts := map[string][]M{}
	for _, v := range samples {
		s := obj(v)
		pid, process := S(s, "pid"), S(s, "process")
		if process == "" {
			process = "Process " + pid
		}
		appKey := "app:" + pid + ":" + process
		port := N(s, "localPort")
		if port < 1 || port > 65535 {
			continue
		}
		app := apps[appKey]
		if app == nil {
			app = upsert("services", appKey, M{"name": process + " @ " + S(decode(S(host, "data")), "name"), "assetId": host["id"], "protocol": strings.ToUpper(S(s, "protocol")), "status": "Active", "notes": "Observed process PID " + pid, "serviceKind": "Network process", "processName": process, "pid": pid})
			raw := a.get("SELECT * FROM records WHERE id=?", S(app, "id"))
			details := decode(S(raw, "data"))
			for k, v := range serviceReview(process, 0, "") {
				details[k] = v
			}
			app = a.observedUpdate(actor, raw, details)
			apps[appKey] = app
		}
		if strings.EqualFold(S(s, "state"), "LISTENING") || strings.EqualFold(S(s, "state"), "LISTEN") {
			raw := a.get("SELECT * FROM records WHERE id=?", S(app, "id"))
			details := decode(S(raw, "data"))
			review := serviceReview(process, port, S(s, "localAddress"))
			if S(details, "reviewStatus") != "Needs review" || S(review, "reviewStatus") == "Needs review" {
				reasons := strArray(details["reviewReasons"])
				for _, reason := range review["reviewReasons"].([]string) {
					if !contains(reasons, reason) {
						reasons = append(reasons, reason)
					}
				}
				for k, v := range review {
					details[k] = v
				}
				details["reviewReasons"] = reasons
				app = a.observedUpdate(actor, raw, details)
				apps[appKey] = app
			}
			listeners[fmt.Sprint(port)] = app
			appPorts[appKey] = append(appPorts[appKey], M{"port": port, "protocol": strings.ToUpper(S(s, "protocol"))})
			upsert("ports", fmt.Sprintf("listener-port:%s:%s:%v", S(host, "id"), strings.ToUpper(S(s, "protocol")), port), M{"name": fmt.Sprintf("%s %v @ %s", strings.ToUpper(S(s, "protocol")), port, S(decode(S(host, "data")), "name")), "assetId": host["id"], "port": fmt.Sprint(port), "protocol": strings.ToUpper(S(s, "protocol")), "status": "Discovered", "autoDiscovered": true, "discoverySource": "Local listening socket"})

			upsert("dependencies", "listen:"+appKey+":"+fmt.Sprint(port), M{"name": process + " listens on " + fmt.Sprint(port), "sourceId": host["id"], "targetId": app["id"], "targetPort": port, "protocol": strings.ToUpper(S(s, "protocol")), "status": "Observed", "purpose": "Listening service"})
		}
	}
	for appKey, ports := range appPorts {
		application := apps[appKey]
		if application == nil {
			continue
		}
		raw := a.get("SELECT * FROM records WHERE id=?", application["id"])
		d := decode(S(raw, "data"))
		d["listeningPorts"] = ports
		d["servicePort"] = ports[0]["port"]
		d["lastSeen"] = observed
		apps[appKey] = a.observedUpdate(actor, raw, d)
	}
	count := 0
	for _, v := range samples {
		s := obj(v)
		remote, port := S(s, "remoteAddress"), N(s, "remotePort")
		if remote == "" || remote == "*" || remote == "0.0.0.0" || port < 1 || port > 65535 {
			continue
		}
		process := S(s, "process")
		if process == "" {
			process = "Process " + S(s, "pid")
		}
		source := apps["app:"+S(s, "pid")+":"+process]
		if source == nil {
			continue
		}
		var target M
		if strings.HasPrefix(remote, "127.") || remote == "::1" {
			target = listeners[fmt.Sprint(port)]
			if target == nil {
				target = a.safe(host)
			}
		} else {
			for _, r := range a.q("SELECT * FROM records WHERE type='assets' AND org_id=? AND deleted IS NULL", oid) {
				if S(decode(S(r, "data")), "ip") == remote {
					target = a.safe(r)
					break
				}
			}
			if target == nil {
				target = upsert("assets", "remote:"+remote, M{"name": remote, "category": "Endpoint", "ip": remote, "status": "Discovered", "notes": "Remote endpoint observed by collector; ownership is unverified."})
			}
		}
		if S(source, "id") == S(target, "id") {
			continue
		}
		key := "flow:" + S(source, "id") + ":" + S(target, "id") + ":" + fmt.Sprint(port) + ":" + S(s, "protocol")
		upsert("dependencies", key, M{"name": process + " → " + remote + ":" + fmt.Sprint(port), "sourceId": source["id"], "targetId": target["id"], "sourcePort": S(s, "localPort"), "targetPort": port, "protocol": strings.ToUpper(S(s, "protocol")), "status": "Observed", "purpose": S(s, "state")})
		count++
	}
	a.run("UPDATE collectors SET last_seen=? WHERE id=?", observed, cid)
	return out(200, M{"ok": true, "connections": count, "services": len(apps), "observedAt": observed, "discovery": discovery})
}
