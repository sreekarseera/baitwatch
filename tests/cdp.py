"""Tiny Chrome DevTools Protocol helper for driving the headless test instance."""
import json
import urllib.request

import websocket


class CDP:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, timeout=15, suppress_origin=True)
        self._id = 0

    def cmd(self, method, params=None, session_id=None):
        self._id += 1
        msg = {"id": self._id, "method": method, "params": params or {}}
        if session_id:
            msg["sessionId"] = session_id
        self.ws.send(json.dumps(msg))
        while True:
            resp = json.loads(self.ws.recv())
            if resp.get("id") == self._id:
                if "error" in resp:
                    raise RuntimeError(f"{method}: {resp['error']}")
                return resp.get("result", {})

    def close(self):
        self.ws.close()


def browser_ws():
    with urllib.request.urlopen("http://localhost:9222/json/version") as r:
        return json.load(r)["webSocketDebuggerUrl"]


def attach(cdp, target_id):
    """Attach to a target, return session id."""
    return cdp.cmd("Target.attachToTarget", {"targetId": target_id, "flatten": True})["sessionId"]


def evaluate(cdp, session_id, expr, await_promise=False):
    r = cdp.cmd(
        "Runtime.evaluate",
        {"expression": expr, "awaitPromise": await_promise, "returnByValue": True},
        session_id=session_id,
    )
    if "exceptionDetails" in r:
        raise RuntimeError(json.dumps(r["exceptionDetails"])[:500])
    return r["result"].get("value")
