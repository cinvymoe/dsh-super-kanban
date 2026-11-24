/**
 * Super Kanban — owner authentication for the plugin HTTP surface.
 *
 * Boundary: the board exposes personal session data, so only the DSH owner may
 * call it.
 * - DSH >= 0.2.3 WebServer runs `authorize(req)` before dispatch (default
 *   `auth: "required"`) and passes the admitted `PeerScope` as the 3rd argument
 *   `handler(req, res, peer)`, including over Desktop's `dsh-app://app` bridge.
 * - DSH 0.2.1-rc.5 .. 0.2.2-rc.5 invokes `handler(req, res)` with 2 arguments
 *   (`peer === undefined`), so we fall back to `connection.admit(req)`.
 *
 * Any unexpected, aborted or non-owner shape fails closed.
 */
import { t } from "./i18n.mjs";

/**
 * @typedef {{ok: true} | {ok: false, status: number, error?: Error}} OwnerAdmission
 */

/**
 * Validate a `PeerScope` supplied directly by DSH WebServer (DSH >= 0.2.3).
 * Never falls back to `connection.admit(req)` when `peer` was explicitly passed.
 *
 * @param {unknown} peer
 * @returns {OwnerAdmission}
 */
function admitSuppliedPeer(peer) {
  if (!peer || typeof peer !== "object") return { ok: false, status: 403 };
  if (peer.signal?.aborted) return { ok: false, status: 401 };
  if (peer.principal?.kind === "owner") return { ok: true };
  return { ok: false, status: 403 };
}

/**
 * Decide whether an HTTP request may use the kanban API.
 * Fails closed: any unexpected/malformed admission result is rejected.
 *
 * @param {{admit?: (req: unknown) => unknown}} connection DSH connection service
 * @param {unknown} req incoming request
 * @param {unknown} [peer] pre-admitted PeerScope from DSH >= 0.2.3 WebServer
 * @returns {OwnerAdmission}
 */
export function ownerAdmission(connection, req, peer) {
  try {
    if (peer !== undefined) return admitSuppliedPeer(peer);
    if (!connection || typeof connection.admit !== "function") return { ok: false, status: 403 };
    const admission = connection.admit(req);
    if (!admission || typeof admission !== "object") return { ok: false, status: 403 };
    if ("rejection" in admission) {
      const status = Number(admission.rejection);
      return { ok: false, status: Number.isInteger(status) && status >= 400 && status <= 599 ? status : 403 };
    }
    if (admission.peer?.signal?.aborted) return { ok: false, status: 401 };
    const principal = admission.peer?.principal;
    if (principal?.kind === "owner") return { ok: true };
    return { ok: false, status: 403 };
  } catch (error) {
    // An admission failure must never become an allow or an unhandled rejection.
    return { ok: false, status: 403, error };
  }
}

/**
 * Localized, human-readable explanation paired with `error: "unauthorized"`.
 *
 * @param {number} status HTTP status code (401 or 403)
 * @returns {string}
 */
export function unauthorizedMessage(status) {
  return status === 403
    ? t("仅当前 DSH 实例的持有者可访问任务看板")
    : t("登录态已失效或未通过本机认证，请刷新页面或重启 DSH 后重试");
}
