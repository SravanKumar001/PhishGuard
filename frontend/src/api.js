const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";

function responseErrorMessage(result, statusText) {
  const detail = typeof result === "object" && result !== null ? result.detail : result;
  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg ?? "Invalid request").join("; ");
  }
  if (typeof detail === "string" && detail) return detail;
  return statusText || "Request failed";
}

export async function apiRequest(path, options = {}) {
  const headers = new Headers(options.headers ?? {});
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const base = API_BASE_URL.replace(/\/$/, "");
  const response = await fetch(`${base}${path}`, {
    ...options,
    headers,
    credentials: "include",
  });
  if (response.status === 204) return null;

  const contentType = response.headers.get("content-type") ?? "";
  const result = contentType.includes("application/json")
    ? await response.json()
    : await response.text();
  if (!response.ok) {
    const error = new Error(responseErrorMessage(result, response.statusText));
    error.status = response.status;
    throw error;
  }
  return result;
}

export async function downloadFile(path, filename) {
  const base = API_BASE_URL.replace(/\/$/, "");
  const response = await fetch(`${base}${path}`, { credentials: "include" });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const error = new Error(responseErrorMessage(body, response.statusText));
    error.status = response.status;
    throw error;
  }
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}

export function jsonBody(value) {
  return JSON.stringify(value);
}
