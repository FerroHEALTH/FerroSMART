// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

// The EUDI Wallet page: the server draws a link that invokes the wallet by
// redirect, which works with no script. Where the browser has the W3C
// Digital Credentials API, a press asks it instead, with the signed
// OpenID4VP request the page carries (OpenID4VP 1.0 Appendix A,
// openid4vp-v1-signed), and the page's form posts the wallet's answer back.
// A browser without the API, or a person who cancels its dialog, follows
// the link. An enhanced offer is marked `data-wallet-ready`.
export const PROTOCOL = "openid4vp-v1-signed";

export function available() {
  return typeof window.DigitalCredential === "function" && Boolean(navigator.credentials);
}

export function query(request) {
  return { mediation: "required", digital: { requests: [{ protocol: PROTOCOL, data: { request } }] } };
}

export function enhance(root) {
  const link = root.querySelector("a[href]");
  const form = root.querySelector("form");
  const request = root.dataset.request;
  if (!link || !form || !request || !available()) return;
  link.addEventListener("click", async (event) => {
    event.preventDefault();
    let credential;
    try {
      credential = await navigator.credentials.get(query(request));
    } catch {
      window.location.assign(link.href);
      return;
    }
    if (!credential || credential.protocol !== PROTOCOL) {
      window.location.assign(link.href);
      return;
    }
    form.elements.namedItem("data").value = JSON.stringify(credential.data);
    form.submit();
  });
  root.dataset.walletReady = "";
}

for (const root of document.querySelectorAll("[data-ferrosmart-wallet]")) enhance(root);
