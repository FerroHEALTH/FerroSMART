- The EUDI Wallet login offers the W3C Digital Credentials API beside the
  redirect, as Implementing Regulation (EU) 2024/2979 Annex II, amended by
  2026/1731, requires of a relying party. The browser first shows a page
  at `{issuer}/wallet`. Its "Open your wallet" link invokes the wallet by
  redirect. Where the browser has the API, the page's module asks for the
  PID with a request signed for the page's origin (`openid4vp-v1-signed`,
  `dc_api.jwt`) and posts the answer to `{issuer}/wallet/dc`. The answer
  is checked as in the redirect lane, bound to the page's origin.
  `[ferrosmart.upstream.openid4vp] digital_credentials_api = false` sends
  the browser straight to the wallet.
