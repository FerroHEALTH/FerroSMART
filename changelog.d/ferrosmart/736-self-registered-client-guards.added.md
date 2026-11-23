- A client the app registered itself (RFC 7591), with the source `dynamic`
  the registration endpoint writes, is held to its own guards: it carries
  no organisation approval and no first-party mark, the person always sees
  the consent page for it with a notice that it registered itself and no
  remember box, the page shows only its links on the redirect URI's scheme
  and host (RFC 7591 §5), and an error before the person's login was
  accepted is a page, never a redirect to it (RFC 9700 §4.11.2).
