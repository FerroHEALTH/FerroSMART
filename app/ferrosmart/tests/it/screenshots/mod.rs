// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The book's screenshots of the pages a person meets during a launch,
//! taken behind the `FERROSMART_SCREENSHOTS` gate, and the guard that every
//! page route has them.
//!
//! With `FERROSMART_SCREENSHOTS=1` the capture starts FerroSMART on a
//! loopback port over its own database schema (`FERROSMART_TEST_PG_URL`),
//! a stub upstream provider and a stub FHIR server of synthetic patients
//! (`stack`), drives headless Chrome through a chromedriver of its own
//! (`chromedriver`), and takes every shot of [`SHOTS`] in the light and the
//! dark theme at 1440 CSS pixels wide and the page's full height, as
//! `<image>.png` and `<image>-dark.png` under [`IMAGES`]. It then writes the
//! release it ran at to [`CAPTURED`]. Without the gate it returns at once.
//! Chrome and chromedriver are the Chrome for Testing release
//! `scripts/release/journey-tools.sh` installs into `target/journey-tools`.
//!
//! The guard runs in the ordinary suite: every route of
//! [`ferrosmart::server::PAGES`] is shown by a shot, every shot has both
//! images, every image is a shot's, the book shows every light image and
//! links every dark one, and [`CAPTURED`] names the server's version, so a
//! release fails until the images are taken again. No specification
//! governs the screenshots: our own design, after FerroPIX's.

#![expect(
    clippy::panic,
    reason = "a capture step fails the case naming the page or file it was on"
)]

mod chromedriver;
mod stack;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use thirtyfour::prelude::*;

use crate::screenshots::chromedriver::{CHROME_ENV, Chromedriver, installed};
use crate::screenshots::stack::Stack;

/// The environment variable that opts in to the capture.
const SCREENSHOTS_GATE: &str = "FERROSMART_SCREENSHOTS";

/// The book's folder of page screenshots, from the workspace root.
const IMAGES: &str = "website/book/src/integrate/img";

/// The file beside the images that names the release they show.
const CAPTURED: &str = "captured-version.txt";

/// How long a wait keeps trying before the capture fails.
pub(crate) const WAIT: Duration = Duration::from_secs(30);

/// How often a wait reads the page again.
const POLL: Duration = Duration::from_millis(100);

/// The width of every shot, in CSS pixels.
const WIDTH: u32 = 1440;

/// The height of the window a page is laid out in before its full height is
/// measured.
const HEIGHT: u32 = 900;

/// The tallest screenshot, so a page that grows without bound stays a file
/// the book can hold.
const TALLEST: u32 = 8000;

/// The two themes, as `prefers-color-scheme` names them, with what each
/// image's name carries.
const THEMES: [(&str, &str); 2] = [("light", ""), ("dark", "-dark")];

/// How the browser reaches a shot's page.
#[derive(Debug, Clone, Copy)]
enum Visit {
    /// The clinician app's consent page.
    ClinicianConsent,
    /// The patient app's consent page, a patient picked.
    PatientConsent,
    /// The patient picker with a search and its results.
    Picker,
    /// The management page with an app that keeps access.
    Manage,
    /// An authorization request of a client nobody registered.
    UnknownClient,
    /// The consent page of a request that lapsed.
    Lapsed,
    /// The callback of a login another browser began.
    OtherBrowser,
    /// The end-session endpoint's confirmation.
    Logout,
    /// The chooser of an app whose people log in at either provider.
    Chooser,
    /// The EUDI Wallet page.
    Wallet,
}

/// Every shot: the image's name, without the theme suffix and the
/// extension, the route of [`ferrosmart::server::PAGES`] it shows, and how
/// the browser reaches it.
const SHOTS: [(&str, &str, Visit); 10] = [
    ("consent-clinician", "/consent", Visit::ClinicianConsent),
    ("consent-patient", "/consent", Visit::PatientConsent),
    ("picker", "/picker", Visit::Picker),
    ("manage", "/manage", Visit::Manage),
    ("error-unknown-client", "/authorize", Visit::UnknownClient),
    ("error-lapsed", "/consent", Visit::Lapsed),
    ("error-other-browser", "/callback", Visit::OtherBrowser),
    ("logout-confirm", "/logout", Visit::Logout),
    ("chooser", "/login", Visit::Chooser),
    ("wallet", "/wallet", Visit::Wallet),
];

/// Whether the page in front of the browser has loaded and, when it loads
/// FerroUI's loader, has been marked by it (`ferrohealth_ui::script::MARK`
/// and `READY`), after FerroPIX's journeys.
const READY: &str = r#"
return document.readyState === "complete"
    && (document.querySelector("script[src*='/ferrohealth-ui/']") === null
        || (document.documentElement.hasAttribute("data-fui-script")
            && document.querySelector("[data-fui]:not([data-fui-ready])") === null));
"#;

/// The workspace root.
pub(crate) fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The file of `image` with the theme suffix `suffix`.
fn output(image: &str, suffix: &str) -> PathBuf {
    workspace()
        .join(IMAGES)
        .join(format!("{image}{suffix}.png"))
}

/// The part of the Chrome `DevTools` Protocol's `Page.getLayoutMetrics`
/// answer the capture reads.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LayoutMetrics {
    /// The size of the page's content, in CSS pixels.
    css_content_size: ContentSize,
}

/// A size in CSS pixels.
#[derive(Debug, Deserialize)]
struct ContentSize {
    /// The height.
    height: f64,
}

/// A headless Chrome session through a chromedriver of its own.
struct Browser {
    /// The `WebDriver` session.
    driver: WebDriver,
    /// The chromedriver, killed with its Chrome when dropped.
    _chromedriver: Chromedriver,
}

impl Browser {
    /// Starts the session.
    async fn start() -> Self {
        let mut capabilities = DesiredCapabilities::chrome();
        // NOTE: Chrome's headless mode (developer.chrome.com/docs/chromium/headless):
        // a container has neither the kernel sandbox nor a large `/dev/shm`.
        capabilities.add_arg("--headless=new").expect("an argument");
        capabilities.set_no_sandbox().expect("an argument");
        capabilities
            .set_disable_dev_shm_usage()
            .expect("an argument");
        capabilities
            .add_arg(&format!("--window-size={WIDTH},{HEIGHT}"))
            .expect("an argument");
        let chrome = std::env::var_os(CHROME_ENV)
            .map(PathBuf::from)
            .or_else(|| installed().1);
        if let Some(chrome) = chrome {
            capabilities
                .set_binary(chrome.to_str().expect("a UTF-8 path"))
                .expect("the binary");
        }
        let (chromedriver, endpoint) = Chromedriver::start()
            .await
            .unwrap_or_else(|error| panic!("chromedriver starts: {error}"));
        let driver = WebDriver::new(endpoint.as_str(), capabilities)
            .await
            .unwrap_or_else(|error| panic!("a WebDriver session at {endpoint}: {error}"));
        Self {
            driver,
            _chromedriver: chromedriver,
        }
    }

    /// Sends the Chrome `DevTools` Protocol command `method` with `params`.
    async fn devtools(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.driver
            .cdp()
            .send_raw(method, params)
            .await
            .unwrap_or_else(|error| panic!("{method}: {error}"))
    }

    /// Lays the page out in a window `height` CSS pixels tall.
    async fn window(&self, height: u32) {
        self.devtools(
            "Emulation.setDeviceMetricsOverride",
            json!({ "width": WIDTH, "height": height, "deviceScaleFactor": 1, "mobile": false }),
        )
        .await;
    }

    /// Has the browser report `theme` as the system's colour scheme, which
    /// FerroUI's pages follow.
    async fn scheme(&self, theme: &str) {
        self.devtools(
            "Emulation.setEmulatedMedia",
            json!({ "features": [{ "name": "prefers-color-scheme", "value": theme }] }),
        )
        .await;
    }

    /// Hands the browser the launch cookie `cookie` for `stack`, or takes
    /// it away.
    async fn cookie(&self, stack: &Stack, cookie: Option<&str>) {
        let url = stack.url("/");
        self.devtools(
            "Network.deleteCookies",
            json!({ "name": ferrosmart::authorize::COOKIE, "url": url }),
        )
        .await;
        if let Some(value) = cookie {
            self.devtools(
                "Network.setCookie",
                json!({ "name": ferrosmart::authorize::COOKIE, "value": value, "url": url, "httpOnly": true }),
            )
            .await;
        }
    }

    /// Opens `address` and waits for its heading and FerroUI's loader.
    async fn open(&self, address: &str) {
        self.driver
            .goto(address)
            .await
            .unwrap_or_else(|error| panic!("opening {address}: {error}"));
        self.driver
            .query(By::Css("h1"))
            .wait(WAIT, POLL)
            .first()
            .await
            .unwrap_or_else(|error| panic!("{address} draws no heading: {error}"));
        let started = Instant::now();
        loop {
            let ready = self
                .driver
                .execute(READY, Vec::new())
                .await
                .is_ok_and(|answer| answer.convert::<bool>().is_ok_and(|ready| ready));
            if ready {
                break;
            }
            assert!(started.elapsed() <= WAIT, "{address} is never ready");
            tokio::time::sleep(POLL).await;
        }
        self.driver
            .execute("return document.fonts.ready.then(() => true);", Vec::new())
            .await
            .unwrap_or_else(|error| panic!("the fonts of {address} load: {error}"));
    }

    /// The height of the page's content, in whole CSS pixels from [`HEIGHT`]
    /// to [`TALLEST`].
    async fn content_height(&self) -> u32 {
        let metrics = self.devtools("Page.getLayoutMetrics", json!({})).await;
        let metrics: LayoutMetrics =
            serde_json::from_value(metrics).expect("the layout answer reads");
        let content = metrics.css_content_size.height;
        (HEIGHT..=TALLEST)
            .find(|tall| f64::from(*tall) >= content)
            .unwrap_or(TALLEST)
    }

    /// Writes the page in front of the browser at its full height to
    /// `file`.
    async fn capture(&self, file: &Path) {
        let height = self.content_height().await;
        self.window(height).await;
        self.driver
            .execute("window.scrollTo(0, 0); return 'top';", Vec::new())
            .await
            .expect("the page scrolls to its top");
        let png = self
            .driver
            .screenshot_as_png()
            .await
            .unwrap_or_else(|error| panic!("taking {}: {error}", file.display()));
        self.window(HEIGHT).await;
        std::fs::write(file, png)
            .unwrap_or_else(|error| panic!("writing {}: {error}", file.display()));
    }
}

/// Brings the page of `visit` about on `stack` and returns its address and
/// the launch cookie the browser carries to it.
async fn reach(stack: &Stack, visit: Visit) -> (String, Option<String>) {
    match visit {
        Visit::ClinicianConsent => (stack.url("/consent"), Some(stack.clinician_consent().await)),
        Visit::PatientConsent => (stack.url("/consent"), Some(stack.patient_consent().await)),
        Visit::Picker => (
            stack.url("/picker?name=Example"),
            Some(stack.picker().await),
        ),
        Visit::Manage => (stack.url("/manage"), Some(stack.manage().await)),
        Visit::UnknownClient => (
            stack.url(&stack.authorize_path("unregistered-app", "openid")),
            None,
        ),
        Visit::Lapsed => (stack.url("/consent"), None),
        Visit::OtherBrowser => (stack.url(&stack.other_browser().await), None),
        Visit::Logout => (stack.url("/logout?client_id=ward-overview"), None),
        Visit::Chooser => (stack.url("/login"), Some(stack.chooser().await)),
        Visit::Wallet => (stack.url("/wallet"), Some(stack.wallet().await)),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_book_shows_every_page_in_light_and_dark() {
    if !std::env::var(SCREENSHOTS_GATE).is_ok_and(|value| value == "1") {
        return;
    }
    let folder = workspace().join(IMAGES);
    std::fs::create_dir_all(&folder)
        .unwrap_or_else(|error| panic!("creating {}: {error}", folder.display()));
    for (theme, suffix) in THEMES {
        let stack = Stack::start().await;
        let browser = Browser::start().await;
        browser.window(HEIGHT).await;
        browser.scheme(theme).await;
        for (image, _, visit) in SHOTS {
            let (address, cookie) = reach(&stack, visit).await;
            browser.cookie(&stack, cookie.as_deref()).await;
            browser.open(&address).await;
            browser.capture(&output(image, suffix)).await;
        }
        if theme == "light" {
            wallet_journey(&browser, &stack).await;
        }
        browser.driver.quit().await.expect("the browser closes");
        stack.stop().await;
    }
    let captured = folder.join(CAPTURED);
    std::fs::write(&captured, format!("{}\n", env!("CARGO_PKG_VERSION")))
        .unwrap_or_else(|error| panic!("writing {}: {error}", captured.display()));
}

/// The text of every page of the book.
fn book() -> String {
    let mut text = String::new();
    let mut folders = vec![workspace().join("website/book/src")];
    while let Some(folder) = folders.pop() {
        let entries = std::fs::read_dir(&folder)
            .unwrap_or_else(|error| panic!("reading {}: {error}", folder.display()));
        for entry in entries {
            let entry = entry.expect("a directory entry").path();
            if entry.is_dir() {
                folders.push(entry);
            } else if entry.extension().is_some_and(|extension| extension == "md") {
                text.push_str(&std::fs::read_to_string(&entry).expect("a page of the book"));
            }
        }
    }
    text
}

#[test]
fn every_page_route_has_a_screenshot_in_light_and_dark() {
    for route in ferrosmart::server::PAGES {
        assert!(
            SHOTS.iter().any(|(_, shown, _)| *shown == route),
            "the page route {route} has no screenshot: add a shot for it to screenshots::SHOTS and run the capture with {SCREENSHOTS_GATE}=1"
        );
    }
    for (image, route, _) in SHOTS {
        assert!(
            ferrosmart::server::PAGES.contains(&route),
            "the shot {image} shows {route}, which is no page route"
        );
    }
    let folder = workspace().join(IMAGES);
    let mut images = BTreeSet::new();
    for (image, _, _) in SHOTS {
        for (_, suffix) in THEMES {
            let file = output(image, suffix);
            assert!(
                file.is_file(),
                "{} is missing: run the capture with {SCREENSHOTS_GATE}=1",
                file.display()
            );
            images.insert(file);
        }
    }
    let captured = folder.join(CAPTURED);
    images.insert(captured.clone());
    let version = std::fs::read_to_string(&captured).unwrap_or_else(|error| {
        panic!(
            "{} cannot be read ({error}): run the capture with {SCREENSHOTS_GATE}=1",
            captured.display()
        )
    });
    assert_eq!(
        env!("CARGO_PKG_VERSION"),
        version.trim_end(),
        "the screenshots were taken at another release: run the capture with {SCREENSHOTS_GATE}=1"
    );
    let entries = std::fs::read_dir(&folder)
        .unwrap_or_else(|error| panic!("reading {}: {error}", folder.display()));
    for entry in entries {
        let entry = folder.join(entry.expect("a directory entry").file_name());
        assert!(
            images.contains(&entry),
            "{} is no shot's image: remove it",
            entry.display()
        );
    }
    let book = book();
    for (image, _, _) in SHOTS {
        let light = format!("img/{image}.png)");
        let dark = format!("img/{image}-dark.png)");
        let shown = book.lines().any(|line| {
            line.find(&light).is_some_and(|at| {
                line.get(..at)
                    .and_then(|before| before.rsplit_once("!["))
                    .and_then(|(_, alt)| alt.split_once("]("))
                    .is_some_and(|(alt, _)| !alt.trim().is_empty())
            })
        });
        assert!(
            shown,
            "no page of the book shows {image}.png as an image with alt text"
        );
        assert!(
            book.contains(&dark),
            "no page of the book links {image}-dark.png"
        );
    }
}

/// The Digital Credentials API the journey hands the page before its module
/// runs: `navigator.credentials.get` answers `ANSWER` to a signed OpenID4VP
/// request whose `nonce` is `NONCE`, and an error to anything else.
const STUBBED_API: &str = r#"
window.DigitalCredential = function DigitalCredential() {};
const stubbed = {
  get: async (options) => {
    const asked = options?.digital?.requests?.[0];
    const payload = asked?.data?.request?.split(".")[1]?.replaceAll("-", "+").replaceAll("_", "/");
    const nonce = payload ? JSON.parse(atob(payload)).nonce : null;
    const matches = asked?.protocol === "openid4vp-v1-signed" && nonce === NONCE;
    return { protocol: "openid4vp-v1-signed", data: matches ? ANSWER : { error: "invalid_request" } };
  },
};
Object.defineProperty(Navigator.prototype, "credentials", { configurable: true, get: () => stubbed });
"#;

/// Drives the wallet page's module through a stubbed Digital Credentials
/// API: a press on its link hands the API the page's signed request, and
/// the wallet's answer, posted back by the page's form, completes the login
/// on the consent page (#840).
async fn wallet_journey(browser: &Browser, stack: &Stack) {
    let cookie = stack.wallet().await;
    let (nonce, answer) = stack.wallet_answer(&cookie).await;
    let source = STUBBED_API
        .replace("NONCE", &serde_json::to_string(&nonce).expect("a string"))
        .replace("ANSWER", &answer.to_string());
    let added = browser
        .devtools(
            "Page.addScriptToEvaluateOnNewDocument",
            json!({ "source": source }),
        )
        .await;
    browser.cookie(stack, Some(&cookie)).await;
    browser.open(&stack.url("/wallet")).await;
    browser
        .driver
        .query(By::Css("[data-wallet-ready] a"))
        .wait(WAIT, POLL)
        .first()
        .await
        .expect("the module enhances the wallet link")
        .click()
        .await
        .expect("the link is pressed");
    let started = Instant::now();
    loop {
        let address = browser.driver.current_url().await.expect("an address");
        if address.path() == "/consent" {
            break;
        }
        assert!(
            started.elapsed() <= WAIT,
            "the wallet answer never reached the consent page: {address}"
        );
        tokio::time::sleep(POLL).await;
    }
    browser
        .devtools(
            "Page.removeScriptToEvaluateOnNewDocument",
            json!({ "identifier": added.get("identifier").expect("an identifier") }),
        )
        .await;
}
