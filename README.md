# Website Trust Checker

A lightweight browser extension that helps users identify potentially suspicious and fraudulent websites before interacting with them.

The extension automatically analyzes the current website and displays a small trust indicator directly on the page.

## Features

* 🔍 **Automatic website analysis** — checks websites when you visit them.
* 🛡️ **Phishing detection** — identifies domains associated with known phishing activity.
* 🌐 **Domain analysis** — detects suspicious domain patterns, including typosquatting and look-alike domains.
* ⚠️ **Non-intrusive warnings** — displays a compact warning without blocking the website.
* 📊 **Trust indicator** — provides a quick visual indication of the website's status.
* ⚡ **Lightweight** — designed to perform checks without significantly affecting browsing performance.

## How It Works

When a page is opened, the extension extracts information about the current website and performs several checks:

```text
User opens website
        ↓
Extract domain
        ↓
Check domain reputation
        ↓
Analyze domain characteristics
        ↓
Calculate result
        ↓
Display trust indicator
```

The extension can combine multiple signals rather than relying on a single blacklist.

For example:

* Known phishing reports
* Suspicious domain structure
* Typosquatting
* Look-alike domains
* Unusual TLDs
* Domain reputation

## Example

A legitimate website:

```text
https://www.microsoft.com
```

may receive:

```text
✓ Trusted
```

A suspicious look-alike domain such as:

```text
https://microsaft-example.com
```

may receive:

```text
⚠ Suspicious
```

The warning is intended to help users make an informed decision before entering credentials or other sensitive information.

## Installation

### From source

Clone the repository:

```bash
git clone https://github.com/W1set/extention.git
cd extention
```

Then load the extension manually.

### Firefox

1. Open:

```text
about:debugging#/runtime/this-firefox
```

2. Select **Load Temporary Add-on**.
3. Select `manifest.json`.
4. Open a website and check the extension indicator.

### Chromium-based browsers

1. Open:

```text
chrome://extensions/
```

2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Select the project directory.

## Project Structure

```text
extention/
├── manifest.json
├── background.js
├── analyzer.js
├── popup.html
├── popup.js
├── popup.css
├── options.html
└── options.js
```

### Main Components

| File            | Purpose                                 |
| --------------- | --------------------------------------- |
| `manifest.json` | Extension configuration and permissions |
| `background.js` | Background extension logic              |
| `analyzer.js`   | Website/domain analysis                 |
| `popup.html`    | Extension popup interface               |
| `popup.js`      | Popup functionality                     |
| `popup.css`     | Popup styling                           |
| `options.html`  | Settings page                           |
| `options.js`    | Settings functionality                  |

## Security

This project is designed as a defensive security tool.

It should be treated as an additional security layer rather than a replacement for:

* Browser security mechanisms
* Antivirus software
* Password managers
* MFA
* DNS/security filtering
* User verification

A website marked as trusted should **not** be interpreted as guaranteed safe.

Likewise, a suspicious result does not necessarily mean that a website is malicious.

## Testing

For testing, use dedicated security datasets and isolated environments.

Recommended sources include:

* [PhishTank](https://www.phishtank.net/) — phishing URL database
* [URLhaus](https://urlhaus.abuse.ch/) — malicious URL database
* Known typosquatting examples
* Test domains created specifically for development

Do **not** enter real credentials or personal information on suspicious websites during testing.

## Roadmap

* [ ] Improve domain similarity detection
* [ ] Add typosquatting detection
* [ ] Add homoglyph detection
* [ ] Integrate external reputation APIs
* [ ] Add domain age analysis
* [ ] Improve trust scoring
* [ ] Add configurable warning levels
* [ ] Add local caching of reputation results
* [ ] Add automated tests
* [ ] Improve Firefox and Chromium compatibility
* [ ] Add unit tests for the domain analyzer

## Contributing

Contributions, bug reports and feature requests are welcome.

Before submitting a pull request:

1. Test the extension locally.
2. Make sure existing functionality still works.
3. Keep changes focused.
4. Do not commit API keys or other secrets.

## Disclaimer

This project is provided for educational and defensive security purposes.

No automated website reputation system can guarantee that a website is safe or malicious. Always verify the domain and avoid entering sensitive information when you are unsure.

## License

This project is licensed under the MIT License.
