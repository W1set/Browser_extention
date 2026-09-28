# Site Verdict

**Site Verdict** is a Firefox browser extension that analyzes websites and provides security information to help identify potentially suspicious or malicious websites.

The extension can use multiple reputation and security checks, including:

* **VirusTotal Reputation**
* **Google Safe Browsing**
* Local website analysis
* Domain and URL information

> **Note:** Site Verdict is an additional security tool. A positive or negative result does not guarantee that a website is completely safe or malicious.

---

## Features

* Check the reputation of the current website.
* VirusTotal reputation lookup.
* Google Safe Browsing lookup.
* Combine multiple security signals.
* Simple browser popup interface.
* Configurable API keys through the extension settings.
* Works with Firefox and Manifest V3.

---

# API Configuration

To use the reputation checks, you need to configure the API keys in the extension's **Settings**.

The extension supports two external reputation services:

1. VirusTotal
2. Google Safe Browsing

You can use either service independently or configure both for additional reputation information.

---

# VirusTotal Reputation

VirusTotal can be used to check a URL against multiple security vendors and reputation databases.

If no VirusTotal API key is configured, the extension will display:

```text
No VirusTotal API key set. Add one in Settings to check reputation.
```

## Getting a VirusTotal API Key

1. Go to the official VirusTotal website:

[VirusTotal](https://www.virustotal.com/?utm_source=chatgpt.com)

2. Create an account or sign in.
3. Open your user profile.
4. Find the **API Key** section.
5. Copy your API key.

## Adding the VirusTotal API Key

Open:

```text
Site Verdict → Settings
```

Find the **VirusTotal API Key** field and paste your key.

Save the settings and run the website check again.

After configuration, the extension can use VirusTotal to retrieve reputation information for the current website.

### VirusTotal API

The extension uses the VirusTotal API to perform reputation checks.

VirusTotal API documentation:

[VirusTotal API Documentation](https://docs.virustotal.com/reference/overview?utm_source=chatgpt.com)

---

# Google Safe Browsing

Google Safe Browsing can provide a second reputation check for websites.

If no Google Safe Browsing API key is configured, the extension will display:

```text
No Google Safe Browsing API key set. Add one in Settings for a second reputation check.
```

## Getting a Google Safe Browsing API Key

1. Open **Google Cloud Console**:

[Google Cloud Console](https://console.cloud.google.com/?utm_source=chatgpt.com)

2. Create a new project or select an existing project.
3. Open **APIs & Services → Library**.
4. Search for:

```text
Safe Browsing API
```

5. Enable the API.
6. Go to:

```text
APIs & Services → Credentials
```

7. Click **Create Credentials**.
8. Select **API key**.
9. Copy the generated API key.

## Adding the Google Safe Browsing API Key

Open:

```text
Site Verdict → Settings
```

Find the **Google Safe Browsing API Key** field and paste your key.

Save the settings and run the website check again.

The extension can then use Google Safe Browsing as a second reputation source.

### Google Safe Browsing API

Official documentation:

[Google Safe Browsing API Documentation](https://developers.google.com/safe-browsing/v4/lookup-api?utm_source=chatgpt.com)

---

# Recommended Configuration

For the most useful reputation information, configure **both** services:

```text
VirusTotal API Key
        +
Google Safe Browsing API Key
        ↓
   Site Verdict
        ↓
Multiple reputation signals
```

The services are independent. If one API is unavailable or not configured, the extension can still use the other available checks.

---

# Example Results

### VirusTotal not configured

```text
Reputation (VirusTotal)

No VirusTotal API key set. Add one in Settings to check reputation.
```

### Google Safe Browsing not configured

```text
Reputation (Google Safe Browsing)

No Google Safe Browsing API key set. Add one in Settings for a second reputation check.
```

### Both APIs configured

The extension can display reputation information from both services, allowing the user to compare the available security signals.

---

# Installation

## Firefox

1. Download or clone this repository.

```bash
git clone https://github.com/W1set/extention.git
cd extention
```

2. Open Firefox.
3. Navigate to:

```text
about:debugging#/runtime/this-firefox
```

4. Click **Load Temporary Add-on...**
5. Select the project's:

```text
manifest.json
```

6. Click the Site Verdict extension icon.
7. Open **Settings** and configure your API keys.

---

# Development

The extension is built using standard WebExtension technologies:

* JavaScript
* HTML
* CSS
* WebExtensions API
* Manifest V3

Main files:

```text
manifest.json       Extension configuration
background.js       Background/service-worker logic
analyzer.js         Website analysis logic
popup.html          Extension popup
popup.js            Popup logic
popup.css           Popup styling
options.html        Settings page
options.js          Settings logic
README.md           Documentation
```

After modifying the extension, reload it from:

```text
about:debugging#/runtime/this-firefox
```

---

# API Key Security

**Do not commit your API keys to GitHub.**

Never put keys directly into files such as:

```javascript
const API_KEY = "your-real-api-key";
```

or:

```text
manifest.json
background.js
analyzer.js
```

Use the extension's Settings page instead.

Before publishing the repository, make sure that no real API keys are present in the source code or Git history.

If an API key has accidentally been published, revoke it and generate a new one.

---

# Privacy

Website URLs may be sent to external reputation services when the corresponding API is enabled.

For example:

```text
Current website
      ↓
Site Verdict
      ↓
VirusTotal / Google Safe Browsing
      ↓
Reputation result
```

Do not use the extension with sensitive or private URLs unless you understand how the selected reputation services process submitted URLs.

Review the privacy policies and API documentation of the services you enable.

---

# Limitations

Site Verdict should not be considered a complete malware or phishing detection system.

Possible limitations include:

* False positives.
* False negatives.
* Newly registered malicious domains may not yet have reputation data.
* Reputation databases can contain outdated information.
* API services may have rate limits.
* API keys may require specific account or project configuration.

A website receiving a clean reputation result does **not** guarantee that the website is safe.

---

# License

This project does not currently specify a license.

If you want other developers to freely use and modify the project, consider adding an open-source license such as MIT.
