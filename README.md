# yt-dlp-tldv

A [yt-dlp](https://github.com/yt-dlp/yt-dlp) extractor plugin for downloading [tldv.io](https://tldv.io) meeting recordings.

## Installation

```bash
pip install yt-dlp-tldv
```

Or install from source:

```bash
git clone https://github.com/nichochar/yt-dlp-tldv.git
cd yt-dlp-tldv
pip install -e .
```

## Usage

### 1. Get your auth token

Open tldv.io in your browser, press F12, go to the Console tab, and run:

```js
JSON.parse(localStorage.getItem("_cap_jwt")).token
```

Copy the token value.

### 2. Download a meeting

```bash
yt-dlp --extractor-args "tldv:token=YOUR_JWT_TOKEN" "https://tldv.io/app/meetings/MEETING_ID"
```

With a custom output filename:

```bash
yt-dlp --extractor-args "tldv:token=YOUR_JWT_TOKEN" \
  -o "%(title)s.%(ext)s" \
  "https://tldv.io/app/meetings/MEETING_ID"
```

### Alternative: username/password (experimental)

> **Note:** Username/password authentication uses tldv's `/auth/login` API endpoint, which has not been fully verified. If it doesn't work, use the token method above instead.

```bash
yt-dlp -u your@email.com -p yourpassword "https://tldv.io/app/meetings/MEETING_ID"
```

## How it works

tldv.io serves meeting recordings as HLS streams with a custom obfuscation layer (Caesar cipher on the m3u8 playlist URLs). This plugin:

1. Authenticates with the tldv API
2. Downloads the obfuscated m3u8 playlist
3. Decodes the Caesar cipher to recover the real segment URLs
4. Hands the decoded playlist to yt-dlp's HLS downloader

## License

MIT
