import json
import re

from yt_dlp.extractor.common import InfoExtractor
from yt_dlp.utils import ExtractorError, try_call


def _caesar_decode(text, shift):
    """Decode Caesar cipher by shifting each letter forward by ``shift`` positions."""
    result = []
    for ch in text:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)


class TldvIE(InfoExtractor):
    _VALID_URL = r'https?://(?:www\.)?tldv\.io/app/meetings/(?P<id>[a-f0-9]+)'
    _NETRC_MACHINE = 'tldv'
    IE_NAME = 'tldv'

    _API_BASE = 'https://gaia.tldv.io/v1'

    _TESTS = [{
        'url': 'https://tldv.io/app/meetings/6979fa3e5095a7001341ea2c',
        'only_matching': True,
    }]

    def _get_auth_token(self, video_id):
        """Get JWT auth token from extractor args, netrc/login, or cookies."""
        # 1. Extractor args (highest priority, case-sensitive for JWT)
        token = self._configuration_arg('token', [None], casesense=True)[0]
        if token:
            return token

        # 2. Username/password (--username/--password or netrc)
        username, password = self._get_login_info()
        if username and password:
            return self._login(username, password, video_id)

        # 3. Cookies (--cookies-from-browser)
        token = self._get_token_from_cookies()
        if token:
            return token

        raise ExtractorError(
            'No authentication token found. Use one of:\n'
            '  --extractor-args "tldv:token=YOUR_JWT_TOKEN"\n'
            '  --username EMAIL --password PASSWORD\n'
            '\n'
            'To get your token from the browser:\n'
            '  1. Open tldv.io and log in\n'
            '  2. Press F12 → Console tab\n'
            '  3. Run: JSON.parse(localStorage.getItem("_cap_jwt")).token\n'
            '  4. Copy the output',
            expected=True)

    def _login(self, username, password, video_id):
        """Authenticate via tldv's API and return JWT token."""
        login_data = json.dumps({
            'email': username,
            'password': password,
        }).encode()

        response = self._download_json(
            f'{self._API_BASE}/auth/login', video_id,
            note='Logging in to tldv',
            errnote='Login failed',
            data=login_data,
            headers={'Content-Type': 'application/json'},
            expected_status=(401, 403))

        token = try_call(lambda: (
            response.get('token')
            or response.get('accessToken')
            or response.get('access_token')
            or response.get('data', {}).get('token')
        ))

        if not token:
            raise ExtractorError(
                'Login failed. Check your credentials or provide the token directly:\n'
                '  --extractor-args "tldv:token=YOUR_JWT_TOKEN"',
                expected=True)

        return token

    def _get_token_from_cookies(self):
        """Try to extract an auth token from tldv.io cookies."""
        cookies = self._get_cookies('https://tldv.io')
        for name in ('token', 'jwt', 'access_token', 'auth_token', 'session', 'tldv_token'):
            cookie = cookies.get(name)
            if cookie:
                return cookie.value
        return None

    def _decode_playlist(self, raw_m3u8, shift, base_url):
        """Decode an obfuscated tldv m3u8 playlist.

        The playlist uses a Caesar cipher on segment URL lines.
        Non-URL lines (HLS tags, comments, blanks) are kept as-is.
        Decoded segment filenames are prepended with ``base_url`` to form
        absolute S3 pre-signed URLs.
        """
        lines = raw_m3u8.splitlines()
        decoded_lines = []

        for line in lines:
            if line.startswith('#TLDVCONF'):
                continue
            if line.startswith('#') or not line.strip():
                decoded_lines.append(line)
                continue
            # Segment URL line — decode and make absolute
            decoded_url = _caesar_decode(line.strip(), shift)
            decoded_lines.append(base_url + decoded_url)

        return '\n'.join(decoded_lines)

    def _real_extract(self, url):
        video_id = self._match_id(url)
        token = self._get_auth_token(video_id)

        headers = {'Authorization': f'Bearer {token}'}

        # Fetch meeting metadata
        metadata = self._download_json(
            f'{self._API_BASE}/meetings/{video_id}',
            video_id, note='Fetching meeting info',
            headers=headers, fatal=False) or {}

        title = (
            metadata.get('name')
            or metadata.get('title')
            or metadata.get('meetingName')
            or video_id
        )
        duration = metadata.get('duration')
        timestamp = try_call(lambda: metadata['createdAt'])
        thumbnail = try_call(lambda: metadata['thumbnail'])

        # Fetch obfuscated m3u8 playlist
        raw_m3u8 = self._download_webpage(
            f'{self._API_BASE}/meetings/{video_id}/playlist.m3u8',
            video_id, note='Downloading obfuscated playlist',
            headers=headers)

        # Parse #TLDVCONF:expiry,shift,base_url
        tldvconf_match = re.search(r'#TLDVCONF:(\d+),(\d+),(.+)', raw_m3u8)
        if not tldvconf_match:
            raise ExtractorError(
                'Could not find TLDVCONF header in playlist. '
                'The format may have changed.', expected=True)

        shift = int(tldvconf_match.group(2))
        base_url = tldvconf_match.group(3).strip()

        self.to_screen(f'Decoding playlist (Caesar shift={shift})')

        decoded_m3u8 = self._decode_playlist(raw_m3u8, shift, base_url)

        # Let yt-dlp parse the decoded m3u8 directly.
        # With m3u8_url=None, yt-dlp encodes the doc as a data URI internally.
        formats, subtitles = self._parse_m3u8_formats_and_subtitles(
            decoded_m3u8, m3u8_url=None, ext='mp4',
            m3u8_id='hls', video_id=video_id)

        return {
            'id': video_id,
            'title': title,
            'formats': formats,
            'subtitles': subtitles,
            'duration': duration,
            'timestamp': timestamp,
            'thumbnail': thumbnail,
        }
